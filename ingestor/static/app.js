(() => {
  const STAGES = ["recon_domain", "brute_domain", "probe_host", "scan_http", "notify_finding"];
  const STAGE_LABELS = {
    recon_domain: "Recon",
    brute_domain: "DNS Brute",
    probe_host: "HTTP Probe",
    scan_http: "Nuclei",
    notify_finding: "Notify",
  };
  const FINDING_STATUSES = ["open", "triaged", "false_positive", "fixed"];
  const FINDING_SEVERITIES = ["critical", "high", "medium", "low", "info"];
  const SEVERITY_RANK = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
  const TARGET_LIMIT = 250;
  const RECENT_JOB_LIMIT = 120;

  function $(selector) {
    return document.querySelector(selector);
  }

  function escapeHtml(value) {
    return String(value ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  function setMessage(el, type, text) {
    if (!el) return;
    el.className = "message";
    if (!text) {
      el.textContent = "";
      return;
    }
    el.textContent = text;
    el.classList.add("is-visible", type);
  }

  function parseTs(value) {
    if (!value) return null;
    const normalized = /Z|[+-]\d{2}:\d{2}$/.test(value) ? value : `${value}Z`;
    const parsed = new Date(normalized);
    return Number.isNaN(parsed.getTime()) ? null : parsed;
  }

  function fmtTs(value) {
    const parsed = parseTs(value);
    return parsed ? parsed.toLocaleString() : "-";
  }

  function relTs(value) {
    const parsed = parseTs(value);
    if (!parsed) return "-";
    const diffSeconds = Math.floor((Date.now() - parsed.getTime()) / 1000);
    if (diffSeconds < 0) return "in future";
    if (diffSeconds < 60) return `${diffSeconds}s ago`;
    if (diffSeconds < 3600) return `${Math.floor(diffSeconds / 60)}m ago`;
    if (diffSeconds < 86400) return `${Math.floor(diffSeconds / 3600)}h ago`;
    return `${Math.floor(diffSeconds / 86400)}d ago`;
  }

  function formatNumber(value) {
    return new Intl.NumberFormat().format(Number(value || 0));
  }

  function toJsonText(value) {
    if (value == null) return "";
    if (typeof value === "string") return value;
    return JSON.stringify(value, null, 2);
  }

  function buildQuery(params) {
    const query = new URLSearchParams();
    Object.entries(params).forEach(([key, value]) => {
      if (value == null || value === "") return;
      query.set(key, value);
    });
    return query.toString() ? `?${query.toString()}` : "";
  }

  async function api(path, options = {}) {
    const response = await fetch(path, {
      headers: {
        Accept: "application/json",
        ...(options.body ? { "Content-Type": "application/json" } : {}),
        ...(options.headers || {}),
      },
      ...options,
    });

    const rawText = await response.text();
    const payload = rawText ? safeJson(rawText) : null;
    if (!response.ok) {
      const detail = payload && typeof payload === "object" ? payload.detail || payload.message : rawText;
      throw new Error(typeof detail === "string" ? detail : response.statusText);
    }
    return payload;
  }

  function safeJson(rawText) {
    try {
      return JSON.parse(rawText);
    } catch {
      return rawText;
    }
  }

  function queueHealth(stage) {
    const queue = stage?.queue || {};
    if (Number(queue.dlq || 0) > 0 || Number(stage?.window?.failed || 0) > 0) return "bad";
    if (Number(queue.processing || 0) > 0 || Number(queue.pending || 0) > 0) return "warn";
    return "good";
  }

  function statusPill(label, kind, cssClass) {
    return `<span class="${kind} ${cssClass}">${escapeHtml(label)}</span>`;
  }

  function severityPill(severity) {
    const level = (severity || "info").toLowerCase();
    return statusPill(level, "severity-pill", level);
  }

  function findingStatusPill(status) {
    const value = (status || "open").toLowerCase();
    return statusPill(value.replace(/_/g, " "), "status-pill", value);
  }

  function healthPill(status) {
    return statusPill(status, "health-pill", status);
  }

  function queuePill(status) {
    const labels = { good: "healthy", warn: "watch", bad: "degraded" };
    return statusPill(labels[status] || status, "queue-pill", status);
  }

  function subdomainStatusPill(status) {
    const value = (status || "offline").toLowerCase();
    return statusPill(value, "status-pill", value);
  }

  function buildWorkerRows(recentJobs = []) {
    const grouped = new Map();
    recentJobs.forEach((job) => {
      const workerName = job.worker_name || "unassigned";
      const stamp = job.finished_at || job.started_at || job.created_at;
      const parsed = parseTs(stamp);
      if (!parsed) return;
      const current = grouped.get(workerName);
      if (!current || parsed > current.lastSeenDate) {
        grouped.set(workerName, {
          worker_name: workerName,
          lastSeen: stamp,
          lastSeenDate: parsed,
          lastStatus: job.status || "unknown",
          lastType: job.type || "-",
          targetRef: job.target_ref || "-",
        });
      }
    });

    return [...grouped.values()]
      .map((row) => {
        const ageMinutes = row.lastSeenDate ? (Date.now() - row.lastSeenDate.getTime()) / 60000 : Number.POSITIVE_INFINITY;
        let health = "offline";
        if (ageMinutes <= 5) health = "healthy";
        else if (ageMinutes <= 30) health = "stale";
        return { ...row, health };
      })
      .sort((a, b) => b.lastSeenDate - a.lastSeenDate);
  }

  function applyRelativeTimestamps() {
    document.querySelectorAll("[data-rel-ts]").forEach((el) => {
      const value = el.getAttribute("data-rel-ts");
      el.textContent = relTs(value);
      el.title = fmtTs(value);
    });
  }

  function startRelativeTicker() {
    applyRelativeTimestamps();
    window.setInterval(applyRelativeTimestamps, 30000);
  }

  function startPolling({ intervalMs, run, onSuccess, onError, onFinally }) {
    let inFlight = false;
    let failCount = 0;
    let timer = null;

    async function tick() {
      if (inFlight) return;
      inFlight = true;
      try {
        const data = await run();
        failCount = 0;
        onSuccess(data);
      } catch (error) {
        failCount += 1;
        if (onError) onError(error, failCount);
      } finally {
        inFlight = false;
        if (onFinally) onFinally(failCount);
        const nextDelay = Math.min(intervalMs * Math.max(1, 2 ** failCount), 60000);
        timer = window.setTimeout(tick, nextDelay);
      }
    }

    tick();
    return () => window.clearTimeout(timer);
  }

  function setUpdatedAt(el, timestamp) {
    if (!el) return;
    el.textContent = timestamp ? `Updated ${new Date(timestamp).toLocaleTimeString()}` : "Waiting for data";
  }

  function renderTargetOptions(select, targets, currentValue = "") {
    if (!select) return;
    const options = ['<option value="">All targets</option>'];
    (targets || []).forEach((target) => {
      options.push(`<option value="${escapeHtml(String(target.id))}">${escapeHtml(target.scope_root)}</option>`);
    });
    select.innerHTML = options.join("");
    select.value = currentValue;
  }

  function renderWordlistOptions(select, wordlists, currentValue = "dns-small.txt") {
    if (!select) return;
    select.innerHTML = (wordlists || []).map((value) => `<option value="${escapeHtml(value)}">${escapeHtml(value)}</option>`).join("");
    select.value = currentValue;
  }

  function renderTemplateOptions(select, templates, currentValue = "all") {
    if (!select) return;
    select.innerHTML = (templates || []).map((value) => `<option value="${escapeHtml(value)}">${escapeHtml(value)}</option>`).join("");
    select.value = currentValue;
  }

  function initDashboard() {
    const staleBanner = $("#stale-banner");
    const updatedAt = $("#last-updated");
    const message = $("#page-message");

    function render(data) {
      setUpdatedAt(updatedAt, Date.now());
      staleBanner.classList.remove("is-visible");
      setMessage(message, "", "");
      renderDashboardOverview(data);
      renderDashboardPipeline(data.pipeline || {});
      renderWorkerHealth("#worker-health-body", data.recent_jobs || []);
      renderDashboardTargets(data.targets || []);
      applyRelativeTimestamps();
    }

    function load() {
      return api(`/admin/progress${buildQuery({
        target_limit: TARGET_LIMIT,
        recent_job_limit: RECENT_JOB_LIMIT,
        window_hours: 24,
      })}`);
    }

    startPolling({
      intervalMs: 5000,
      run: load,
      onSuccess: render,
      onError: (error, failCount) => {
        staleBanner.textContent = `Dashboard refresh failed (${failCount}). ${error.message}`;
        staleBanner.classList.add("is-visible");
      },
    });
  }

  function renderDashboardOverview(data) {
    const overview = data.overview || {};
    const pipeline = data.pipeline || {};
    const queueDepthSum = STAGES.reduce((sum, stageName) => {
      const queue = pipeline[stageName]?.queue || {};
      return sum + Number(queue.pending || 0) + Number(queue.processing || 0) + Number(queue.dlq || 0);
    }, 0);

    $("#overview-cards").innerHTML = `
      <article class="metric-card">
        <div class="label">Targets</div>
        <div class="value">${formatNumber(overview.targets_enabled ?? overview.targets_total)}</div>
        <div class="sub">${formatNumber(overview.targets_total)} total tracked roots</div>
      </article>
      <article class="metric-card">
        <div class="label">Live Endpoints</div>
        <div class="value">${formatNumber(overview.endpoints_live)}</div>
        <div class="sub">${formatNumber(overview.endpoints_total)} endpoints discovered overall</div>
      </article>
      <article class="metric-card">
        <div class="label">Open Findings</div>
        <div class="value">${formatNumber(overview.findings_open_total)}</div>
        <div class="sub">${formatNumber(overview.findings_open_window)} opened in the last 24h</div>
      </article>
      <article class="metric-card">
        <div class="label">Queue Pressure</div>
        <div class="value">${formatNumber(queueDepthSum)}</div>
        <div class="sub">${formatNumber(overview.jobs_running)} jobs currently running</div>
      </article>
    `;
  }

  function renderDashboardPipeline(pipeline) {
    $("#pipeline-grid").innerHTML = STAGES.map((stageName) => {
      const stage = pipeline[stageName] || {};
      const queue = stage.queue || {};
      const health = queueHealth(stage);
      return `
        <article class="stage-card health-${health}">
          <div class="stage-top">
            <div>
              <h3>${escapeHtml(STAGE_LABELS[stageName])}</h3>
              <div class="kicker">done/h ${Number(stage.done_per_hour_window || 0).toFixed(2)}</div>
            </div>
            ${queuePill(health)}
          </div>
          <div class="stage-stats">
            <div class="mini-stat"><span class="label">Queue</span><strong>${formatNumber(queue.pending)}</strong></div>
            <div class="mini-stat"><span class="label">Processing</span><strong>${formatNumber(queue.processing)}</strong></div>
            <div class="mini-stat"><span class="label">DLQ</span><strong>${formatNumber(queue.dlq)}</strong></div>
            <div class="mini-stat"><span class="label">Window Done</span><strong>${formatNumber(stage.window?.done)}</strong></div>
          </div>
          <div class="badge-row" style="margin-top:0.9rem">
            <span class="muted">Last success: <span data-rel-ts="${escapeHtml(stage.last_done_at || "")}">${escapeHtml(relTs(stage.last_done_at))}</span></span>
            <span class="muted">Last failure: <span data-rel-ts="${escapeHtml(stage.last_failed_at || "")}">${escapeHtml(relTs(stage.last_failed_at))}</span></span>
          </div>
        </article>
      `;
    }).join("");
  }

  function renderWorkerHealth(targetSelector, recentJobs) {
    const tbody = $(targetSelector);
    const workers = buildWorkerRows(recentJobs);
    if (!tbody) return;
    if (!workers.length) {
      tbody.innerHTML = '<tr><td colspan="5"><div class="empty-state">No worker activity has been recorded yet.</div></td></tr>';
      return;
    }

    tbody.innerHTML = workers.map((worker) => `
      <tr>
        <td><strong>${escapeHtml(worker.worker_name)}</strong></td>
        <td>${healthPill(worker.health)}</td>
        <td>${escapeHtml(worker.lastType)}</td>
        <td>${findingStatusPill(worker.lastStatus)}</td>
        <td><span data-rel-ts="${escapeHtml(worker.lastSeen)}">${escapeHtml(relTs(worker.lastSeen))}</span></td>
      </tr>
    `).join("");
  }

  function renderDashboardTargets(targets) {
    const tbody = $("#dashboard-targets-body");
    if (!targets?.length) {
      tbody.innerHTML = '<tr><td colspan="7"><div class="empty-state">No targets yet. Add one from the Targets page.</div></td></tr>';
      return;
    }

    tbody.innerHTML = targets.map((target) => {
      const findingsHref = `/ui/findings.html${buildQuery({
        target_id: String(target.id),
        status: "open",
      })}`;
      return `
        <tr>
          <td><a href="${findingsHref}"><strong>${escapeHtml(target.scope_root)}</strong></a></td>
          <td>${formatNumber(target.subdomain_count)}</td>
          <td>${formatNumber(target.live_endpoint_count)}</td>
          <td>${formatNumber(target.finding_open_count)}</td>
          <td><span data-rel-ts="${escapeHtml(target.last_recon || "")}">${escapeHtml(relTs(target.last_recon))}</span></td>
          <td><span data-rel-ts="${escapeHtml(target.next_recon_due_at || "")}">${escapeHtml(relTs(target.next_recon_due_at))}</span></td>
          <td>
            <div class="target-actions">
              <a href="${findingsHref}" role="button" class="secondary">Open findings</a>
              <a href="/ui/targets.html" role="button" class="outline contrast">Manage</a>
            </div>
          </td>
        </tr>
      `;
    }).join("");
  }

  function initFindings() {
    const message = $("#page-message");
    const staleBanner = $("#stale-banner");
    const updatedAt = $("#last-updated");
    const filtersForm = $("#findings-filters");
    const findingDialog = $("#finding-dialog");
    const dialogTitle = $("#finding-dialog-title");
    const dialogPills = $("#finding-dialog-pills");
    const dialogMetaRow = $("#finding-dialog-meta-row");
    const detailContent = $("#finding-detail-content");
    const detailStatus = $("#detail-status");
    const detailSave = $("#detail-save");
    const detailClose = $("#detail-close");
    const severityChips = $("#severity-chips");
    const statusChips = $("#status-chips");
    const targetSelect = $("#filter-target");
    const windowSelect = $("#filter-window");
    const sortSelect = $("#filter-sort");

    const query = new URLSearchParams(window.location.search);
    const state = {
      targets: [],
      findings: [],
      activeFindingId: null,
      filters: {
        severity: splitCsv(query.get("severity")),
        status: splitCsv(query.get("status")).length ? splitCsv(query.get("status")) : ["open"],
        targetId: query.get("target_id") || "",
        windowHours: query.has("window_hours") ? query.get("window_hours") : "24",
        sort: query.get("sort") || "matched_desc",
      },
    };

    function syncControls() {
      severityChips.querySelectorAll(".filter-chip").forEach((chip) => {
        chip.setAttribute("aria-pressed", state.filters.severity.includes(chip.value) ? "true" : "false");
      });
      statusChips.querySelectorAll(".filter-chip").forEach((chip) => {
        chip.setAttribute("aria-pressed", state.filters.status.includes(chip.value) ? "true" : "false");
      });
      targetSelect.value = state.filters.targetId;
      windowSelect.value = state.filters.windowHours;
      sortSelect.value = state.filters.sort;
    }

    function syncUrl() {
      const next = new URLSearchParams();
      if (state.filters.severity.length) next.set("severity", state.filters.severity.join(","));
      if (state.filters.status.length) next.set("status", state.filters.status.join(","));
      if (state.filters.targetId) next.set("target_id", state.filters.targetId);
      if (state.filters.windowHours !== "all") next.set("window_hours", state.filters.windowHours);
      if (state.filters.sort !== "matched_desc") next.set("sort", state.filters.sort);
      const nextUrl = `${window.location.pathname}${next.toString() ? `?${next.toString()}` : ""}`;
      window.history.replaceState({}, "", nextUrl);
    }

    async function loadTargets() {
      state.targets = await api("/targets");
      renderTargetOptions(targetSelect, state.targets, state.filters.targetId);
    }

    async function loadFindings() {
      const params = {
        severity: state.filters.severity.join(","),
        status: state.filters.status.join(","),
        target_id: state.filters.targetId,
        limit: "200",
      };
      if (state.filters.windowHours !== "all") params.window_hours = state.filters.windowHours;
      state.findings = await api(`/findings${buildQuery(params)}`);
      renderFindingsTable();
      if (state.activeFindingId) {
        const stillPresent = state.findings.some((finding) => finding.id === state.activeFindingId);
        if (!stillPresent) closeDetail();
      }
    }

    function sortedFindings() {
      const rows = [...state.findings];
      const sort = state.filters.sort;
      if (sort === "severity_desc") {
        rows.sort((a, b) => (SEVERITY_RANK[b.severity] || 0) - (SEVERITY_RANK[a.severity] || 0));
      } else if (sort === "severity_asc") {
        rows.sort((a, b) => (SEVERITY_RANK[a.severity] || 0) - (SEVERITY_RANK[b.severity] || 0));
      } else if (sort === "matched_asc") {
        rows.sort((a, b) => (parseTs(a.first_seen)?.getTime() || 0) - (parseTs(b.first_seen)?.getTime() || 0));
      } else {
        rows.sort((a, b) => (parseTs(b.first_seen)?.getTime() || 0) - (parseTs(a.first_seen)?.getTime() || 0));
      }
      return rows;
    }

    function renderFindingsTable() {
      const tbody = $("#findings-body");
      const rows = sortedFindings();
      $("#findings-count").textContent = `${rows.length} visible`;
      if (!rows.length) {
        tbody.innerHTML = '<tr><td colspan="6"><div class="empty-state">No findings match the current filters.</div></td></tr>';
        return;
      }

      tbody.innerHTML = rows.map((finding) => `
        <tr class="clickable" data-finding-row="${finding.id}">
          <td>${severityPill(finding.severity)}</td>
          <td><strong>${escapeHtml(finding.title)}</strong></td>
          <td><span data-rel-ts="${escapeHtml(finding.first_seen || "")}">${escapeHtml(relTs(finding.first_seen))}</span></td>
          <td>${escapeHtml(finding.scope_root)}</td>
          <td>${findingStatusPill(finding.status)}</td>
          <td>
            <div class="target-actions">
              <button type="button" class="outline contrast" data-action="triaged" data-finding-id="${finding.id}">Triage</button>
              <button type="button" class="secondary" data-action="false_positive" data-finding-id="${finding.id}">FP</button>
              <button type="button" class="secondary" data-action="fixed" data-finding-id="${finding.id}">Fixed</button>
            </div>
          </td>
        </tr>
      `).join("");
    }

    async function openDetail(findingId) {
      state.activeFindingId = findingId;
      dialogTitle.textContent = "";
      dialogPills.innerHTML = "";
      dialogMetaRow.innerHTML = "";
      detailContent.innerHTML = "<p class='muted' style='padding:0.5rem 0'>Loading…</p>";
      findingDialog.showModal();
      try {
        const detail = await api(`/findings/${findingId}`);
        detailStatus.value = detail.status || "open";
        detailSave.dataset.findingId = String(findingId);

        dialogPills.innerHTML = severityPill(detail.severity) + findingStatusPill(detail.status);
        dialogTitle.textContent = detail.title || "-";
        dialogMetaRow.innerHTML = [
          detail.scope_root || detail.hostname ? `<span class="meta-item"><span class="meta-label">Target</span> ${escapeHtml(detail.scope_root || detail.hostname)}</span>` : "",
          detail.first_seen ? `<span class="meta-item"><span class="meta-label">Observed</span> ${escapeHtml(relTs(detail.first_seen))}</span>` : "",
          detail.hostname && detail.hostname !== detail.scope_root ? `<span class="meta-item"><span class="meta-label">Host</span> <span class="mono">${escapeHtml(detail.hostname)}</span></span>` : "",
        ].filter(Boolean).join("");

        const fields = [
          ["Template", `<span class="mono">${escapeHtml(detail.template_id || "-")}</span>`],
          ["Matched at", `<span class="mono">${escapeHtml(detail.matched_at || "-")}</span>`],
          ["URL", `<span class="mono">${escapeHtml(detail.url || "-")}</span>`],
          ["First seen", escapeHtml(fmtTs(detail.first_seen))],
        ];

        detailContent.innerHTML = `
          <div class="finding-fields">
            ${fields.map(([label, value]) => `
              <div class="finding-field">
                <div class="finding-field-label">${label}</div>
                <div class="finding-field-value">${value}</div>
              </div>
            `).join("")}
          </div>
          <div class="finding-raw-section">
            <h3>Raw event</h3>
            <pre>${escapeHtml(toJsonText(detail.raw_event || detail.raw_event_error || "No raw event available."))}</pre>
          </div>
        `;
      } catch (error) {
        detailContent.innerHTML = `<div class="empty-state">Failed to load finding detail: ${escapeHtml(error.message)}</div>`;
      }
    }

    function closeDetail() {
      state.activeFindingId = null;
      detailSave.dataset.findingId = "";
      findingDialog.close();
    }

    async function patchFinding(findingId, status) {
      try {
        await api(`/findings/${findingId}`, {
          method: "PATCH",
          body: JSON.stringify({ status }),
        });
        setMessage(message, "success", `Finding ${findingId} marked as ${status.replace(/_/g, " ")}.`);
        await loadFindings();
        if (state.activeFindingId === findingId) await openDetail(findingId);
      } catch (error) {
        setMessage(message, "error", error.message);
      }
    }

    filtersForm.addEventListener("click", (event) => {
      const chip = event.target.closest(".filter-chip");
      if (!chip) return;
      const pressed = chip.getAttribute("aria-pressed") === "true";
      chip.setAttribute("aria-pressed", pressed ? "false" : "true");
    });

    filtersForm.addEventListener("submit", async (event) => {
      event.preventDefault();
      state.filters.severity = pressedChipValues(severityChips);
      state.filters.status = pressedChipValues(statusChips);
      state.filters.targetId = targetSelect.value;
      state.filters.windowHours = windowSelect.value;
      state.filters.sort = sortSelect.value;
      syncUrl();
      await loadFindings();
      closeDetail();
    });

    $("#filter-reset").addEventListener("click", async () => {
      state.filters = {
        severity: [],
        status: ["open"],
        targetId: "",
        windowHours: "24",
        sort: "matched_desc",
      };
      syncControls();
      syncUrl();
      closeDetail();
      await loadFindings();
    });

    $("#findings-body").addEventListener("click", async (event) => {
      const actionButton = event.target.closest("button[data-action]");
      if (actionButton) {
        await patchFinding(Number(actionButton.dataset.findingId), actionButton.dataset.action);
        return;
      }
      const row = event.target.closest("tr[data-finding-row]");
      if (!row) return;
      await openDetail(Number(row.dataset.findingRow));
    });

    detailSave.addEventListener("click", async () => {
      const findingId = Number(detailSave.dataset.findingId || "0");
      if (!findingId) return;
      await patchFinding(findingId, detailStatus.value);
    });

    detailClose.addEventListener("click", () => closeDetail());
    findingDialog.addEventListener("click", (e) => { if (e.target === findingDialog) closeDetail(); });

    syncControls();
    loadTargets()
      .then(() => loadFindings())
      .then(() => setUpdatedAt(updatedAt, Date.now()))
      .catch((error) => setMessage(message, "error", error.message));

    startPolling({
      intervalMs: 30000,
      run: async () => {
        await loadFindings();
        return true;
      },
      onSuccess: () => {
        staleBanner.classList.remove("is-visible");
        setUpdatedAt(updatedAt, Date.now());
      },
      onError: (error, failCount) => {
        staleBanner.textContent = `Findings refresh failed (${failCount}). ${error.message}`;
        staleBanner.classList.add("is-visible");
      },
    });
  }

  function initSubdomains() {
    const message = $("#page-message");
    const staleBanner = $("#stale-banner");
    const updatedAt = $("#last-updated");
    const filtersForm = $("#subdomains-filters");
    const targetSelect = $("#subdomains-filter-target");
    const statusSelect = $("#subdomains-filter-status");
    const technologyInput = $("#subdomains-filter-technology");
    const searchInput = $("#subdomains-filter-search");
    const sortBySelect = $("#subdomains-filter-sort-by");
    const sortDirSelect = $("#subdomains-filter-sort-dir");
    const tbody = $("#subdomains-body");
    const detailContent = $("#subdomain-detail-content");

    const query = new URLSearchParams(window.location.search);
    const state = {
      targets: [],
      rows: [],
      selectedId: null,
      filters: {
        targetId: query.get("target_id") || "",
        status: query.get("status") || "",
        technology: query.get("technology") || "",
        search: query.get("search") || "",
        sortBy: query.get("sort_by") || "last_seen",
        sortDir: query.get("sort_dir") || "desc",
      },
    };

    function syncControls() {
      renderTargetOptions(targetSelect, state.targets, state.filters.targetId);
      statusSelect.value = state.filters.status;
      technologyInput.value = state.filters.technology;
      searchInput.value = state.filters.search;
      sortBySelect.value = state.filters.sortBy;
      sortDirSelect.value = state.filters.sortDir;
    }

    function syncUrl() {
      const next = new URLSearchParams();
      if (state.filters.targetId) next.set("target_id", state.filters.targetId);
      if (state.filters.status) next.set("status", state.filters.status);
      if (state.filters.technology) next.set("technology", state.filters.technology);
      if (state.filters.search) next.set("search", state.filters.search);
      if (state.filters.sortBy !== "last_seen") next.set("sort_by", state.filters.sortBy);
      if (state.filters.sortDir !== "desc") next.set("sort_dir", state.filters.sortDir);
      const nextUrl = `${window.location.pathname}${next.toString() ? `?${next.toString()}` : ""}`;
      window.history.replaceState({}, "", nextUrl);
    }

    function readFiltersFromControls() {
      state.filters.targetId = targetSelect.value;
      state.filters.status = statusSelect.value;
      state.filters.technology = technologyInput.value.trim();
      state.filters.search = searchInput.value.trim();
      state.filters.sortBy = sortBySelect.value;
      state.filters.sortDir = sortDirSelect.value;
    }

    async function loadTargets() {
      state.targets = await api("/targets");
      syncControls();
    }

    async function loadSubdomains() {
      const params = {
        target_id: state.filters.targetId,
        status: state.filters.status,
        technology: state.filters.technology,
        search: state.filters.search,
        sort_by: state.filters.sortBy,
        sort_dir: state.filters.sortDir,
        limit: "500",
      };
      state.rows = await api(`/subdomains${buildQuery(params)}`);
      renderSubdomainsTable();

      if (!state.rows.length) {
        state.selectedId = null;
        renderSubdomainDetail(null);
        return;
      }

      const selectedRow = state.rows.find((row) => row.id === state.selectedId) || state.rows[0];
      state.selectedId = selectedRow.id;
      renderSubdomainDetail(selectedRow);
    }

    function renderSubdomainsTable() {
      $("#subdomains-count").textContent = `${state.rows.length} visible`;
      if (!state.rows.length) {
        tbody.innerHTML = '<tr><td colspan="5"><div class="empty-state">No hostnames match the current filters.</div></td></tr>';
        return;
      }

      tbody.innerHTML = state.rows.map((row) => `
        <tr class="clickable subdomain-row ${row.id === state.selectedId ? "is-selected" : ""}" data-subdomain-row="${row.id}">
          <td>
            <strong>${escapeHtml(row.hostname)}</strong>
            <div class="muted">${escapeHtml(row.source || "source unknown")}</div>
          </td>
          <td>${escapeHtml(row.scope_root)}</td>
          <td>${subdomainStatusPill(row.status)}</td>
          <td><span data-rel-ts="${escapeHtml(row.last_seen || "")}">${escapeHtml(relTs(row.last_seen))}</span></td>
          <td>${formatNumber(row.endpoint_count)}</td>
        </tr>
      `).join("");
    }

    function renderSubdomainDetail(row) {
      if (!row) {
        detailContent.innerHTML = '<div class="empty-state">Select a hostname row to inspect its scope, endpoint counts, and aggregated technologies.</div>';
        return;
      }

      const technologyTags = (row.technology_tags || []).length
        ? row.technology_tags.map((tag) => `<span class="subdomain-tech-tag">${escapeHtml(tag)}</span>`).join("")
        : '<span class="muted">No technologies recorded.</span>';

      detailContent.innerHTML = `
        <div class="subdomain-detail-header">
          <div>
            <div class="eyebrow">Hostname Detail</div>
            <h3 class="subdomain-detail-title">${escapeHtml(row.hostname)}</h3>
          </div>
          <div class="finding-dialog-pills">
            ${subdomainStatusPill(row.status)}
          </div>
        </div>
        <div class="finding-fields">
          <div class="finding-field">
            <div class="finding-field-label">Target</div>
            <div class="finding-field-value">${escapeHtml(row.scope_root || "-")}</div>
          </div>
          <div class="finding-field">
            <div class="finding-field-label">Source</div>
            <div class="finding-field-value">${escapeHtml(row.source || "-")}</div>
          </div>
          <div class="finding-field">
            <div class="finding-field-label">First seen</div>
            <div class="finding-field-value">${escapeHtml(fmtTs(row.first_seen))}</div>
          </div>
          <div class="finding-field">
            <div class="finding-field-label">Last seen</div>
            <div class="finding-field-value">${escapeHtml(fmtTs(row.last_seen))}</div>
          </div>
          <div class="finding-field">
            <div class="finding-field-label">Endpoint count</div>
            <div class="finding-field-value">${formatNumber(row.endpoint_count)}</div>
          </div>
          <div class="finding-field">
            <div class="finding-field-label">Alive endpoints</div>
            <div class="finding-field-value">${formatNumber(row.alive_endpoint_count)}</div>
          </div>
        </div>
        <div class="subdomain-tech-section">
          <h3>Technology tags</h3>
          <div class="subdomain-tech-list">${technologyTags}</div>
        </div>
      `;
    }

    async function applyFilters() {
      readFiltersFromControls();
      syncUrl();
      await loadSubdomains();
      applyRelativeTimestamps();
    }

    filtersForm.addEventListener("submit", async (event) => {
      event.preventDefault();
      await applyFilters();
    });

    filtersForm.addEventListener("change", async () => {
      await applyFilters();
    });

    tbody.addEventListener("click", (event) => {
      const row = event.target.closest("tr[data-subdomain-row]");
      if (!row) return;
      state.selectedId = Number(row.dataset.subdomainRow);
      renderSubdomainsTable();
      renderSubdomainDetail(state.rows.find((item) => item.id === state.selectedId) || null);
      applyRelativeTimestamps();
    });

    $("#subdomains-reset").addEventListener("click", async () => {
      state.filters = {
        targetId: "",
        status: "",
        technology: "",
        search: "",
        sortBy: "last_seen",
        sortDir: "desc",
      };
      syncControls();
      await applyFilters();
    });

    syncControls();
    loadTargets()
      .then(() => loadSubdomains())
      .then(() => {
        staleBanner.classList.remove("is-visible");
        setUpdatedAt(updatedAt, Date.now());
        applyRelativeTimestamps();
      })
      .catch((error) => setMessage(message, "error", error.message));

    startPolling({
      intervalMs: 30000,
      run: async () => {
        await loadSubdomains();
        return true;
      },
      onSuccess: () => {
        staleBanner.classList.remove("is-visible");
        setUpdatedAt(updatedAt, Date.now());
        applyRelativeTimestamps();
      },
      onError: (error, failCount) => {
        staleBanner.textContent = `Subdomains refresh failed (${failCount}). ${error.message}`;
        staleBanner.classList.add("is-visible");
      },
    });
  }

  function initTargets() {
    const message = $("#page-message");
    const updatedAt = $("#last-updated");
    const createForm = $("#create-target-form");
    const targetsBody = $("#targets-body");
    const dialog = $("#target-dialog");
    const editForm = $("#edit-target-form");
    const metaPromise = api("/admin/meta");
    let metaCache = null;

    const confirmDeleteDialog = $("#confirm-delete-dialog");
    let _pendingDeleteId = null;
    let _pendingDeleteName = null;

    $("#confirm-delete-cancel").addEventListener("click", () => {
      confirmDeleteDialog.close();
    });

    $("#confirm-delete-confirm").addEventListener("click", async () => {
      confirmDeleteDialog.close();
      const targetId = _pendingDeleteId;
      const scopeRoot = _pendingDeleteName;
      _pendingDeleteId = null;
      _pendingDeleteName = null;
      if (!targetId) return;
      try {
        await api(`/targets/${targetId}/purge`, { method: "POST" });
        setMessage(message, "success", `Deleted ${scopeRoot} and all associated data.`);
        await refresh();
      } catch (error) {
        setMessage(message, "error", error.message);
      }
    });

    confirmDeleteDialog.addEventListener("close", () => {
      _pendingDeleteId = null;
      _pendingDeleteName = null;
    });

    async function refresh() {
      const [meta, targets] = await Promise.all([metaCache ? Promise.resolve(metaCache) : metaPromise, api("/targets")]);
      metaCache = meta;
      renderWordlistOptions($("#create-brute-wordlist"), meta.allowed_wordlists, "dns-small.txt");
      renderTemplateOptions($("#create-nuclei-template"), meta.allowed_nuclei_templates, "all");
      renderWordlistOptions($("#edit-brute-wordlist"), meta.allowed_wordlists, $("#edit-brute-wordlist").value || "dns-small.txt");
      renderTemplateOptions($("#edit-nuclei-template"), meta.allowed_nuclei_templates, $("#edit-nuclei-template").value || "all");
      renderTargetsTable(targets);
      setUpdatedAt(updatedAt, Date.now());
    }

    function renderTargetsTable(targets) {
      $("#targets-count").textContent = `${targets.length} targets`;
      if (!targets.length) {
        targetsBody.innerHTML = '<tr><td colspan="8"><div class="empty-state">No targets configured yet.</div></td></tr>';
        return;
      }
      targetsBody.innerHTML = targets.map((target) => `
        <tr>
          <td><strong>${escapeHtml(target.scope_root)}</strong><div class="muted">${escapeHtml(target.notes || "No notes")}</div></td>
          <td>${target.enabled ? healthPill("healthy") : healthPill("offline")}</td>
          <td>${target.active_recon ? "On" : "Off"}</td>
          <td class="mono">${escapeHtml(target.brute_wordlist || "-")}</td>
          <td class="mono">${escapeHtml(target.nuclei_template || "-")}</td>
          <td>${formatNumber(target.subdomain_count)}</td>
          <td>${formatNumber(target.finding_open_count)}</td>
          <td>
            <div class="target-actions">
              <button type="button" class="outline contrast" data-edit='${escapeHtml(JSON.stringify(target))}'>Edit</button>
              <button type="button" class="secondary" data-run="${target.id}">Run</button>
              <span class="target-actions-sep" aria-hidden="true"></span>
              ${target.enabled ? `<button type="button" class="secondary" data-stop="${target.id}" data-name="${escapeHtml(target.scope_root)}">Stop</button>` : ""}
              <button type="button" class="secondary" data-disable="${target.id}" data-name="${escapeHtml(target.scope_root)}">Disable</button>
              <button type="button" class="outline danger" data-delete="${target.id}" data-name="${escapeHtml(target.scope_root)}">Del</button>
            </div>
          </td>
        </tr>
      `).join("");
    }

    async function submitCreate(event) {
      event.preventDefault();
      const payload = {
        scope_root: $("#create-scope-root").value,
        notes: $("#create-notes").value || null,
        active_recon: $("#create-active-recon").checked,
        brute_wordlist: $("#create-brute-wordlist").value,
        nuclei_template: $("#create-nuclei-template").value,
      };
      try {
        await api("/targets", { method: "POST", body: JSON.stringify(payload) });
        createForm.reset();
        setMessage(message, "success", `Queued recon for ${payload.scope_root}.`);
        await refresh();
      } catch (error) {
        setMessage(message, "error", error.message);
      }
    }

    function openEditDialog(target) {
      $("#edit-target-id").value = String(target.id);
      $("#edit-scope-root").value = target.scope_root;
      $("#edit-notes").value = target.notes || "";
      $("#edit-active-recon").checked = Boolean(target.active_recon);
      $("#edit-brute-wordlist").value = target.brute_wordlist || "dns-small.txt";
      $("#edit-nuclei-template").value = target.nuclei_template || "all";
      dialog.showModal();
    }

    async function submitEdit(event) {
      event.preventDefault();
      const targetId = Number($("#edit-target-id").value);
      const payload = {
        scope_root: $("#edit-scope-root").value,
        notes: $("#edit-notes").value,
        active_recon: $("#edit-active-recon").checked,
        brute_wordlist: $("#edit-brute-wordlist").value,
        nuclei_template: $("#edit-nuclei-template").value,
      };
      try {
        await api(`/targets/${targetId}`, {
          method: "PATCH",
          body: JSON.stringify(payload),
        });
        dialog.close();
        setMessage(message, "success", `Updated ${payload.scope_root}.`);
        await refresh();
      } catch (error) {
        setMessage(message, "error", error.message);
      }
    }

    targetsBody.addEventListener("click", async (event) => {
      const editButton = event.target.closest("button[data-edit]");
      if (editButton) {
        openEditDialog(JSON.parse(editButton.dataset.edit));
        return;
      }

      const runButton = event.target.closest("button[data-run]");
      if (runButton) {
        try {
          const response = await api(`/targets/${runButton.dataset.run}/run`, { method: "POST" });
          setMessage(message, "success", response.dedup_suppressed ? `Run suppressed for ${response.scope_root}.` : `Run queued for ${response.scope_root}.`);
        } catch (error) {
          setMessage(message, "error", error.message);
        }
        await refresh();
        return;
      }

      const stopButton = event.target.closest("button[data-stop]");
      if (stopButton) {
        const targetId = stopButton.dataset.stop;
        const scopeRoot = stopButton.dataset.name;
        try {
          await api(`/targets/${targetId}/stop`, { method: "POST" });
          setMessage(message, "success", `Stopped — pipeline drained for ${scopeRoot}.`);
          await refresh();
        } catch (error) {
          setMessage(message, "error", error.message);
        }
        return;
      }

      const disableButton = event.target.closest("button[data-disable]");
      if (disableButton) {
        const targetId = disableButton.dataset.disable;
        const scopeRoot = disableButton.dataset.name;
        if (!window.confirm(`Disable ${scopeRoot}? Existing data stays in place.`)) return;
        try {
          await api(`/targets/${targetId}`, { method: "DELETE" });
          setMessage(message, "success", `${scopeRoot} disabled.`);
          await refresh();
        } catch (error) {
          setMessage(message, "error", error.message);
        }
        return;
      }

      const deleteButton = event.target.closest("button[data-delete]");
      if (deleteButton) {
        _pendingDeleteId = deleteButton.dataset.delete;
        _pendingDeleteName = deleteButton.dataset.name;
        $("#confirm-delete-name").textContent = _pendingDeleteName;
        confirmDeleteDialog.showModal();
        return;
      }
    });

    createForm.addEventListener("submit", submitCreate);
    editForm.addEventListener("submit", submitEdit);
    $("#edit-cancel").addEventListener("click", () => dialog.close());

    refresh().catch((error) => setMessage(message, "error", error.message));
  }

  function initOps() {
    const message = $("#page-message");
    const staleBanner = $("#stale-banner");
    const updatedAt = $("#last-updated");

    async function loadCore() {
      const [progress, queues, failedJobs] = await Promise.all([
        api(`/admin/progress${buildQuery({
          target_limit: TARGET_LIMIT,
          recent_job_limit: RECENT_JOB_LIMIT,
          window_hours: 24,
        })}`),
        api("/admin/queues"),
        api("/admin/failed-jobs?limit=100"),
      ]);
      return { progress, queues, failedJobs };
    }

    async function loadDlq() {
      const dlq = await api("/admin/dlq");
      renderDlq(dlq);
    }

    function renderOps(data) {
      staleBanner.classList.remove("is-visible");
      setUpdatedAt(updatedAt, Date.now());
      renderWorkerHealth("#ops-worker-health-body", data.progress.recent_jobs || []);
      renderQueueDepths(data.queues || {});
      renderFailedJobs(data.failedJobs || []);
      applyRelativeTimestamps();
    }

    startPolling({
      intervalMs: 15000,
      run: loadCore,
      onSuccess: renderOps,
      onError: (error, failCount) => {
        staleBanner.textContent = `Ops refresh failed (${failCount}). ${error.message}`;
        staleBanner.classList.add("is-visible");
      },
    });

    loadDlq().catch((error) => setMessage(message, "error", error.message));

    $("#dlq-list").addEventListener("click", async (event) => {
      const actionButton = event.target.closest("button[data-dlq-action]");
      if (!actionButton) return;
      const queue = actionButton.dataset.queue;
      const raw = actionButton.dataset.raw;
      const action = actionButton.dataset.dlqAction;
      try {
        await api(`/admin/dlq/${queue}/${action}`, {
          method: "POST",
          body: JSON.stringify({ raw }),
        });
        setMessage(message, "success", `${action === "requeue" ? "Requeued" : "Dismissed"} one ${queue} DLQ item.`);
        await loadDlq();
      } catch (error) {
        setMessage(message, "error", error.message);
      }
    });
  }

  function renderQueueDepths(queues) {
    const tbody = $("#queue-depths-body");
    tbody.innerHTML = STAGES.map((queueName) => {
      const row = queues[queueName] || {};
      const health = Number(row.dlq || 0) > 0 ? "bad" : Number(row.processing || row.pending || 0) > 0 ? "warn" : "good";
      return `
        <tr>
          <td><strong>${escapeHtml(STAGE_LABELS[queueName])}</strong></td>
          <td>${queuePill(health)}</td>
          <td>${formatNumber(row.pending)}</td>
          <td>${formatNumber(row.processing)}</td>
          <td>${formatNumber(row.dlq)}</td>
        </tr>
      `;
    }).join("");
  }

  function renderDlq(dlq) {
    const root = $("#dlq-list");
    const queues = STAGES.map((queueName) => ({ queueName, ...(dlq[queueName] || { depth: 0, recent: [] }) }));
    root.innerHTML = queues.map((queue) => `
      <details class="accordion" ${queue.depth ? "open" : ""}>
        <summary class="accordion-summary">
          <div>
            <h3>${escapeHtml(STAGE_LABELS[queue.queueName])}</h3>
            <div class="muted">${formatNumber(queue.depth)} items waiting in DLQ</div>
          </div>
          ${queue.depth ? queuePill("bad") : queuePill("good")}
        </summary>
        ${queue.recent.length ? queue.recent.map((entry) => `
          <article class="payload-card">
            <div class="payload-card-header">
              <div class="muted">Authoritative raw payload key</div>
              <div class="target-actions">
                <button type="button" class="outline contrast" data-dlq-action="requeue" data-queue="${queue.queueName}" data-raw="${escapeHtml(entry.raw)}">Requeue</button>
                <button type="button" class="secondary" data-dlq-action="dismiss" data-queue="${queue.queueName}" data-raw="${escapeHtml(entry.raw)}">Dismiss</button>
              </div>
            </div>
            <div class="payload-preview">
              <pre>${escapeHtml(entry.payload ? JSON.stringify(entry.payload, null, 2) : entry.raw)}</pre>
            </div>
          </article>
        `).join("") : '<div class="empty-state">No DLQ entries for this queue.</div>'}
      </details>
    `).join("");
  }

  function renderFailedJobs(rows) {
    const tbody = $("#failed-jobs-body");
    if (!rows.length) {
      tbody.innerHTML = '<tr><td colspan="6"><div class="empty-state">No failed jobs recorded.</div></td></tr>';
      return;
    }
    tbody.innerHTML = rows.map((row) => `
      <tr>
        <td><strong>${escapeHtml(row.type)}</strong></td>
        <td>${escapeHtml(row.target_ref || "-")}</td>
        <td>${escapeHtml(row.failure_reason || "-")}</td>
        <td>${formatNumber(row.retry_count)}</td>
        <td><span data-rel-ts="${escapeHtml(row.failed_at || "")}">${escapeHtml(relTs(row.failed_at))}</span></td>
        <td><details><summary>Payload</summary><pre>${escapeHtml(toJsonText(row.payload || "No payload"))}</pre></details></td>
      </tr>
    `).join("");
  }

  function splitCsv(value) {
    if (!value) return [];
    return value.split(",").map((item) => item.trim()).filter(Boolean);
  }

  function selectedValues(select) {
    return [...select.selectedOptions].map((option) => option.value);
  }

  function pressedChipValues(container) {
    return [...container.querySelectorAll(".filter-chip[aria-pressed='true']")].map((chip) => chip.value);
  }

  function initCommon() {
    startRelativeTicker();
  }

  document.addEventListener("DOMContentLoaded", () => {
    initCommon();
    const page = document.body.dataset.page;
    if (page === "dashboard") initDashboard();
    if (page === "findings") initFindings();
    if (page === "subdomains") initSubdomains();
    if (page === "targets") initTargets();
    if (page === "ops") initOps();
  });
})();
