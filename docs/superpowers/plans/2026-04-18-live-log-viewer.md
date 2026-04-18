# Live Log Viewer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a Logs page to the ingestor UI that streams live worker tool output (amass, subfinder, httpx, nuclei) via SSE, with selectable worker, auto-scroll tail, and full-history load.

**Architecture:** Workers currently using `subprocess.run(capture_output=True)` are changed to stream stdout line-by-line into the logger. The ingestor exposes three new REST endpoints: list workers, fetch last-N lines, and an SSE stream. A new `logs.html` page connects via `EventSource` and appends lines in real time.

**Tech Stack:** Python `subprocess.Popen` (threading reader), FastAPI `StreamingResponse` (async generator), Browser `EventSource` API, PicoCSS + vanilla JS.

---

## File Map

| Action | Path | Responsibility |
|--------|------|----------------|
| Modify | `workers/intel/worker.py` | `_run_amass`: Popen + threading reader, log each line |
| Modify | `workers/httpx_worker/worker.py` | `run_httpx`: Popen + threading reader, log each line |
| Modify | `workers/recon/worker.py` | `_stream_into_queue`: add `logger.info(line)` per discovered hostname |
| Modify | `workers/nuclei/worker.py` | Promote non-JSON nuclei output lines from DEBUG → INFO |
| Modify | `ingestor/app.py` | Add `GET /logs`, `GET /logs/{worker}`, `GET /logs/{worker}/stream` |
| Modify | `ingestor/tests/test_api_dashboard_v2.py` | Tests for new log endpoints |
| Create | `ingestor/static/logs.html` | Log viewer page (worker selector, monospace panel, SSE) |
| Modify | `ingestor/static/index.html` | Add "Logs" nav link |
| Modify | `ingestor/static/findings.html` | Add "Logs" nav link |
| Modify | `ingestor/static/subdomains.html` | Add "Logs" nav link |
| Modify | `ingestor/static/targets.html` | Add "Logs" nav link |
| Modify | `ingestor/static/companies.html` | Add "Logs" nav link |
| Modify | `ingestor/static/ops.html` | Add "Logs" nav link |

---

## Task 1: Update worker-intel `_run_amass` to stream line-by-line

**Files:**
- Modify: `workers/intel/worker.py` (function `_run_amass`, lines ~74-95)

### Background

`_run_amass` currently calls `subprocess.run(capture_output=True)`. This buffers all amass stdout until the process exits — which can be 10+ minutes. Changing to `Popen` + a reader thread logs each line immediately and feeds the log file in real time.

- [ ] **Step 1: Write the failing test**

Create `workers/tests/__init__.py` (empty file) and `workers/tests/test_worker_intel.py`:

```python
# workers/tests/test_worker_intel.py
import io
import logging
import sys
import types
from pathlib import Path
from unittest.mock import MagicMock, patch

ROOT = Path(__file__).resolve().parents[2]
WORKERS_DIR = ROOT / "workers"
if str(WORKERS_DIR) not in sys.path:
    sys.path.insert(0, str(WORKERS_DIR))

redis_stub = types.ModuleType("redis")
class _Redis: pass
redis_stub.Redis = _Redis
redis_stub.ConnectionError = Exception
sys.modules.setdefault("redis", redis_stub)

import importlib
intel_worker = importlib.import_module("intel.worker")


def _make_proc(lines: list[str], returncode: int = 0):
    mock_proc = MagicMock()
    # proc.stdout is iterable — reader thread iterates over it
    mock_proc.stdout = iter(lines)
    mock_proc.poll.return_value = returncode
    mock_proc.wait.return_value = returncode
    mock_proc.kill.return_value = None
    return mock_proc


def test_run_amass_logs_each_line(caplog):
    """Every stdout line must be logged at INFO, not batched until process end."""
    fake_lines = ["AS12345, Example Corp\n", "AS67890, Another Corp\n"]
    mock_proc = _make_proc(fake_lines)

    with patch("subprocess.Popen", return_value=mock_proc):
        with caplog.at_level(logging.INFO, logger="worker-intel"):
            result = intel_worker._run_amass(["amass", "intel", "-org", "Example"])

    assert result == ["AS12345, Example Corp", "AS67890, Another Corp"]
    messages = [r.message for r in caplog.records]
    assert any("AS12345" in m for m in messages)
    assert any("AS67890" in m for m in messages)


def test_run_amass_returns_empty_on_missing_binary(caplog):
    with patch("subprocess.Popen", side_effect=FileNotFoundError):
        with caplog.at_level(logging.ERROR, logger="worker-intel"):
            result = intel_worker._run_amass(["amass", "intel", "-org", "Example"])
    assert result == []
    assert any("not found" in r.message for r in caplog.records)
```

- [ ] **Step 2: Run tests to confirm they fail**

```bash
cd C:\Users\Mathias\Documents\pi
python -m pytest workers/tests/test_worker_intel.py -v
```

Expected: `FAILED` — `_run_amass` still uses `subprocess.run`, not `Popen`.

- [ ] **Step 3: Replace `_run_amass` in `workers/intel/worker.py`**

Replace the existing `_run_amass` function (lines ~74-95) with:

```python
def _run_amass(cmd: list[str]) -> list[str]:
    """Run amass and return non-empty stdout lines, logging each as it arrives."""
    logger.info("Running: %s", " ".join(cmd))
    lines: list[str] = []

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
    except FileNotFoundError:
        logger.error("amass binary not found")
        return []
    except Exception as exc:
        logger.error("amass failed to start: %s", exc)
        return []

    import threading

    def _reader():
        assert proc.stdout is not None
        for raw in proc.stdout:
            line = raw.strip()
            if line:
                logger.info(line)
                lines.append(line)

    t = threading.Thread(target=_reader, daemon=True)
    t.start()
    timeout_secs = TIMEOUT_MINUTES * 60 + 30
    t.join(timeout=timeout_secs)

    if t.is_alive():
        proc.kill()
        logger.error("amass timed out after %d minute(s)", TIMEOUT_MINUTES)
        t.join(timeout=5)
    else:
        if proc.poll() not in (0, 1, None):
            logger.warning("amass exited with code %s", proc.poll())

    return lines
```

Also remove the now-unused `import threading` at top level if it was added — check that `threading` is only imported once. (It wasn't imported before, so the inline import is fine, or move it to the top-level imports.)

Actually, move `import threading` to the top of the file with the other stdlib imports. Remove the inline `import threading` inside the function and ensure `import threading` is present in the top-level imports section.

- [ ] **Step 4: Run tests to confirm they pass**

```bash
python -m pytest workers/tests/test_worker_intel.py -v
```

Expected:
```
PASSED workers/tests/test_worker_intel.py::test_run_amass_logs_each_line
PASSED workers/tests/test_worker_intel.py::test_run_amass_returns_empty_on_missing_binary
```

- [ ] **Step 5: Commit**

```bash
rtk git add workers/intel/worker.py workers/tests/__init__.py workers/tests/test_worker_intel.py
rtk git commit -m "feat: stream amass output line-by-line in worker-intel"
```

---

## Task 2: Update worker-httpx `run_httpx` to stream

**Files:**
- Modify: `workers/httpx_worker/worker.py` (function `run_httpx`, lines ~107-150)

### Background

`run_httpx` uses `subprocess.run(capture_output=True)`. httpx with `-silent -o file` produces minimal stdout, but we still change to Popen for consistency so any httpx progress/errors reach the log file as they occur.

- [ ] **Step 1: Replace `run_httpx` in `workers/httpx_worker/worker.py`**

Replace the `run_httpx` function (lines ~107-150) with:

```python
def run_httpx(hostname: str, output_file: str) -> list:
    """
    Run httpx against a hostname and return parsed JSON records from the output file.
    stdout/stderr are logged line-by-line as they arrive.
    """
    cmd = [
        "httpx",
        "-u", hostname,
        "-silent",
        "-json",
        "-o", output_file,
        "-status-code",
        "-title",
        "-tech-detect",
        "-max-redirects", "1",
        "-threads", str(MAX_CONCURRENCY),
        "-timeout", "10",
        "-retries", "1",
        "-no-color",
    ]

    logger.info("httpx: %s", hostname)
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
    except FileNotFoundError:
        logger.error("httpx binary not found for %s", hostname)
        return []

    import threading

    def _reader():
        assert proc.stdout is not None
        for raw in proc.stdout:
            line = raw.strip()
            if line:
                logger.info(line)

    t = threading.Thread(target=_reader, daemon=True)
    t.start()
    t.join(timeout=120)

    if t.is_alive():
        proc.kill()
        logger.error("httpx timed out for %s", hostname)
        t.join(timeout=5)

    if not os.path.exists(output_file):
        return []

    results = []
    with open(output_file) as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                results.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return results
```

Move `import threading` to the top-level imports section of the file (remove any inline one).

- [ ] **Step 2: Run existing tests to verify nothing broke**

```bash
python -m pytest ingestor/tests/test_api_dashboard_v2.py -v -k "httpx or probe"
```

Expected: all existing tests pass (httpx tests mock at the task level, not subprocess level).

- [ ] **Step 3: Commit**

```bash
rtk git add workers/httpx_worker/worker.py
rtk git commit -m "feat: stream httpx output line-by-line in worker-httpx"
```

---

## Task 3: Update worker-recon to log each discovered hostname

**Files:**
- Modify: `workers/recon/worker.py` (function `_stream_into_queue`, lines ~88-147)

### Background

`_stream_into_queue` already uses `Popen` and streams hostnames into a queue, but doesn't log them individually. Adding `logger.info` per line makes individual hostnames visible in the log viewer.

- [ ] **Step 1: Add logger.info per hostname in `_stream_into_queue`**

Find this block inside `_stream_into_queue` (around line 121-123):

```python
                hostname = line.strip()
                if hostname:
                    fh.write(hostname + "\n")
                    out_q.put((hostname, tool_name))
```

Replace with:

```python
                hostname = line.strip()
                if hostname:
                    logger.info("%s: %s", tool_name, hostname)
                    fh.write(hostname + "\n")
                    out_q.put((hostname, tool_name))
```

- [ ] **Step 2: Run existing tests**

```bash
python -m pytest ingestor/tests/test_api_dashboard_v2.py -v
```

Expected: all existing tests pass.

- [ ] **Step 3: Commit**

```bash
rtk git add workers/recon/worker.py
rtk git commit -m "feat: log each discovered hostname in worker-recon"
```

---

## Task 4: Update worker-nuclei to log non-JSON output at INFO

**Files:**
- Modify: `workers/nuclei/worker.py` (scanning loop, around lines 335-338)

### Background

The nuclei scanning loop already uses `Popen` and streams output, but non-JSON lines (tool banners, progress messages, errors) are `logger.debug`. Promoting to INFO makes nuclei progress visible in the log viewer.

- [ ] **Step 1: Promote non-JSON nuclei log lines to INFO**

Find this block in the nuclei scanning loop (around line 335-338):

```python
                try:
                    finding = json.loads(line)
                except json.JSONDecodeError:
                    logger.debug("Non-JSON nuclei output: %s", line[:120])
                    continue
```

Replace with:

```python
                try:
                    finding = json.loads(line)
                except json.JSONDecodeError:
                    logger.info("nuclei: %s", line[:200])
                    continue
```

- [ ] **Step 2: Run existing tests**

```bash
python -m pytest ingestor/tests/test_api_dashboard_v2.py -v
```

Expected: all existing tests pass.

- [ ] **Step 3: Commit**

```bash
rtk git add workers/nuclei/worker.py
rtk git commit -m "feat: log nuclei non-JSON output at INFO in worker-nuclei"
```

---

## Task 5: Add `GET /logs` and `GET /logs/{worker}` endpoints

**Files:**
- Modify: `ingestor/app.py` (add two endpoints + `StreamingResponse` import)
- Modify: `ingestor/tests/test_api_dashboard_v2.py` (add tests)

- [ ] **Step 1: Write failing tests**

Append to `ingestor/tests/test_api_dashboard_v2.py`:

```python
# ---------------------------------------------------------------------------
# Log endpoints
# ---------------------------------------------------------------------------

@pytest.fixture
def log_dir(tmp_path, app_ctx, monkeypatch):
    """Patch LOG_DIR in the loaded ingestor module and return the tmp path."""
    ingestor_app, _, _ = app_ctx
    monkeypatch.setattr(ingestor_app, "LOG_DIR", str(tmp_path))
    return tmp_path


def test_list_logs_empty(client, log_dir):
    r = client.get("/logs")
    assert r.status_code == 200
    assert r.json()["workers"] == []


def test_list_logs_returns_worker_names(client, log_dir):
    (log_dir / "worker-intel.log").write_text("line\n")
    (log_dir / "worker-recon.log").write_text("line\n")
    r = client.get("/logs")
    assert r.status_code == 200
    assert set(r.json()["workers"]) == {"worker-intel", "worker-recon"}


def test_get_log_lines_last_n(client, log_dir):
    content = "\n".join(f"line{i}" for i in range(10)) + "\n"
    (log_dir / "worker-intel.log").write_text(content)
    r = client.get("/logs/worker-intel?lines=3")
    assert r.status_code == 200
    assert r.json()["lines"] == ["line7", "line8", "line9"]


def test_get_log_lines_all(client, log_dir):
    (log_dir / "worker-intel.log").write_text("a\nb\nc\n")
    r = client.get("/logs/worker-intel?lines=0")
    assert r.status_code == 200
    assert r.json()["lines"] == ["a", "b", "c"]


def test_get_log_lines_not_found(client, log_dir):
    r = client.get("/logs/worker-intel")
    assert r.status_code == 404


def test_get_log_invalid_worker_name(client):
    r = client.get("/logs/../etc/shadow")
    assert r.status_code in (400, 404, 422)
```

- [ ] **Step 2: Run tests to confirm they fail**

```bash
python -m pytest ingestor/tests/test_api_dashboard_v2.py -v -k "log"
```

Expected: `FAILED` — endpoints don't exist yet.

- [ ] **Step 3: Add `StreamingResponse` import and new endpoints to `ingestor/app.py`**

At the top of `app.py`, add `StreamingResponse` to the fastapi imports line:

```python
from fastapi.responses import RedirectResponse, StreamingResponse
```

Add `import asyncio` to the stdlib imports near the top.

Then append the following **before** the `if __name__ == "__main__"` block (or just before the `app.mount` / startup lines at the end of the file). Find where the company endpoints end and add after them:

```python
# ---------------------------------------------------------------------------
# Log endpoints
# ---------------------------------------------------------------------------

_LOG_WORKER_RE = re.compile(r"^[\w-]+$")


@app.get("/logs")
def list_logs():
    """Return list of worker names that have log files in LOG_DIR."""
    pattern = os.path.join(LOG_DIR, "*.log")
    import glob as _glob_mod
    files = _glob_mod.glob(pattern)
    workers = sorted(os.path.splitext(os.path.basename(f))[0] for f in files)
    return {"workers": workers}


@app.get("/logs/{worker}")
def get_log_lines(worker: str, lines: int = Query(default=500, ge=0, le=10000)):
    """Return the last `lines` lines from the worker's log file (0 = all)."""
    if not _LOG_WORKER_RE.match(worker):
        raise HTTPException(status_code=400, detail="Invalid worker name")
    log_path = os.path.join(LOG_DIR, f"{worker}.log")
    if not os.path.isfile(log_path):
        raise HTTPException(status_code=404, detail="Log file not found")
    with open(log_path, "r", encoding="utf-8", errors="replace") as fh:
        all_lines = fh.readlines()
    trimmed = [ln.rstrip("\n") for ln in all_lines]
    return {"lines": trimmed if lines == 0 else trimmed[-lines:]}


@app.get("/logs/{worker}/stream")
async def stream_log(worker: str, request: Request):
    """SSE endpoint: seek to end of log file, stream new lines as they arrive."""
    if not _LOG_WORKER_RE.match(worker):
        raise HTTPException(status_code=400, detail="Invalid worker name")
    log_path = os.path.join(LOG_DIR, f"{worker}.log")
    if not os.path.isfile(log_path):
        raise HTTPException(status_code=404, detail="Log file not found")

    async def event_generator():
        with open(log_path, "r", encoding="utf-8", errors="replace") as fh:
            fh.seek(0, 2)
            while True:
                if await request.is_disconnected():
                    break
                line = fh.readline()
                if line:
                    yield f"data: {line.rstrip(chr(10))}\n\n"
                else:
                    await asyncio.sleep(0.2)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
```

Also add `Request` to the fastapi imports (it's needed for `stream_log`):

```python
from fastapi import FastAPI, HTTPException, Query, Request
```

- [ ] **Step 4: Run tests to confirm they pass**

```bash
python -m pytest ingestor/tests/test_api_dashboard_v2.py -v -k "log"
```

Expected: all log endpoint tests pass.

- [ ] **Step 5: Run full test suite**

```bash
python -m pytest ingestor/tests/test_api_dashboard_v2.py -v
```

Expected: all tests pass.

- [ ] **Step 6: Commit**

```bash
rtk git add ingestor/app.py ingestor/tests/test_api_dashboard_v2.py
rtk git commit -m "feat: add GET /logs, /logs/{worker}, /logs/{worker}/stream endpoints"
```

---

## Task 6: Add SSE stream tests

**Files:**
- Modify: `ingestor/tests/test_api_dashboard_v2.py`

- [ ] **Step 1: Write SSE-specific tests**

Append to `ingestor/tests/test_api_dashboard_v2.py`:

```python
def test_stream_log_not_found(client, log_dir):
    r = client.get("/logs/worker-intel/stream")
    assert r.status_code == 404


def test_stream_log_invalid_worker(client):
    r = client.get("/logs/bad..name/stream")
    assert r.status_code in (400, 404, 422)


def test_stream_log_headers(client, log_dir):
    (log_dir / "worker-intel.log").write_text("")
    with client.stream("GET", "/logs/worker-intel/stream") as r:
        assert r.status_code == 200
        assert "text/event-stream" in r.headers["content-type"]
```

- [ ] **Step 2: Run tests**

```bash
python -m pytest ingestor/tests/test_api_dashboard_v2.py -v -k "stream"
```

Expected: all three SSE tests pass.

- [ ] **Step 3: Commit**

```bash
rtk git add ingestor/tests/test_api_dashboard_v2.py
rtk git commit -m "test: add SSE stream endpoint tests"
```

---

## Task 7: Build `logs.html`

**Files:**
- Create: `ingestor/static/logs.html`

- [ ] **Step 1: Create `ingestor/static/logs.html`**

```html
<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Recon Platform | Logs</title>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@picocss/pico@2/css/pico.min.css">
  <link rel="stylesheet" href="/ui/app.css">
  <style>
    .log-toolbar {
      display: flex;
      align-items: center;
      gap: 0.75rem;
      flex-wrap: wrap;
      margin-bottom: 1rem;
    }
    .log-toolbar select {
      margin: 0;
      width: auto;
      min-width: 180px;
    }
    .log-toolbar button {
      margin: 0;
      padding: 0.4rem 0.9rem;
      font-size: 0.85rem;
    }
    .log-panel-wrap {
      position: relative;
    }
    #log-panel {
      background: #060c12;
      border: 1px solid var(--app-border);
      border-radius: var(--app-radius-sm);
      padding: 1rem;
      font-family: "JetBrains Mono", "Fira Mono", ui-monospace, monospace;
      font-size: 0.78rem;
      line-height: 1.6;
      height: 60vh;
      overflow-y: auto;
      white-space: pre-wrap;
      word-break: break-all;
      color: #c9d8ea;
    }
    #log-panel .log-error { color: var(--app-bad); }
    #log-panel .log-warn  { color: var(--app-warn); }

    #jump-btn {
      position: absolute;
      bottom: 1rem;
      right: 1rem;
      padding: 0.3rem 0.8rem;
      font-size: 0.8rem;
      display: none;
    }
    #conn-banner {
      margin-top: 0.5rem;
      font-size: 0.82rem;
    }
  </style>
</head>
<body data-page="logs">
  <div class="app-shell">
    <header class="topbar">
      <div class="topbar-inner">
        <a class="brand" href="/ui/index.html">
          <span class="brand-mark">R</span>
          <span>Recon</span>
        </a>
        <nav class="nav-links" aria-label="Primary">
          <a href="/ui/index.html">Dashboard</a>
          <a href="/ui/findings.html">Findings</a>
          <a href="/ui/subdomains.html">Subdomains</a>
          <a href="/ui/targets.html">Targets</a>
          <a href="/ui/companies.html">Companies</a>
          <a href="/ui/ops.html">Ops</a>
          <a class="is-active" href="/ui/logs.html" aria-current="page">Logs</a>
        </nav>
        <div class="status-meta">
          <span id="conn-dot" class="status-dot bad"></span>
          <span id="conn-label">Disconnected</span>
        </div>
      </div>
    </header>

    <main>
      <div id="page-message" class="message" role="status" aria-live="polite"></div>

      <section class="page-header panel">
        <div class="page-header-copy">
          <h1>Worker Logs</h1>
          <p>Live output from worker tool subprocesses. New lines stream automatically.</p>
        </div>
      </section>

      <section class="panel page-section">
        <div class="log-toolbar">
          <select id="worker-select" aria-label="Select worker">
            <option value="">Loading workers…</option>
          </select>
          <button id="history-btn" class="secondary outline">Load full history</button>
          <button id="clear-btn" class="secondary outline">Clear view</button>
        </div>

        <div class="log-panel-wrap">
          <div id="log-panel" role="log" aria-live="polite" aria-label="Worker log output"></div>
          <button id="jump-btn" class="secondary">↓ Jump to bottom</button>
        </div>

        <div id="conn-banner" class="message" role="status" aria-live="polite"></div>
      </section>
    </main>
  </div>

  <script>
    (() => {
      const panel = document.getElementById("log-panel");
      const workerSelect = document.getElementById("worker-select");
      const historyBtn = document.getElementById("history-btn");
      const clearBtn = document.getElementById("clear-btn");
      const jumpBtn = document.getElementById("jump-btn");
      const connDot = document.getElementById("conn-dot");
      const connLabel = document.getElementById("conn-label");
      const connBanner = document.getElementById("conn-banner");

      let evtSource = null;
      let retryDelay = 1000;
      let retryTimer = null;
      let atBottom = true;

      function escHtml(s) {
        return String(s ?? "")
          .replace(/&/g, "&amp;")
          .replace(/</g, "&lt;")
          .replace(/>/g, "&gt;");
      }

      function classForLine(line) {
        if (/\bERROR\b|\bCRITICAL\b/.test(line)) return "log-error";
        if (/\bWARNING\b|\bWARN\b/.test(line)) return "log-warn";
        return "";
      }

      function appendLine(text) {
        const span = document.createElement("span");
        const cls = classForLine(text);
        if (cls) span.className = cls;
        span.textContent = text + "\n";
        panel.appendChild(span);
        if (atBottom) panel.scrollTop = panel.scrollHeight;
      }

      function setLines(lines) {
        panel.innerHTML = "";
        lines.forEach(appendLine);
        panel.scrollTop = panel.scrollHeight;
        atBottom = true;
      }

      function setConnected(ok, msg) {
        connDot.className = "status-dot " + (ok ? "good" : "bad");
        connLabel.textContent = msg;
      }

      function setBanner(text, type) {
        connBanner.className = "message" + (text ? " is-visible " + type : "");
        connBanner.textContent = text || "";
      }

      panel.addEventListener("scroll", () => {
        const threshold = 40;
        atBottom = panel.scrollTop + panel.clientHeight >= panel.scrollHeight - threshold;
        jumpBtn.style.display = atBottom ? "none" : "block";
      });

      jumpBtn.addEventListener("click", () => {
        panel.scrollTop = panel.scrollHeight;
        atBottom = true;
        jumpBtn.style.display = "none";
      });

      clearBtn.addEventListener("click", () => {
        panel.innerHTML = "";
      });

      historyBtn.addEventListener("click", async () => {
        const worker = workerSelect.value;
        if (!worker) return;
        historyBtn.disabled = true;
        historyBtn.textContent = "Loading…";
        try {
          const r = await fetch(`/logs/${encodeURIComponent(worker)}?lines=0`);
          if (!r.ok) throw new Error(await r.text());
          const { lines } = await r.json();
          setLines(lines);
          // Re-connect stream after full history load
          connectStream(worker);
        } catch (err) {
          setBanner("Failed to load history: " + err.message, "error");
        } finally {
          historyBtn.disabled = false;
          historyBtn.textContent = "Load full history";
        }
      });

      function connectStream(worker) {
        if (evtSource) { evtSource.close(); evtSource = null; }
        if (retryTimer) { clearTimeout(retryTimer); retryTimer = null; }
        if (!worker) return;

        setConnected(false, "Connecting…");
        setBanner("", "");

        evtSource = new EventSource(`/logs/${encodeURIComponent(worker)}/stream`);

        evtSource.onopen = () => {
          setConnected(true, "Streaming");
          retryDelay = 1000;
          setBanner("", "");
        };

        evtSource.onmessage = (evt) => {
          appendLine(evt.data);
        };

        evtSource.onerror = () => {
          evtSource.close();
          evtSource = null;
          setConnected(false, "Disconnected");
          setBanner(`Connection lost — reconnecting in ${Math.round(retryDelay / 1000)}s…`, "error");
          retryTimer = setTimeout(() => connectStream(worker), retryDelay);
          retryDelay = Math.min(retryDelay * 2, 30000);
        };
      }

      async function loadWorkerList() {
        try {
          const r = await fetch("/logs");
          if (!r.ok) throw new Error("HTTP " + r.status);
          const { workers } = await r.json();
          workerSelect.innerHTML = workers.length
            ? workers.map(w => `<option value="${escHtml(w)}">${escHtml(w)}</option>`).join("")
            : `<option value="">No log files found</option>`;
          return workers[0] || null;
        } catch (err) {
          workerSelect.innerHTML = `<option value="">Failed to load workers</option>`;
          return null;
        }
      }

      workerSelect.addEventListener("change", async () => {
        const worker = workerSelect.value;
        panel.innerHTML = "";
        if (!worker) return;
        // Load last 500 lines then connect stream
        try {
          const r = await fetch(`/logs/${encodeURIComponent(worker)}?lines=500`);
          if (!r.ok) throw new Error(await r.text());
          const { lines } = await r.json();
          setLines(lines);
        } catch (err) {
          setBanner("Failed to load log: " + err.message, "error");
        }
        connectStream(worker);
      });

      // Init
      loadWorkerList().then(first => {
        if (first) {
          workerSelect.value = first;
          workerSelect.dispatchEvent(new Event("change"));
        }
      });
    })();
  </script>
</body>
</html>
```

- [ ] **Step 2: Commit**

```bash
rtk git add ingestor/static/logs.html
rtk git commit -m "feat: add logs.html live log viewer page"
```

---

## Task 8: Add "Logs" nav link to all pages

**Files:**
- Modify: `ingestor/static/index.html`
- Modify: `ingestor/static/findings.html`
- Modify: `ingestor/static/subdomains.html`
- Modify: `ingestor/static/targets.html`
- Modify: `ingestor/static/companies.html`
- Modify: `ingestor/static/ops.html`

In each file, find the `<nav class="nav-links">` block. Add the Logs link **after** the Ops link:

```html
<a href="/ui/logs.html">Logs</a>
```

For example, in `index.html` find:
```html
          <a href="/ui/ops.html">Ops</a>
        </nav>
```

Replace with:
```html
          <a href="/ui/ops.html">Ops</a>
          <a href="/ui/logs.html">Logs</a>
        </nav>
```

Repeat for `findings.html`, `subdomains.html`, `targets.html`, `companies.html`, `ops.html`.

- [ ] **Step 1: Edit each HTML file** — add Logs nav link after Ops link in each of the six pages.

- [ ] **Step 2: Verify logs.html already has the correct nav** — it was created in Task 7 with `is-active` on the Logs link. Confirm the other six pages have the plain `<a href="/ui/logs.html">Logs</a>` (no `is-active`).

- [ ] **Step 3: Commit**

```bash
rtk git add ingestor/static/index.html ingestor/static/findings.html ingestor/static/subdomains.html ingestor/static/targets.html ingestor/static/companies.html ingestor/static/ops.html
rtk git commit -m "feat: add Logs nav link to all pages"
```

---

## Task 9: Deploy via Portainer

- [ ] **Step 1: Push to remote**

```bash
rtk git push
```

- [ ] **Step 2: Redeploy via Portainer API**

```bash
source .env
TOKEN=$(curl -s -X POST "$PORTAINER_URL/api/auth" \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"$PORTAINER_USER\",\"password\":\"$PORTAINER_PASSWORD\"}" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['jwt'])")

ENV=$(curl -s -H "Authorization: Bearer $TOKEN" \
  "$PORTAINER_URL/api/stacks/15" \
  | python3 -c "import sys,json; print(json.dumps(json.load(sys.stdin)['Env']))")

curl -s -X PUT "$PORTAINER_URL/api/stacks/15/git/redeploy?endpointId=2" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"env\":$ENV,\"prune\":false,\"pullImage\":true,\"repositoryAuthentication\":false}" \
  | python3 -c "import sys,json; r=json.load(sys.stdin); print('Redeployed:', r['Name'])"
```

- [ ] **Step 3: Verify**

Open `http://192.168.1.191:8090/ui/logs.html` in a browser. Select `worker-intel`. Trigger a company intel scan and watch amass output appear in real time.

---

## Self-Review

- **Spec coverage**: All three spec sections covered — worker subprocess changes (Tasks 1-4), API endpoints (Tasks 5-6), logs.html UI (Task 7-8).
- **Placeholder scan**: No TBDs or incomplete steps.
- **Type consistency**: `_LOG_WORKER_RE` used in both `/logs/{worker}` and `/logs/{worker}/stream`. `LOG_DIR` constant referenced consistently. `Request` import added alongside endpoint definition.
- **Edge cases handled**: Invalid worker name → 400, missing log file → 404, SSE disconnect → generator exits cleanly, retry backoff on connection loss.
