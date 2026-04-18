# Stop Scans & Delete Target — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `POST /targets/{id}/stop` (drain + disable) and `POST /targets/{id}/purge` (full hard delete) endpoints, wired into the Targets dashboard page.

**Architecture:** Two new FastAPI routes in `ingestor/app.py` backed by two helper functions (`_drain_target_queues`, `_purge_target_files`). Frontend adds Stop and Delete buttons to the existing targets table event-listener in `app.js`, with a new `<dialog>` for delete confirmation in `targets.html`.

**Tech Stack:** Python 3, FastAPI, Redis (LRANGE/LREM/DELETE), SQLite (manual ordered deletes — no CASCADE), vanilla JS, Pico CSS `<dialog>`.

---

## File Map

| File | What changes |
|------|-------------|
| `ingestor/app.py` | Add `_drain_target_queues()`, `_purge_target_files()` helpers; add two new routes |
| `ingestor/tests/test_api_dashboard_v2.py` | Extend `FakeRedis` with `delete` + `lpush`; add tests for both endpoints |
| `ingestor/static/targets.html` | Add Stop/Delete buttons to table; add `<dialog id="confirm-delete-dialog">` |
| `ingestor/static/app.js` | Add `stopTarget`, `deleteTarget` handlers in `initTargets` event listener |
| `docs/api.md` | Document both new endpoints |

---

## Task 1: Extend FakeRedis and write failing tests for `/stop`

**Files:**
- Modify: `ingestor/tests/test_api_dashboard_v2.py`

- [ ] **Step 1: Add `delete` and `lpush` methods to `FakeRedis`**

Open `ingestor/tests/test_api_dashboard_v2.py`. After the `lrem` method (line ~85), add:

```python
    def lpush(self, key, *values):
        bucket = self.lists.setdefault(key, [])
        for v in reversed(values):
            bucket.insert(0, v)
        return len(bucket)

    def delete(self, *keys):
        deleted = 0
        for key in keys:
            if key in self.lists:
                del self.lists[key]
                deleted += 1
        return deleted
```

- [ ] **Step 2: Add `_insert_finding` helper after `_insert_endpoint`**

```python
def _insert_finding(ingestor_app, endpoint_id, template_id="test-tpl", raw_blob_path=None):
    with ingestor_app.db_conn() as conn:
        return conn.execute(
            "INSERT INTO findings (endpoint_id, template_id, severity, matched_at, raw_blob_path, dedupe_key) VALUES (?, ?, ?, ?, ?, ?)",
            (endpoint_id, template_id, "high", "https://example.com", raw_blob_path, f"key-{template_id}-{endpoint_id}"),
        ).lastrowid
```

- [ ] **Step 3: Write failing tests for `POST /targets/{id}/stop`**

Add after the existing `test_run_target_now_*` tests:

```python
def test_stop_target_disables_and_drains(client):
    test_client, ingestor_app, fake_redis, _ = client
    target_id = _insert_target(ingestor_app, scope_root="stop.example.com", enabled=1)

    # Pre-populate queues with tasks for this target and a different target
    import json
    fake_redis.lpush("recon_domain", json.dumps({"domain": "stop.example.com"}))
    fake_redis.lpush("recon_domain", json.dumps({"domain": "other.example.com"}))
    fake_redis.lpush("probe_host", json.dumps({"hostname": "sub.stop.example.com", "scope_root": "stop.example.com"}))
    fake_redis.lpush("probe_host:processing", json.dumps({"hostname": "sub2.stop.example.com", "scope_root": "stop.example.com"}))

    res = test_client.post(f"/targets/{target_id}/stop")
    assert res.status_code == 200
    body = res.json()
    assert body["stopped"] is True
    assert body["scope_root"] == "stop.example.com"
    assert body["tasks_drained"] == 3  # recon + probe + probe:processing

    # Target should be disabled in DB
    with ingestor_app.db_conn() as conn:
        row = conn.execute("SELECT enabled FROM targets WHERE id = ?", (target_id,)).fetchone()
    assert row["enabled"] == 0

    # Unrelated task should survive
    assert fake_redis.llen("recon_domain") == 1
    remaining = json.loads(fake_redis.lrange("recon_domain", 0, 0)[0])
    assert remaining["domain"] == "other.example.com"


def test_stop_target_404(client):
    test_client, _, _, _ = client
    res = test_client.post("/targets/9999/stop")
    assert res.status_code == 404


def test_stop_target_already_disabled_is_idempotent(client):
    test_client, ingestor_app, _, _ = client
    target_id = _insert_target(ingestor_app, scope_root="disabled.example.com", enabled=0)
    res = test_client.post(f"/targets/{target_id}/stop")
    assert res.status_code == 200
    assert res.json()["stopped"] is True
```

- [ ] **Step 4: Run tests to confirm they fail**

```bash
cd ingestor && python -m pytest tests/test_api_dashboard_v2.py::test_stop_target_disables_and_drains tests/test_api_dashboard_v2.py::test_stop_target_404 tests/test_api_dashboard_v2.py::test_stop_target_already_disabled_is_idempotent -v
```

Expected: 3 FAILs — `404` for the stop route (not yet implemented).

---

## Task 2: Implement `_drain_target_queues` and `POST /targets/{id}/stop`

**Files:**
- Modify: `ingestor/app.py`

- [ ] **Step 1: Add `_drain_target_queues` helper**

In `ingestor/app.py`, after the `_DLQ_QUEUES` list definition (around line 77), add:

```python
_ALL_QUEUES = ["recon_domain", "brute_domain", "probe_host", "scan_http", "notify_finding"]
```

Then, after the `_decode_json_text` helper function, add:

```python
def _drain_target_queues(r: redis_lib.Redis, scope_root: str) -> int:
    """Remove all pending/processing queue entries for scope_root. Returns count removed."""
    drained = 0
    queue_lists = _ALL_QUEUES + [f"{q}:processing" for q in _ALL_QUEUES]
    for queue in queue_lists:
        items = r.lrange(queue, 0, -1)
        for raw in items:
            try:
                payload = json.loads(raw if isinstance(raw, str) else raw.decode())
                if payload.get("domain") == scope_root or payload.get("scope_root") == scope_root:
                    drained += r.lrem(queue, 1, raw)
            except Exception:
                continue
    inflight_keys = [
        f"inflight:recon_domain:{scope_root}",
        f"inflight:recon_domain:manual:{scope_root}",
        f"inflight:brute_domain:brute:{scope_root}",
    ]
    r.delete(*inflight_keys)
    return drained
```

- [ ] **Step 2: Add `POST /targets/{target_id}/stop` route**

After the `DELETE /targets/{target_id}` route (around line 888), add:

```python
@app.post("/targets/{target_id}/stop", status_code=200)
def stop_target(target_id: int):
    with db_conn() as conn:
        row = conn.execute("SELECT scope_root FROM targets WHERE id = ?", (target_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Target not found")
        conn.execute("UPDATE targets SET enabled = 0 WHERE id = ?", (target_id,))
    scope_root = row["scope_root"]
    drained = _drain_target_queues(get_r(), scope_root)
    logger.info("Stopped target %s — drained %d task(s)", scope_root, drained)
    return {"stopped": True, "scope_root": scope_root, "tasks_drained": drained}
```

- [ ] **Step 3: Run stop tests — expect pass**

```bash
cd ingestor && python -m pytest tests/test_api_dashboard_v2.py::test_stop_target_disables_and_drains tests/test_api_dashboard_v2.py::test_stop_target_404 tests/test_api_dashboard_v2.py::test_stop_target_already_disabled_is_idempotent -v
```

Expected: 3 PASSes.

- [ ] **Step 4: Run full test suite to check for regressions**

```bash
cd ingestor && python -m pytest tests/ -v
```

Expected: all existing tests still pass.

- [ ] **Step 5: Commit**

```bash
rtk git add ingestor/app.py ingestor/tests/test_api_dashboard_v2.py && rtk git commit -m "feat: add POST /targets/{id}/stop — drain queues and disable target"
```

---

## Task 3: Write failing tests for `/purge`

**Files:**
- Modify: `ingestor/tests/test_api_dashboard_v2.py`

- [ ] **Step 1: Add purge tests**

Add after the stop tests:

```python
def test_purge_target_removes_all_data(client, tmp_path, monkeypatch):
    test_client, ingestor_app, fake_redis, _ = client

    # Point OUTPUT_DIR to tmp_path so file deletion is testable
    monkeypatch.setattr(ingestor_app, "_OUTPUT_DIR", str(tmp_path))

    target_id = _insert_target(ingestor_app, scope_root="purge.example.com", enabled=1)
    endpoint_id = _insert_endpoint(ingestor_app, target_id, "sub.purge.example.com")

    # Create a real file that should be deleted
    raw_blob = tmp_path / "purge.example.com_nuclei.jsonl"
    raw_blob.write_text('{"template-id": "test"}\n')
    _insert_finding(ingestor_app, endpoint_id, raw_blob_path=str(raw_blob))

    # Add a queue task for this target
    import json
    fake_redis.lpush("recon_domain", json.dumps({"domain": "purge.example.com"}))

    res = test_client.post(f"/targets/{target_id}/purge")
    assert res.status_code == 200
    body = res.json()
    assert body["purged"] is True
    assert body["scope_root"] == "purge.example.com"
    assert body["files_deleted"] >= 1

    # DB records gone
    with ingestor_app.db_conn() as conn:
        assert conn.execute("SELECT id FROM targets WHERE id = ?", (target_id,)).fetchone() is None
        assert conn.execute("SELECT id FROM subdomains WHERE target_id = ?", (target_id,)).fetchone() is None
        assert conn.execute("SELECT id FROM endpoints WHERE id = ?", (endpoint_id,)).fetchone() is None
        assert conn.execute("SELECT id FROM findings WHERE endpoint_id = ?", (endpoint_id,)).fetchone() is None

    # File deleted
    assert not raw_blob.exists()

    # Queue drained
    assert fake_redis.llen("recon_domain") == 0


def test_purge_target_404(client):
    test_client, _, _, _ = client
    res = test_client.post("/targets/9999/purge")
    assert res.status_code == 404


def test_purge_target_no_data(client):
    """Purge a target with no subdomains/findings — should succeed cleanly."""
    test_client, ingestor_app, _, _ = client
    target_id = _insert_target(ingestor_app, scope_root="bare.example.com", enabled=1)
    res = test_client.post(f"/targets/{target_id}/purge")
    assert res.status_code == 200
    body = res.json()
    assert body["purged"] is True
    assert body["files_deleted"] == 0
    with ingestor_app.db_conn() as conn:
        assert conn.execute("SELECT id FROM targets WHERE id = ?", (target_id,)).fetchone() is None
```

- [ ] **Step 2: Run to confirm failures**

```bash
cd ingestor && python -m pytest tests/test_api_dashboard_v2.py::test_purge_target_removes_all_data tests/test_api_dashboard_v2.py::test_purge_target_404 tests/test_api_dashboard_v2.py::test_purge_target_no_data -v
```

Expected: 3 FAILs — purge route not yet defined.

---

## Task 4: Implement `_purge_target_files` and `POST /targets/{id}/purge`

**Files:**
- Modify: `ingestor/app.py`

- [ ] **Step 1: Add `import glob as _glob` at the top of `ingestor/app.py`**

Find the imports block (around line 28) and add after `import re`:

```python
import glob as _glob
```

- [ ] **Step 2: Add `_purge_target_files` helper**

After the `_drain_target_queues` function, add:

```python
def _purge_target_files(target_id: int, scope_root: str) -> int:
    """Delete output files for a target. Returns count of files deleted."""
    deleted = 0
    paths_to_delete: set[str] = set()

    with db_conn() as conn:
        rows = conn.execute(
            """
            SELECT f.raw_blob_path FROM findings f
            JOIN endpoints e ON e.id = f.endpoint_id
            JOIN subdomains s ON s.id = e.subdomain_id
            WHERE s.target_id = ?
            """,
            (target_id,),
        ).fetchall()

    for row in rows:
        path = row["raw_blob_path"]
        if path and _is_path_within_base(path, _OUTPUT_DIR):
            paths_to_delete.add(path)

    pattern = os.path.join(_OUTPUT_DIR, "**", f"*{scope_root}*")
    for path in _glob.glob(pattern, recursive=True):
        if _is_path_within_base(path, _OUTPUT_DIR):
            paths_to_delete.add(path)

    for path in paths_to_delete:
        try:
            if os.path.isfile(path):
                os.remove(path)
                deleted += 1
        except OSError as exc:
            logger.warning("Purge: could not remove %s: %s", path, exc)

    return deleted
```

- [ ] **Step 3: Add `POST /targets/{target_id}/purge` route**

After the `stop_target` route, add:

```python
@app.post("/targets/{target_id}/purge", status_code=200)
def purge_target(target_id: int):
    with db_conn() as conn:
        row = conn.execute("SELECT scope_root FROM targets WHERE id = ?", (target_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Target not found")

    scope_root = row["scope_root"]
    _drain_target_queues(get_r(), scope_root)
    files_deleted = _purge_target_files(target_id, scope_root)

    with db_conn() as conn:
        subdomain_ids = [r["id"] for r in conn.execute(
            "SELECT id FROM subdomains WHERE target_id = ?", (target_id,)
        ).fetchall()]

        if subdomain_ids:
            ph = ",".join("?" * len(subdomain_ids))
            endpoint_ids = [r["id"] for r in conn.execute(
                f"SELECT id FROM endpoints WHERE subdomain_id IN ({ph})", subdomain_ids
            ).fetchall()]

            if endpoint_ids:
                ep_ph = ",".join("?" * len(endpoint_ids))
                finding_ids = [r["id"] for r in conn.execute(
                    f"SELECT id FROM findings WHERE endpoint_id IN ({ep_ph})", endpoint_ids
                ).fetchall()]

                if finding_ids:
                    fi_ph = ",".join("?" * len(finding_ids))
                    conn.execute(f"DELETE FROM notifications WHERE finding_id IN ({fi_ph})", finding_ids)
                    conn.execute(f"DELETE FROM findings WHERE id IN ({fi_ph})", finding_ids)

                conn.execute(f"DELETE FROM endpoints WHERE id IN ({ep_ph})", endpoint_ids)

            conn.execute(f"DELETE FROM subdomains WHERE id IN ({ph})", subdomain_ids)

        conn.execute("DELETE FROM jobs WHERE target_ref = ?", (scope_root,))
        conn.execute("DELETE FROM failed_jobs WHERE target_ref = ?", (scope_root,))
        conn.execute("DELETE FROM targets WHERE id = ?", (target_id,))

    logger.info("Purged target %s (id=%d) — %d file(s) deleted", scope_root, target_id, files_deleted)
    return {"purged": True, "scope_root": scope_root, "files_deleted": files_deleted}
```

- [ ] **Step 4: Run purge tests — expect pass**

```bash
cd ingestor && python -m pytest tests/test_api_dashboard_v2.py::test_purge_target_removes_all_data tests/test_api_dashboard_v2.py::test_purge_target_404 tests/test_api_dashboard_v2.py::test_purge_target_no_data -v
```

Expected: 3 PASSes.

- [ ] **Step 5: Run full test suite**

```bash
cd ingestor && python -m pytest tests/ -v
```

Expected: all tests pass.

- [ ] **Step 6: Commit**

```bash
rtk git add ingestor/app.py ingestor/tests/test_api_dashboard_v2.py && rtk git commit -m "feat: add POST /targets/{id}/purge — hard delete target and all associated data"
```

---

## Task 5: Update API docs

**Files:**
- Modify: `docs/api.md`

- [ ] **Step 1: Add stop and purge endpoint docs**

In `docs/api.md`, find the `### DELETE /targets/{target_id}` section. After it, add:

```markdown
### POST `/targets/{target_id}/stop`

Disable target and drain all pending queue entries for it across all pipeline stages.

In-flight subprocesses (actively running subfinder/nuclei) finish naturally; workers skip downstream enqueuing once they see `enabled=0`.

Response (`200`):

```json
{
  "stopped": true,
  "scope_root": "example.com",
  "tasks_drained": 3
}
```

Responses:
- `200`: stopped (idempotent — safe to call on already-disabled targets)
- `404`: unknown target

---

### POST `/targets/{target_id}/purge`

Hard-delete a target and all associated data: subdomains, endpoints, findings, notifications, jobs, failed jobs, Redis queue entries, dedup keys, and raw output files on disk.

**This is irreversible.**

Response (`200`):

```json
{
  "purged": true,
  "scope_root": "example.com",
  "files_deleted": 4
}
```

Responses:
- `200`: purged
- `404`: unknown target
```

- [ ] **Step 2: Commit**

```bash
rtk git add docs/api.md && rtk git commit -m "docs: document /stop and /purge target endpoints"
```

---

## Task 6: Add Stop button to `targets.html` and `app.js`

**Files:**
- Modify: `ingestor/static/targets.html`
- Modify: `ingestor/static/app.js`

- [ ] **Step 1: Add Stop button to the table row template in `app.js`**

In `ingestor/static/app.js`, find the `renderTargetsTable` function (~line 633). Replace the Actions `<td>` content:

Old:
```javascript
          <td>
            <div class="table-actions">
              <button type="button" class="contrast" data-edit='${escapeHtml(JSON.stringify(target))}'>Edit</button>
              <button type="button" class="secondary" data-run="${target.id}">Run now</button>
              <button type="button" class="secondary" data-disable="${target.id}" data-name="${escapeHtml(target.scope_root)}">Disable</button>
            </div>
          </td>
```

New:
```javascript
          <td>
            <div class="table-actions">
              <button type="button" class="contrast" data-edit='${escapeHtml(JSON.stringify(target))}'>Edit</button>
              <button type="button" class="secondary" data-run="${target.id}">Run now</button>
              ${target.enabled ? `<button type="button" class="secondary" data-stop="${target.id}" data-name="${escapeHtml(target.scope_root)}">Stop</button>` : ""}
              <button type="button" class="secondary" data-disable="${target.id}" data-name="${escapeHtml(target.scope_root)}">Disable</button>
              <button type="button" class="outline danger" data-delete="${target.id}" data-name="${escapeHtml(target.scope_root)}">Delete</button>
            </div>
          </td>
```

- [ ] **Step 2: Add Stop handler in the `targetsBody` click listener**

In `ingestor/static/app.js`, find the `targetsBody.addEventListener("click", ...)` block (~line 711). After the `runButton` block and before the `disableButton` block, add:

```javascript
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
```

- [ ] **Step 3: Commit**

```bash
rtk git add ingestor/static/app.js && rtk git commit -m "feat: add Stop button to targets table"
```

---

## Task 7: Add Delete button and confirmation dialog

**Files:**
- Modify: `ingestor/static/targets.html`
- Modify: `ingestor/static/app.js`

- [ ] **Step 1: Add delete confirmation `<dialog>` to `targets.html`**

In `ingestor/static/targets.html`, find the closing `</dialog>` tag for `target-dialog` (~line 143). After it, add:

```html
    <dialog id="confirm-delete-dialog">
      <article>
        <header>
          <h2>Delete target?</h2>
        </header>
        <p>This will permanently remove <strong id="confirm-delete-name"></strong> and all associated subdomains, endpoints, findings, jobs, and output files.</p>
        <p><strong>This cannot be undone.</strong></p>
        <div class="dialog-actions">
          <button type="button" id="confirm-delete-cancel" class="secondary">Cancel</button>
          <button type="button" id="confirm-delete-confirm" class="danger">Delete</button>
        </div>
      </article>
    </dialog>
```

- [ ] **Step 2: Add Delete handler in `initTargets` in `app.js`**

In `ingestor/static/app.js`, find `function initTargets()` (the block that starts with `const targetsBody = ...`). After the `const dialog = ...` line, add:

```javascript
    const confirmDeleteDialog = $("#confirm-delete-dialog");
    let _pendingDeleteId = null;
    let _pendingDeleteName = null;

    $("#confirm-delete-cancel").addEventListener("click", () => {
      confirmDeleteDialog.close();
      _pendingDeleteId = null;
      _pendingDeleteName = null;
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
```

- [ ] **Step 3: Add delete button handler in the `targetsBody` click listener**

In the `targetsBody.addEventListener("click", ...)` block, after the `disableButton` block, add:

```javascript
      const deleteButton = event.target.closest("button[data-delete]");
      if (deleteButton) {
        _pendingDeleteId = deleteButton.dataset.delete;
        _pendingDeleteName = deleteButton.dataset.name;
        $("#confirm-delete-name").textContent = _pendingDeleteName;
        confirmDeleteDialog.showModal();
        return;
      }
```

- [ ] **Step 4: Add `.danger` button style to `app.css` if not already present**

Check `ingestor/static/app.css` for a `.danger` rule. If missing, append:

```css
button.danger, [role="button"].danger {
  --pico-background-color: var(--pico-del-color, #c0392b);
  --pico-border-color: var(--pico-del-color, #c0392b);
  --pico-color: #fff;
}
button.danger:hover, [role="button"].danger:hover {
  filter: brightness(0.88);
}
```

- [ ] **Step 5: Run full test suite one last time**

```bash
cd ingestor && python -m pytest tests/ -v
```

Expected: all tests pass.

- [ ] **Step 6: Commit**

```bash
rtk git add ingestor/static/targets.html ingestor/static/app.js ingestor/static/app.css && rtk git commit -m "feat: add Delete button with confirmation dialog to targets page"
```
