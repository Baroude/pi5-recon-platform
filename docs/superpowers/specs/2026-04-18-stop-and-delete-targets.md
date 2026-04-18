# Stop Scans & Delete Target — Design Spec

**Date:** 2026-04-18  
**Scope:** Two new operator actions accessible from the dashboard Targets page.

---

## Overview

Two new capabilities added to the recon platform:

1. **Stop** — disable a target and drain all pending queue entries for it, halting the pipeline without deleting any data. Reversible.
2. **Purge** — hard-delete a target and all associated data: DB records, Redis queue entries, dedup keys, and raw output files on disk. Irreversible.

---

## Backend

### `POST /targets/{target_id}/stop`

**Purpose:** Drain + disable. Stops new work from being picked up for this target.

**Steps:**
1. Fetch `scope_root` for `target_id` — 404 if not found.
2. Set `targets.enabled = 0`.
3. For each of the 10 queue lists (`recon_domain`, `brute_domain`, `probe_host`, `scan_http`, `notify_finding` + their `:processing` mirrors):
   - `LRANGE` the full list.
   - For each entry: parse JSON, check if `payload["domain"] == scope_root` (for recon/brute queues) or `payload["scope_root"] == scope_root` (for probe/scan/notify queues). If either matches, `LREM count=1`.
4. Delete Redis dedup/inflight keys matching patterns:
   - `inflight:recon_domain:{scope_root}`
   - `inflight:recon_domain:manual:{scope_root}`
   - `inflight:brute_domain:brute:{scope_root}`
5. Return `{"stopped": true, "scope_root": "...", "tasks_drained": N}`.

**Behavior of in-flight tasks:** Workers that are already mid-execution (subprocess running) finish naturally. When they try to enqueue downstream tasks, the next worker sees `enabled=0` and skips. The target is effectively frozen within one task cycle (~minutes at most).

**Response codes:** `200` success, `404` target not found.

---

### `POST /targets/{target_id}/purge`

**Purpose:** Full hard delete of the target and all associated data.

**Steps:**
1. Fetch `scope_root` and `target_id` — 404 if not found.
2. Run stop logic (drain queues, clear dedup keys, set `enabled=0`).
3. Collect `raw_blob_path` values from all `findings` rows linked to this target's subdomains (via `findings → endpoints → subdomains → target_id`). Filter paths that are within `OUTPUT_DIR` using `_is_path_within_base`.
4. Glob `OUTPUT_DIR/**/*{scope_root}*` for any worker-generated JSONL/TXT not linked to a finding (e.g. subfinder/amass output files). Filter to within `OUTPUT_DIR`.
5. Delete collected files; count deletions; log errors but don't abort.
6. Delete DB rows in order (no CASCADE on FKs):
   - `notifications` WHERE `finding_id IN (findings for this target)`
   - `findings` WHERE `endpoint_id IN (endpoints for this target)`
   - `endpoints` WHERE `subdomain_id IN (subdomains for this target)`
   - `subdomains` WHERE `target_id = ?`
   - `jobs` WHERE `target_ref = scope_root`
   - `failed_jobs` WHERE `target_ref = scope_root`
   - `targets` WHERE `id = target_id`
7. Return `{"purged": true, "scope_root": "...", "files_deleted": N}`.

**Response codes:** `200` success, `404` target not found.

---

## Frontend (`targets.html` / `app.js`)

### Action buttons

The existing **Actions** column in the target inventory table gains two buttons per row:

| Button | Condition | Action |
|--------|-----------|--------|
| **Stop** | `enabled == 1` only | `POST /targets/{id}/stop` — no confirmation dialog (reversible) |
| **Delete** | Always visible | Opens confirmation `<dialog>`, then `POST /targets/{id}/purge` |

**Full button order in the Actions column:** Edit · Run · Stop · Disable · Delete

### Stop button behaviour
- Calls `POST /targets/{id}/stop`.
- On success: updates the row status to disabled (same visual as after a Disable action) and shows a brief toast "Stopped — pipeline drained."
- On error: shows error toast with response detail.
- Hidden when target is already disabled (same condition as the existing Run button).

### Delete button behaviour
- Opens a `<dialog>` (reuse existing `target-dialog` pattern or a new `confirm-dialog`):
  ```
  Delete [scope_root]?
  This will permanently remove all subdomains, endpoints, findings, jobs,
  and output files for this target. This cannot be undone.
  [Cancel]  [Delete]   ← Delete button styled destructive (red/outline-danger)
  ```
- On confirm: calls `POST /targets/{id}/purge`.
- On success: removes the table row from the DOM, shows toast "Deleted [scope_root] and all associated data."
- On error: closes dialog, shows error toast.

---

## Data integrity notes

- **No ON DELETE CASCADE** in the schema — explicit ordered deletes required (see step 6 above).
- **`jobs` and `failed_jobs`** use `target_ref TEXT` (not a FK) — deleted manually by `target_ref = scope_root`.
- **Output file deletion** uses the existing `_is_path_within_base(path, OUTPUT_DIR)` guard to prevent path traversal.
- **Concurrency:** A worker mid-execution for a purged target will get "target not found" at its DB check and nack normally. No special handling needed.
- **Stop idempotency:** Calling stop on an already-disabled target is safe — it re-drains queues and returns success.

---

## Files changed

| File | Change |
|------|--------|
| `ingestor/app.py` | Add `POST /targets/{id}/stop`, `POST /targets/{id}/purge` routes; add `_drain_target_queues()` and `_purge_target_files()` helpers |
| `ingestor/static/targets.html` | Add Stop and Delete buttons; add delete confirmation `<dialog>` |
| `ingestor/static/app.js` | Add `stopTarget()`, `deleteTarget()` JS functions; wire up dialog and toasts |
| `docs/api.md` | Document both new endpoints |
