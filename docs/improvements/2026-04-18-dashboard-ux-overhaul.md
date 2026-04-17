# Spec: Dashboard UX Overhaul

**Date:** 2026-04-18  
**Status:** Approved

## Goal

Replace the single-page dashboard with a multi-page UI that splits concerns cleanly: operations, findings triage, target management, and DLQ/ops. Add finding triage states so findings can be actioned. Add a DLQ management UI so stuck tasks can be requeued or dismissed without touching the API directly. Keep the polling architecture and plain HTML/JS stack — no build toolchain.

## Pages

| Page | File | Purpose |
|---|---|---|
| Dashboard | `static/index.html` | Pipeline health, queue depths, worker activity, target list overview |
| Findings | `static/findings.html` | Findings table with triage, filters, detail panel |
| Targets | `static/targets.html` | Full target management — create, edit, delete, all config |
| Ops | `static/ops.html` | DLQ viewer, failed jobs, worker health |

A shared top nav links between pages. Active page is highlighted. Dark theme across all pages using **Pico.css** (CDN-linked, no build step, ~10KB).

---

## Visual Design

- **Theme:** dark (Pico.css `data-theme="dark"`)
- **Layout:** full-width with a fixed top navbar, main content in a centered `<main>` container (max-width ~1200px)
- **Typography:** system font stack via Pico defaults
- **Tables:** sortable client-side where helpful (severity, timestamp)
- **Status badges:** colored pills for severity, finding status, queue health
- **No external icon fonts** — use Unicode/emoji sparingly for status indicators

---

## Data Model Changes

### `findings` table

Add one column:

```sql
ALTER TABLE findings ADD COLUMN status TEXT NOT NULL DEFAULT 'open'
  CHECK(status IN ('open', 'triaged', 'false_positive', 'fixed'));
```

Status meanings:
- `open` — default, unreviewed
- `triaged` — reviewed, confirmed real, pending action
- `false_positive` — reviewed, dismissed
- `fixed` — resolved/remediated

---

## New API Endpoints

### `PATCH /findings/{finding_id}`

Update finding status.

Request:
```json
{ "status": "triaged" }
```

Response (`200`): full finding row.  
Errors: `400` if status value invalid, `404` if not found.

### `GET /admin/dlq`

Already exists — returns DLQ depths + recent entries per stage.  
Extend response to include the raw task payload for each DLQ entry (needed for the requeue UI).

### `POST /admin/dlq/{queue}/requeue`

Requeue one item from a DLQ back to its origin queue.

Request:
```json
{ "index": 0 }
```

Uses `LINDEX` to read the item, `LREM` to remove it from the DLQ, `RPUSH` to the main queue.  
Response (`200`): `{ "requeued": true, "queue": "recon_domain" }`  
Error `404` if index out of range.

### `DELETE /admin/dlq/{queue}/{index}`

Dismiss (permanently remove) one DLQ item.

Uses `LSET` + `LREM` pattern to remove by index atomically.  
Response (`200`): `{ "dismissed": true }`

---

## Page Specs

### Dashboard (`index.html`)

Replaces current dashboard. Keeps existing polling semantics.

Sections:
- **Overview bar** — total targets, live endpoints, total findings (open only), queue depth sum
- **Pipeline panel** — per-stage card: queue depth, processing, DLQ depth, done/hour. Colored indicator (green/amber/red based on DLQ depth and stuck jobs)
- **Worker activity** — table of `recent_jobs` grouped by `worker_name`, showing last seen and last job status. Worker is "healthy" if it completed a job in the last 5 minutes, "stale" if 5–30 min, "offline" if >30 min.
- **Target list** — compact table: scope_root, subdomain count, endpoint count, open findings, last recon, next recon due. Links to findings filtered by target.

Polling: unchanged from current implementation (5s default, overlap guard, stale banner, backoff).

### Findings (`findings.html`)

Sections:
- **Filter bar** — severity (multi-select), target (dropdown), status (multi-select: open/triaged/fp/fixed), time window (1h/24h/7d/all)
- **Findings table** — columns: severity badge, title, matched_at (relative), target, status badge, action button
- **Detail panel** — slides in on row click, shows full finding detail (template_id, matched_at, URL, raw_event if available), status selector, "Mark as" dropdown

Triage actions available inline in the table:
- Mark as triaged
- Mark as false positive
- Mark as fixed

Default filter: `status=open`, last 24h.

Polling: refresh findings table every 30s (findings change less frequently than queue state).

### Targets (`targets.html`)

Replaces the target management that currently lives inside `index.html`.

Sections:
- **Target list table** — all targets with: scope_root, enabled status, active_recon, port_scan (new), brute_wordlist, nuclei_template, subdomain count, open findings count, actions
- **Create target form** — inline expandable form: scope_root, notes, active_recon toggle, port_scan toggle, brute_wordlist select, nuclei_template select
- **Edit target** — same fields in an inline edit row or modal
- **Delete** — soft-disable with confirmation prompt
- **Manual run button** — trigger immediate recon for a target

No polling needed on this page — targets change only on user action.

### Ops (`ops.html`)

Sections:
- **Worker health** — table of worker names, last job completed, last job status, health indicator (healthy/stale/offline). Derived from `recent_jobs` data.
- **Queue depths** — same data as current `/admin/queues` endpoint, in a clean table
- **DLQ panel** — per-queue accordion: DLQ depth, list of items with payload preview, Requeue and Dismiss buttons per item
- **Failed jobs table** — recent rows from `failed_jobs` table: type, target_ref, failure_reason, retry_count, created_at

Polling: 15s refresh for worker health and queue depths. DLQ panel refreshes on user action (requeue/dismiss) only.

---

## Navigation

Shared nav bar rendered in each HTML file (no server-side templating — copy-paste across pages is acceptable for a single-user tool):

```
[RECON] Dashboard | Findings | Targets | Ops
```

Active page link is bold/highlighted. Nav is sticky at the top.

---

## Existing `index.html`

The current `index.html` is replaced by the new multi-page design. The new `index.html` is the Dashboard page. A redirect from `/ui/` to `/ui/index.html` stays in place.

---

## Implementation Order

Within this feature, implement in this order to maintain a working UI at each step:

1. DB migration: add `findings.status` column
2. New API endpoints: `PATCH /findings/{id}`, extend `GET /admin/dlq`, add requeue/dismiss endpoints
3. Design system: Pico.css integration + shared nav + dark theme shell
4. Dashboard page (replaces existing index.html)
5. Findings page
6. Targets page
7. Ops page

---

## Out of Scope

- Server-side templating or a JS framework.
- WebSocket / SSE (polling is sufficient).
- Multi-user auth or role-based access (no auth in v1).
- Bulk triage actions (future).
- Export to CSV/JSON (future).
- Mobile-responsive layout beyond what Pico.css provides by default.
