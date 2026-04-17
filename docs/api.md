# API Reference

The ingestor serves HTTP JSON APIs on port `8090` (override with `INGESTOR_PORT`).

Base URL:

```text
http://<pi-ip>:8090
```

No auth is implemented in v1. Restrict network access at deployment time.

## Targets

### POST `/targets`

Create a target (or re-enable a disabled one) and enqueue initial recon.

Request body:

```json
{
  "scope_root": "example.com",
  "notes": "bug bounty program",
  "active_recon": true,
  "brute_wordlist": "dns-medium.txt",
  "nuclei_template": "http"
}
```

`brute_wordlist` must be one of:

- `dns-small.txt`
- `dns-medium.txt`
- `dns-large.txt`

`nuclei_template` must be one of the values returned by `GET /admin/meta`
under `allowed_nuclei_templates`. The default is `all`.

Response (`201`):

```json
{
  "id": 1,
  "scope_root": "example.com",
  "queued": true,
  "active_recon": true,
  "brute_wordlist": "dns-medium.txt",
  "nuclei_template": "http"
}
```

### GET `/targets`

List targets and target-level summary fields.

### PATCH `/targets/{target_id}`

Update target scan config.

Request body supports:

- `active_recon` (bool)
- `brute_wordlist` (allowed values above)
- `nuclei_template` (allowed values from `GET /admin/meta`)

### POST `/targets/{target_id}/run`

Manually trigger a recon enqueue for one target.

Responses:

- `200`: queued or dedup-suppressed
- `404`: unknown target
- `409`: target exists but is disabled

Response shape:

```json
{
  "target_id": 1,
  "scope_root": "example.com",
  "queued": true,
  "dedup_suppressed": false
}
```

### DELETE `/targets/{target_id}`

Disable target (data is retained).

### GET `/targets/{target_id}/jobs`

Get recent jobs for a target.

Query:

- `limit` (default `20`, max `100`)

## Dashboard/Admin

### GET `/admin/meta`

Dashboard metadata for UI controls and scan config options.

Response shape:

```json
{
  "allowed_wordlists": ["dns-large.txt", "dns-medium.txt", "dns-small.txt"],
  "allowed_nuclei_templates": ["all", "dns", "http", "network", "ssl"],
  "recon_interval_hours": 24.0,
  "defaults": {
    "window_hours": 24,
    "target_limit": 200,
    "recent_job_limit": 60,
    "refresh_interval_secs": 5
  },
  "bounds": {
    "window_hours": {"min": 1, "max": 168},
    "target_limit": {"min": 1, "max": 500},
    "recent_job_limit": {"min": 5, "max": 200},
    "refresh_interval_secs": {"min": 2, "max": 60}
  }
}
```

### GET `/admin/progress`

Consolidated operator snapshot used by the dashboard.

Query:

- `target_limit` (default `200`, min `1`, max `500`)
- `recent_job_limit` (default `60`, min `5`, max `200`)
- `window_hours` (default `24`, min `1`, max `168`)

Includes:

- `overview` global metrics plus:
  - `oldest_running_started_at`
  - `last_job_finished_at`
- `pipeline` per-stage queue + status totals plus:
  - `done_per_hour_window`
  - stages: `recon_domain`, `brute_domain`, `probe_host`, `scan_http`, `notify_finding`
- `targets` with config + scheduling fields:
  - `active_recon`
  - `brute_wordlist`
  - `nuclei_template`
  - `next_recon_due_at`
  - `next_recon_in_secs`
  - `is_recon_overdue`
- `recent_jobs`

### GET `/admin/queues`

Live queue depths for each pipeline stage:

- pending (`<queue>`)
- processing (`<queue>:processing`)
- dead letter (`dlq:<queue>`)

Current stages:

- `recon_domain`
- `brute_domain`
- `probe_host`
- `scan_http`
- `notify_finding`

### GET `/admin/dlq`

DLQ depths plus recent DLQ entries per stage.

## Findings and Subdomains

### GET `/findings`

Query recent findings with optional filters.

Query:

- `severity` (optional: `info|low|medium|high|critical`)
- `target_id` (optional)
- `window_hours` (optional, min `1`, max `168`)
- `limit` (default `50`, max `500`)

Response rows include `scope_root` for target-scoped UI filtering.

### GET `/findings/{finding_id}`

Return the full persisted finding plus a best-effort raw nuclei event loaded from
the associated JSONL artifact under `OUTPUT_DIR`.

Response includes:

- finding fields such as `template_id`, `severity`, `title`, `matched_at`
- endpoint/target context such as `url`, `host`, `hostname`, `target_id`, `scope_root`
- `raw_event` when a matching JSONL event can be found
- `raw_event_error` when the raw artifact is missing, outside `OUTPUT_DIR`, or has no exact match

### GET `/subdomains`

List subdomains.

Query:

- `target_id` (optional)
- `limit` (default `100`, max `1000`)

## Health

### GET `/health`

Returns `200` when Redis, SQLite, and refresh-thread checks pass.
Returns `503` with issue list when unhealthy.

## Dashboard Runtime Semantics

Dashboard V2 (`/ui/index.html`) uses polling only (no SSE/WebSocket):

- Base poll interval from control `refresh_interval_secs` (default `5s`)
- Overlap guard: if a refresh is in-flight, the next poll waits
- Failure handling: keep last good render, show stale banner, backoff up to `30s`
- Recovery: backoff resets to selected poll interval after a successful refresh
- Real-time UI ticks:
  - relative timestamps update every second
  - running-job durations update every second
  - next-refresh countdown updates every second
