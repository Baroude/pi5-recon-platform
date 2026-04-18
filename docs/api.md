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

List hostname-level subdomain inventory rows.

Query:

- `target_id` (optional)
- `status` (optional: `online|offline`)
- `technology` (optional, case-insensitive exact match against aggregated technology tags)
- `search` (optional hostname substring match, case-insensitive)
- `sort_by` (optional: `hostname|last_seen|status|scope_root`, default `last_seen`)
- `sort_dir` (optional: `asc|desc`, default `desc`)
- `offset` (optional, default `0`)
- `limit` (default `100`, max `1000`)

Response rows are still one row per discovered subdomain hostname, not one row per endpoint.
Each row rolls endpoint data up onto the hostname:

- `status` is `online` when any endpoint under the hostname has `alive = 1`, otherwise `offline`
- `endpoint_count` is the total number of endpoints under the hostname
- `alive_endpoint_count` is the number of endpoints with `alive = 1`
- `technology_tags` is the deduplicated, lower-cased set of endpoint technologies for the hostname
- `last_seen` is the most recent endpoint `last_seen` when endpoints exist, otherwise the subdomain row `last_seen`

Response shape:

```json
[
  {
    "id": 12,
    "target_id": 3,
    "hostname": "app.example.com",
    "source": "recon",
    "first_seen": "2026-04-18 08:00:00",
    "last_seen": "2026-04-18 11:00:00",
    "scope_root": "example.com",
    "status": "online",
    "endpoint_count": 2,
    "alive_endpoint_count": 1,
    "technology_tags": ["nginx", "php", "wordpress"]
  }
]
```

### GET `/subdomains/options`

Return the normalized technology vocabulary used by the subdomains inventory filter.

Response shape:

```json
{
  "technologies": ["amazon web services", "nginx", "wordpress"]
}
```

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
