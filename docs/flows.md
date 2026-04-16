# Flows

## Full End-to-End Flow: POST /targets to Finding Notification

```
Client                ingestor          Redis            worker-recon
  │                      │                │                    │
  │  POST /targets       │                │                    │
  │  {"scope_root":      │                │                    │
  │   "example.com"}     │                │                    │
  │─────────────────────►│                │                    │
  │                      │ validate domain│                    │
  │                      │ upsert targets │                    │
  │                      │ table          │                    │
  │                      │────────────────►                    │
  │                      │ LPUSH recon_domain                  │
  │                      │ {"domain":"example.com"}            │
  │                      │────────────────►                    │
  │  201 {"id":1,        │                │                    │
  │  "queued":true}      │                │                    │
  │◄─────────────────────│                │                    │
  │                      │                │                    │
  │                      │                │  BLMOVE recon_domain
  │                      │                │  → recon_domain:processing
  │                      │                │────────────────────►
  │                      │                │                    │ run subfinder
  │                      │                │                    │ run amass
  │                      │                │                    │ filter in-scope
  │                      │                │                    │ upsert subdomains
  │                      │                │◄────────────────────
  │                      │                │ LPUSH probe_host ×N
  │                      │                │ LPUSH notify_finding
  │                      │                │  (new_subdomain) ×N
  │                      │                │                    │
  │                      │                │          worker-httpx
  │                      │                │                    │
  │                      │                │  BLMOVE probe_host │
  │                      │                │  → probe_host:processing
  │                      │                │────────────────────────►
  │                      │                │                    │  run httpx
  │                      │                │                    │  normalize URLs
  │                      │                │                    │  upsert endpoints
  │                      │                │◄────────────────────────
  │                      │                │ LPUSH scan_http ×M
  │                      │                │ LPUSH notify_finding
  │                      │                │  (new_endpoint) ×M
  │                      │                │                    │
  │                      │                │          worker-nuclei
  │                      │                │                    │
  │                      │                │  BLMOVE scan_http  │
  │                      │                │  → scan_http:processing
  │                      │                │────────────────────────────►
  │                      │                │                    │  run nuclei
  │                      │                │                    │  dedupe findings
  │                      │                │                    │  upsert findings
  │                      │                │◄────────────────────────────
  │                      │                │ LPUSH notify_finding
  │                      │                │  (new_finding) ×K
  │                      │                │                    │
  │                      │                │          worker-notify
  │                      │                │                    │
  │                      │                │  BLMOVE notify_finding
  │                      │                │  → notify_finding:processing
  │                      │                │─────────────────────────────────►
  │                      │                │                    │  query finding
  │                      │                │                    │  check severity
  │                      │                │                    │  format message
  │                      │                │                    │  POST Telegram
  │                      │                │                    │  POST Discord
  │                      │                │                    │  record notification
```

---

## Subdomain Discovery Flow

**Trigger:** `recon_domain` task arrives in Redis.

**Worker:** `worker-recon`

**Steps:**

1. `BLMOVE recon_domain → recon_domain:processing` (atomic, blocking up to 30 s)
2. Validate that `domain` field is present in the payload.
3. Query `targets` table: confirm a row with `scope_root = domain` and `enabled = 1` exists. If not, ack and skip.
4. **TTL check:** query `jobs` for the most recent successful `recon_domain` job for this domain. If the last run finished within `DEFAULT_RECON_INTERVAL_HOURS`, ack and skip (work is fresh).
5. Insert a `jobs` row with `status = 'running'`, `started_at = now()`, `worker_name = 'worker-recon'`.
6. Run **subfinder**:
   - Command: `subfinder -d <domain> -o <output_file> -silent -all -t <MAX_RECON_CONCURRENCY> -timeout 30`
   - Output file: `/data/output/recon/<domain>-subfinder-<timestamp>.txt`
   - Parse output: one hostname per line. Return `[]` on timeout or missing file.
7. Run **amass** (passive):
   - Command: `amass enum -passive -d <domain> -o <output_file> -silent -timeout 10`
   - Output file: `/data/output/recon/<domain>-amass-<timestamp>.txt`
   - Gracefully skipped if binary is absent.
8. Merge and deduplicate results from both tools.
9. Filter: keep only hostnames that equal `domain` or are subdomains of `domain` (using `is_in_scope()`). Wildcard prefixes (`*.`) are stripped before comparison.
10. For each in-scope hostname:
    - `INSERT OR IGNORE INTO subdomains (target_id, hostname, source)` + `UPDATE last_seen`
    - Enqueue `probe_host` with dedup key = hostname, TTL = `DEFAULT_HTTPX_INTERVAL_HOURS × 3600 s`
    - Enqueue `notify_finding` with `notification_type = new_subdomain`
11. Update `jobs` row: `status = 'done'`, `finished_at = now()`, `raw_output_path = <subfinder_output_file>`.
12. `ack_task`: remove task from `recon_domain:processing`.

---

## HTTP Probing Flow

**Trigger:** `probe_host` task arrives in Redis.

**Worker:** `worker-httpx`

**Steps:**

1. `BLMOVE probe_host → probe_host:processing`
2. Validate payload: `hostname`, `target_id`, `scope_root`.
3. Query `subdomains` table: confirm `hostname` exists under `target_id`. If not found, ack and skip.
4. **TTL check:** query `jobs` for last successful `probe_host` run for this hostname. If within `DEFAULT_HTTPX_INTERVAL_HOURS`, skip.
5. Insert `jobs` row `status = 'running'`.
6. Run **httpx**:
   - Command: `httpx -u <hostname> -silent -json -o <output_file> -status-code -title -tech-detect -follow-redirects -threads <MAX_HTTPX_CONCURRENCY> -timeout 10 -retries 1`
   - httpx probes both `http://` and `https://` by default.
   - Output file: `/data/output/httpx/<hostname>-<timestamp>.jsonl`
   - Parse JSONL: each line is a JSON record with `url`, `status_code`, `title`, `tech`, `webserver`.
7. For each JSONL record:
   - Normalize URL (`_normalize_url()`): lowercase host, strip default ports, strip trailing root slash.
   - Compute `content_hash = sha1(status_code|title|webserver)[:12]`.
   - Look up `endpoints` by normalized URL:
     - **Endpoint exists, alive, hash changed:** update metadata, enqueue `scan_http` (content changed).
     - **Endpoint exists, alive, hash unchanged:** update `last_seen` only. No new scan.
     - **Endpoint exists, not alive:** mark `alive = 1`, update metadata, enqueue `scan_http`.
     - **Endpoint does not exist:** insert new row, enqueue `scan_http`, enqueue `notify_finding` with `notification_type = new_endpoint`.
8. Update `jobs` row: `status = 'done'`, `finished_at = now()`.
9. `ack_task`.

---

## Nuclei Scan Flow

**Trigger:** `scan_http` task arrives in Redis.

**Worker:** `worker-nuclei`

**Steps:**

1. `BLMOVE scan_http → scan_http:processing`
2. Validate payload: `url`, `endpoint_id`.
3. **TTL check:** query `jobs` for last successful `scan_http` for this URL. If within `DEFAULT_NUCLEI_INTERVAL_HOURS`, skip.
4. Insert `jobs` row `status = 'running'`.
5. Build severity filter: starting from `NUCLEI_SEVERITY_MIN` (default `medium`), include that severity and all higher ones. Example: `medium` → `["medium","high","critical"]`.
6. Run **nuclei**:
   - Command: `nuclei -u <url> -t <NUCLEI_TEMPLATES_DIR> -severity <comma-joined-severities> -jsonl -o <output_file> -silent -rate-limit 10 -bulk-size 25 -c <MAX_NUCLEI_CONCURRENCY> -timeout 15`
   - Output file: `/data/output/nuclei/<hostname>-<timestamp>.jsonl`
   - Parse JSONL: each line has `template-id`, `info.severity`, `info.name`, `matched-at`.
7. For each finding:
   - Compute `dedupe_key = sha1(template_id + "|" + url)`.
   - Look up `findings` by `dedupe_key`:
     - **Exists:** update `last_seen`. Do **not** re-notify.
     - **Does not exist:** insert new row, then check `severity_meets_threshold()`. If severity >= `NUCLEI_SEVERITY_MIN`, enqueue `notify_finding` with `notification_type = new_finding`.
8. Update `jobs` row: `status = 'done'`, `finished_at = now()`.
9. `ack_task`.

**Template updater (background thread):**

Runs in a separate daemon thread within `worker-nuclei`. On startup and every `NUCLEI_TEMPLATES_UPDATE_INTERVAL_HOURS` (default 24 h):

```
nuclei -update-templates -ud <NUCLEI_TEMPLATES_DIR> -silent
```

The nuclei entrypoint script (`entrypoint.sh`) also runs template update before the Python worker starts, and waits up to 120 seconds for the templates directory to be non-empty before proceeding.

---

## Notification Dispatch Flow

**Trigger:** `notify_finding` task arrives in Redis.

**Worker:** `worker-notify`

**Steps:**

1. `BLMOVE notify_finding → notify_finding:processing`
2. Read `notification_type` from payload.
3. **Case `new_finding`:**
   - Query `findings` JOIN `endpoints` for the given `finding_id`.
   - Call `severity_meets_threshold(severity)`. If below threshold, ack and skip.
   - Format Markdown message:
     ```
     *[SEVERITY] Template ID*
     Title
     URL: matched_at
     ```
   - Call `_dispatch(text)`.
4. **Case `new_subdomain`:**
   - Format message: `*New Subdomain*\n\`hostname\` (scope: \`scope_root\`)`.
   - Call `_dispatch(text)`.
5. **Case `new_endpoint`:**
   - Format message: `*New Live Endpoint*\n<url>`.
   - Call `_dispatch(text)`.
6. `_dispatch(text)` calls:
   - `_send_telegram(text)` if `TELEGRAM_BOT_TOKEN` and `TELEGRAM_CHAT_ID` are set.
   - `_send_discord(text)` if `DISCORD_WEBHOOK_URL` is set.
   - Logs to stdout/file if neither channel is configured.
7. For `new_finding`, call `_record_notification(finding_id, channel)` for each channel that was invoked.
8. `ack_task`.

---

## Error, Retry, and DLQ Flow

This flow is identical across all workers, implemented in `workers/common/queue.py`.

**On task processing failure (any exception):**

1. Worker catches the exception, logs the error.
2. Calls `nack_task(r, queue, processing_queue, task, max_retries=2)`.
3. Inside `nack_task`:
   - Read `retry_count` from task payload (default 0).
   - Increment `retry_count`.
   - If `retry_count <= max_retries` (i.e., ≤ 2):
     - Update `retry_count` in task payload.
     - `LPUSH <queue>` — task is re-enqueued at the front.
     - `LREM <processing_queue>` — removed from processing.
     - Returns `True`.
   - If `retry_count > max_retries`:
     - `LPUSH dlq:<queue>` — task moved to dead-letter queue.
     - `LREM <processing_queue>` — removed from processing.
     - Returns `False`.
4. Worker also calls `record_failed_job(task, reason)` which inserts a row into the `failed_jobs` SQLite table.

**On worker restart / container crash:**

1. Worker calls `recover_processing_queue(r, queue, processing_queue)` at startup.
2. This moves all tasks in `<queue>:processing` back to the main `<queue>` via `LMOVE` in a loop.
3. Tasks are re-processed from scratch. Since tool execution is idempotent (upsert patterns in DB), re-processing produces correct results.

**Retry count flow:**

```
Task enqueued (retry_count=0)
  → Worker processes
    → Success: ack_task, task removed
    → Failure: retry_count becomes 1, LPUSH to queue
      → Worker processes again
        → Success: ack_task
        → Failure: retry_count becomes 2, LPUSH to queue
          → Worker processes again
            → Success: ack_task
            → Failure: retry_count=3 > 2, LPUSH to dlq:<queue>, record failed_job
```

---

## Incremental Reschedule Flow (TTL-Based)

The ingestor runs a background thread (`_refresh_loop`) that fires every 3600 seconds (1 hour) while the process is running.

**Steps:**

1. Thread wakes up.
2. Query `targets` where `enabled = 1`.
3. For each enabled target, query the most recent `done` job of type `recon_domain` for that domain.
4. If no such job exists, or if `finished_at` is older than `DEFAULT_RECON_INTERVAL_HOURS`, call `enqueue()` for `recon_domain`.
5. `enqueue()` checks the `inflight:recon_domain:<domain>` Redis key:
   - If key **exists**: the interval hasn't elapsed yet (TTL still active). Task is silently dropped. `enqueue()` returns `False`.
   - If key **does not exist**: task is pushed to `recon_domain`. Redis key is set with TTL = `DEFAULT_RECON_INTERVAL_HOURS × 3600 s`. `enqueue()` returns `True`.
6. Thread sleeps for 3600 s and repeats.

This dual-layer check (SQLite timestamp + Redis TTL) means:
- Even if the ingestor restarts and the thread fires immediately, already-fresh targets are not redundantly re-enqueued.
- The Redis TTL ensures interval enforcement survives across ingestor restarts (as long as Redis retains the key).

Workers themselves also perform TTL checks (step 4 in each worker flow above) as a final guard before actually running the external tool, preventing wasted CPU if a task was somehow enqueued despite the inflight key.
