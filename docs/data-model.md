# Data Model

## SQLite Database

**File:** `/data/db/recon.db` (bind-mounted from `/opt/recon-platform/data/db/recon.db` on the host)

**Mode:** WAL (Write-Ahead Logging) — enables concurrent reads while a write is in progress. Set on every connection open.

**Foreign keys:** Enabled on every connection via `PRAGMA foreign_keys = ON`.

---

### Table: `targets`

Represents the operator-configured scope roots to monitor.

| Column | Type | Constraints | Description |
|---|---|---|---|
| `id` | INTEGER | PRIMARY KEY AUTOINCREMENT | Surrogate key |
| `scope_root` | TEXT | NOT NULL UNIQUE | The root domain, e.g. `example.com`. Normalized to lowercase. |
| `created_at` | TEXT | NOT NULL DEFAULT `datetime('now')` | ISO-8601 timestamp of first addition |
| `enabled` | INTEGER | NOT NULL DEFAULT `1` | `1` = active, `0` = disabled (soft-delete via `DELETE /targets/:id`) |
| `notes` | TEXT | | Optional operator notes, free-form |

**Key behavior:** Disabling a target (`enabled = 0`) stops the refresh loop from re-enqueuing it. Re-posting the same domain re-enables it.

---

### Table: `jobs`

Execution history for every task that a worker has started or completed.

| Column | Type | Constraints | Description |
|---|---|---|---|
| `id` | INTEGER | PRIMARY KEY AUTOINCREMENT | Surrogate key |
| `type` | TEXT | NOT NULL | One of: `recon_domain`, `probe_host`, `scan_http`, `notify_finding` |
| `target_ref` | TEXT | | Human-readable reference: domain name or hostname |
| `status` | TEXT | NOT NULL DEFAULT `'pending'` | `pending` → `running` → `done` / `failed` |
| `created_at` | TEXT | NOT NULL DEFAULT `datetime('now')` | When the task was created |
| `started_at` | TEXT | | When a worker began executing the task |
| `finished_at` | TEXT | | When the worker completed (success or failure) |
| `retry_count` | INTEGER | NOT NULL DEFAULT `0` | How many times this task has been retried |
| `worker_name` | TEXT | | Identity of the worker: `worker-recon`, `worker-httpx`, etc. |
| `raw_output_path` | TEXT | | Absolute path to the tool's raw output file, if applicable |

---

### Table: `subdomains`

Every hostname discovered by the recon worker under a target's scope.

| Column | Type | Constraints | Description |
|---|---|---|---|
| `id` | INTEGER | PRIMARY KEY AUTOINCREMENT | Surrogate key |
| `target_id` | INTEGER | NOT NULL REFERENCES `targets(id)` | Parent target |
| `hostname` | TEXT | NOT NULL | Fully-qualified hostname, e.g. `api.example.com` |
| `source` | TEXT | | Discovery source: `subfinder`, `amass`, or both (last-write wins) |
| `first_seen` | TEXT | NOT NULL DEFAULT `datetime('now')` | ISO-8601 timestamp |
| `last_seen` | TEXT | NOT NULL DEFAULT `datetime('now')` | Updated on every successful recon run that rediscovers the host |
| `status` | TEXT | NOT NULL DEFAULT `'active'` | `active` or `inactive` |
| UNIQUE | | `(target_id, hostname)` | Prevents duplicate rows for the same hostname under the same target |

**Key behavior:** The recon worker performs an `INSERT OR IGNORE` followed by an `UPDATE last_seen` (upsert pattern) so that known hostnames are refreshed without creating duplicates.

---

### Table: `endpoints`

Live HTTP/HTTPS endpoints discovered by the httpx worker.

| Column | Type | Constraints | Description |
|---|---|---|---|
| `id` | INTEGER | PRIMARY KEY AUTOINCREMENT | Surrogate key |
| `subdomain_id` | INTEGER | NOT NULL REFERENCES `subdomains(id)` | Parent subdomain |
| `url` | TEXT | NOT NULL UNIQUE | Normalized canonical URL, e.g. `https://api.example.com/admin` |
| `scheme` | TEXT | | `http` or `https` |
| `host` | TEXT | | Hostname component |
| `port` | INTEGER | | Port number (only stored when non-default) |
| `title` | TEXT | | HTML `<title>` extracted by httpx |
| `technologies` | TEXT | | JSON array of detected technologies, e.g. `["nginx","WordPress"]` |
| `status_code` | INTEGER | | Last observed HTTP status code |
| `content_hash` | TEXT | | 12-char SHA1 of `status_code\|title\|webserver` — used for change detection |
| `first_seen` | TEXT | NOT NULL DEFAULT `datetime('now')` | |
| `last_seen` | TEXT | NOT NULL DEFAULT `datetime('now')` | Updated on every re-probe |
| `alive` | INTEGER | NOT NULL DEFAULT `1` | `1` = currently responding, `0` = unreachable |

**Key behavior:** On re-probe, if `content_hash` changes, a new `scan_http` task is enqueued even if the endpoint already exists. If httpx returns no result for a hostname, existing endpoints for that hostname are not automatically marked `alive = 0`; that is left to future probe cycles.

**URL normalization rules (applied before insert/lookup):**
- Hostname lowercased
- Default ports stripped (port 80 from `http://`, port 443 from `https://`)
- Root path normalized to empty string (trailing slash removed)

---

### Table: `findings`

Vulnerability findings emitted by the nuclei worker.

| Column | Type | Constraints | Description |
|---|---|---|---|
| `id` | INTEGER | PRIMARY KEY AUTOINCREMENT | Surrogate key |
| `endpoint_id` | INTEGER | REFERENCES `endpoints(id)` | Parent endpoint (nullable if endpoint was deleted) |
| `scanner` | TEXT | NOT NULL DEFAULT `'nuclei'` | Scanning tool; always `nuclei` in v1 |
| `template_id` | TEXT | | Nuclei template ID, e.g. `CVE-2021-44228` |
| `severity` | TEXT | | `info`, `low`, `medium`, `high`, or `critical` |
| `title` | TEXT | | Human-readable vulnerability title from the template |
| `matched_at` | TEXT | | Exact URL where the finding matched |
| `first_seen` | TEXT | NOT NULL DEFAULT `datetime('now')` | |
| `last_seen` | TEXT | NOT NULL DEFAULT `datetime('now')` | Updated on re-scan if dedupe_key already exists |
| `raw_blob_path` | TEXT | | Path to the full nuclei JSONL output for this finding |
| `dedupe_key` | TEXT | UNIQUE | SHA1 of `template_id\|url` — prevents duplicate alert rows |

**Key behavior:** On every nuclei scan, the worker computes `dedupe_key = sha1(template_id + "|" + url)`. If a row with that key already exists, only `last_seen` is updated. A `notify_finding` task is only enqueued for genuinely new findings (first insert).

---

### Table: `failed_jobs`

Structured record of every task that was moved to a dead-letter queue.

| Column | Type | Constraints | Description |
|---|---|---|---|
| `id` | INTEGER | PRIMARY KEY AUTOINCREMENT | Surrogate key |
| `original_job_id` | INTEGER | | References `jobs.id` if a job row existed |
| `type` | TEXT | NOT NULL | Task type (`recon_domain`, etc.) |
| `target_ref` | TEXT | | Domain or hostname for human readability |
| `payload` | TEXT | | Full JSON task payload as stored |
| `failure_reason` | TEXT | | Exception message or error description |
| `retry_count` | INTEGER | NOT NULL DEFAULT `0` | Number of retries attempted before failure |
| `failed_at` | TEXT | NOT NULL DEFAULT `datetime('now')` | |

---

### Table: `notifications`

Delivery log for every outbound notification.

| Column | Type | Constraints | Description |
|---|---|---|---|
| `id` | INTEGER | PRIMARY KEY AUTOINCREMENT | Surrogate key |
| `finding_id` | INTEGER | REFERENCES `findings(id)` | Associated finding (nullable for subdomain/endpoint notifications) |
| `channel` | TEXT | NOT NULL | `telegram` or `discord` |
| `sent_at` | TEXT | NOT NULL DEFAULT `datetime('now')` | |
| `delivery_status` | TEXT | NOT NULL DEFAULT `'sent'` | `sent`, `failed`, or `pending` |

---

## Entity Relationships

```
targets (1)────────────────────(N) subdomains
                                         │
                                        (1)
                                         │
                                        (N)
                                     endpoints (1)────────(N) findings
                                                                    │
                                                                   (1)
                                                                    │
                                                                   (N)
                                                              notifications

targets (1)────────────────────────────────(N) jobs
findings (1)───────────────────────────────(N) notifications
```

---

## Redis Data Structures

### Task Queues

All queues are Redis **lists**. Tasks are pushed to the left (`LPUSH`) and consumed from the right via `BLMOVE`.

| Key | Type | Producer | Consumer | Contents |
|---|---|---|---|---|
| `recon_domain` | List | ingestor, ingestor refresh loop | worker-recon | JSON task payloads |
| `probe_host` | List | worker-recon | worker-httpx | JSON task payloads |
| `scan_http` | List | worker-httpx | worker-nuclei | JSON task payloads |
| `notify_finding` | List | worker-recon, worker-httpx, worker-nuclei | worker-notify | JSON task payloads |

### Processing Queues

Each worker moves tasks atomically from the main queue to its own processing list via `BLMOVE src dst LEFT RIGHT`. The task stays in the processing queue until the worker calls `ack_task` (success) or `nack_task` (failure).

| Key | Type | Owned by | Behavior on restart |
|---|---|---|---|
| `recon_domain:processing` | List | worker-recon | Recovered back to `recon_domain` at startup |
| `probe_host:processing` | List | worker-httpx | Recovered back to `probe_host` at startup |
| `scan_http:processing` | List | worker-nuclei | Recovered back to `scan_http` at startup |
| `notify_finding:processing` | List | worker-notify | Recovered back to `notify_finding` at startup |

### Dead-Letter Queues

| Key | Type | TTL | Contents |
|---|---|---|---|
| `dlq:recon_domain` | List | No expiry | Tasks that failed after `MAX_RETRIES` (2) attempts |
| `dlq:probe_host` | List | No expiry | Tasks that failed after `MAX_RETRIES` (2) attempts |
| `dlq:scan_http` | List | No expiry | Tasks that failed after `MAX_RETRIES` (2) attempts |
| `dlq:notify_finding` | List | No expiry | Tasks that failed after `MAX_RETRIES` (2) attempts |

DLQ entries are also mirrored to the `failed_jobs` SQLite table for structured inspection.

### Deduplication / Inflight Guards

| Key pattern | Type | TTL | Set by | Purpose |
|---|---|---|---|---|
| `inflight:recon_domain:<domain>` | String | `DEFAULT_RECON_INTERVAL_HOURS × 3600 s` | `enqueue()` | Prevent re-running recon before the interval expires |
| `inflight:probe_host:<hostname>` | String | `DEFAULT_HTTPX_INTERVAL_HOURS × 3600 s` | `enqueue()` | Prevent re-probing before the interval expires |
| `inflight:scan_http:<url>` | String | `DEFAULT_NUCLEI_INTERVAL_HOURS × 3600 s` | `enqueue()` | Prevent re-scanning before the interval expires |

If the key exists when `enqueue()` is called, the task is silently dropped and `enqueue()` returns `False`. When the TTL expires, the next enqueue call succeeds.

---

## Key Design Decisions

### Why `dedupe_key = SHA1(template_id | url)` for findings

Nuclei scans run repeatedly (every `DEFAULT_NUCLEI_INTERVAL_HOURS`). Without deduplication, each rescan would insert duplicate finding rows and fire duplicate alerts. The composite key `template_id|url` represents the unique (vulnerability, location) pair. SHA1 keeps the key to a fixed length regardless of URL complexity. The `|` separator is safe because neither template IDs nor URLs contain bare `|` characters.

### Why two deduplication layers (Redis inflight + SQLite UNIQUE)

- The Redis inflight key prevents a task from being enqueued at all while a fresh result is still valid. This is a coarse-grained, time-based gate.
- The SQLite UNIQUE constraints (`subdomains`, `endpoints`, `findings`) are a fine-grained, data-based gate that prevents duplicate rows even if two workers accidentally race. The two layers are complementary.

### Why the processing queue pattern instead of simple RPOP

A simple pop loses the task if the worker crashes mid-execution. `BLMOVE` atomically moves the task to a `<queue>:processing` list. On restart, `recover_processing_queue()` moves any orphaned tasks back to the main queue so they are retried. This guarantees at-least-once delivery without a separate coordinator.

### Why AOF over RDB snapshotting for Redis

Queue contents and dedup keys must survive a container restart or Pi reboot. RDB snapshots are point-in-time and can lose the most recent tasks. AOF with `appendfsync everysec` limits data loss to at most one second of writes, which is acceptable for a recon platform where tasks can be re-enqueued manually if needed.

### Why SQLite instead of Postgres

The platform runs on a single Raspberry Pi 5. SQLite with WAL mode handles the expected write concurrency (one writer per worker, multiple readers) without the operational overhead of a separate database service. WAL mode allows concurrent reads without blocking writes, making it suitable for the ingestor (reads) + workers (writes) access pattern.
