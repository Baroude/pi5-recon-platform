# Data Model

## SQLite

Database file:

- `/data/db/recon.db` inside containers
- bind-mounted from `/opt/recon-platform/data/db/recon.db`

WAL mode and foreign keys are enabled on each connection.

## Tables

### `targets`

| Column | Type | Notes |
|---|---|---|
| `id` | INTEGER PK AUTOINCREMENT | |
| `scope_root` | TEXT UNIQUE NOT NULL | normalized domain root |
| `created_at` | TEXT NOT NULL default `datetime('now')` | |
| `enabled` | INTEGER NOT NULL default `1` | soft delete flag |
| `notes` | TEXT | optional |
| `active_recon` | BOOLEAN NOT NULL default `0` | enable `brute_domain` branch |
| `brute_wordlist` | TEXT NOT NULL default `'dns-small.txt'` | selected wordlist filename |

### `jobs`

`type` values currently used:

- `recon_domain`
- `brute_domain`
- `probe_host`
- `scan_http`
- `notify_finding`

### `subdomains`

`source` may include:

- `subfinder`
- `amass`
- `shuffledns`
- `alterx`
- `httpx` (fallback insert path)

Unique key: `(target_id, hostname)`.

### `endpoints`

Stores normalized URL state, hash, and liveness.

Includes `last_scanned_at` for nuclei interval enforcement.

### `findings`

Unique `dedupe_key` = `sha1(template_id + "|" + matched_at)`.

### `failed_jobs`

Structured mirror of tasks that were pushed to DLQ.

### `notifications`

Per-channel delivery log rows.

## Redis Structures

### Main Queues

| Key | Producer(s) | Consumer |
|---|---|---|
| `recon_domain` | ingestor | worker-recon |
| `brute_domain` | worker-recon | worker-dns-brute |
| `probe_host` | worker-recon, worker-dns-brute | worker-httpx |
| `scan_http` | worker-httpx | worker-nuclei |
| `notify_finding` | worker-recon, worker-dns-brute, worker-httpx, worker-nuclei | worker-notify |

### Processing Queues

- `recon_domain:processing`
- `brute_domain:processing`
- `probe_host:processing`
- `scan_http:processing`
- `notify_finding:processing`

### Dead-Letter Queues

- `dlq:recon_domain`
- `dlq:brute_domain`
- `dlq:probe_host`
- `dlq:scan_http`
- `dlq:notify_finding`

### Dedup/In-Flight Keys

Pattern:

```text
inflight:<queue>:<dedup_key>
```

Current usages:

- `inflight:recon_domain:<domain>`
- `inflight:brute_domain:brute:<domain>`
- `inflight:probe_host:<hostname>`
- `inflight:scan_http:<url>`

## Retry Semantics

`nack_task()` behavior:

- if `retry_count < MAX_RETRIES`: increment and `RPUSH` back to queue
- else: move to `dlq:<queue>`

`recover_processing_queue()` on startup:

- moves stuck processing tasks back to queue
- increments `retry_count`
- sends to DLQ when incremented count reaches configured max
