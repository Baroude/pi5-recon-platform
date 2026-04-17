# Flows

## End-to-End Pipeline

Primary pipeline:

```text
POST /targets -> recon_domain -> probe_host -> scan_http -> notify_finding
```

Optional active branch (per target):

```text
recon_domain -> brute_domain -> probe_host
```

`brute_domain` is only enqueued when `targets.active_recon = true`.

## 1. Target Creation

`POST /targets`:

- validates domain
- inserts or re-enables target
- stores `active_recon` and `brute_wordlist`
- enqueues initial `recon_domain`

## 2. Passive Recon (`worker-recon`)

- consumes `recon_domain` via `BLMOVE`
- validates enabled target
- runs subfinder + amass passive mode concurrently
- filters in-scope hostnames
- upserts `subdomains`
- enqueues `probe_host`
- enqueues `notify_finding` (`new_subdomain`)
- if `active_recon=true`, enqueues `brute_domain` with selected wordlist

## 3. Active DNS Brute (`worker-dns-brute`)

- consumes `brute_domain`
- resolves `resolver` service hostname and writes resolver file once at startup
- wildcard check with `dnsx` (3 random labels)
- brute force with `shuffledns`
- permutations with `alterx` + `dnsx`
- filters in-scope + excludes `_`-prefixed labels
- upserts `subdomains`
- enqueues `probe_host` for new hosts
- enqueues `notify_finding` (`new_subdomain`)

## 4. HTTP Probe (`worker-httpx`)

- consumes `probe_host`
- runs httpx
- normalizes URLs
- upserts `endpoints`
- enqueues `scan_http` for new/changed/revived endpoints
- enqueues `notify_finding` (`new_endpoint`) for newly discovered live endpoints

## 5. Nuclei Scan (`worker-nuclei`)

- consumes `scan_http`
- enforces scan interval with `endpoints.last_scanned_at`
- applies per-scope throttle (`NUCLEI_THROTTLE_SECS`)
- streams nuclei JSONL output
- deduplicates findings by `sha1(template_id|matched_at)`
- enqueues `notify_finding` (`new_finding`) for new rows meeting severity threshold
- updates `endpoints.last_scanned_at`

## 6. Notification (`worker-notify`)

- consumes `notify_finding`
- handles `new_finding`, `new_subdomain`, `new_endpoint`
- sends to Telegram/Discord if configured
- records `notifications` rows per active channel

## Failure, Retry, DLQ

Queue helper behavior (`workers/common/queue.py`):

- consume: `BLMOVE <queue> -> <queue>:processing`
- success: `ack_task` removes raw task from processing list
- failure: `nack_task`

`nack_task` logic with `MAX_RETRIES=2`:

1. first failure: `retry_count 0 -> 1`, `RPUSH` back to queue
2. second failure: `retry_count 1 -> 2`, `RPUSH` back to queue
3. third failure: `retry_count 2`, moved to `dlq:<queue>`

Recovery on worker startup:

- `recover_processing_queue()` moves stuck tasks from processing back to main queue
- increments retry count during recovery
- if incremented count reaches max, task is sent to DLQ

## Scheduler Loop (Ingestor)

Every hour:

- scans enabled targets
- checks if last successful recon is older than `DEFAULT_RECON_INTERVAL_HOURS`
- enqueues `recon_domain` when stale

Dedup still applies through Redis inflight keys, so duplicate scheduling attempts are suppressed.
