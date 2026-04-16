# Architecture

## High-Level System Diagram

```
                          ┌─────────────────────────────────────────────────────────┐
                          │                    recon-net (Docker bridge)             │
                          │                                                           │
  ┌──────────┐  POST      │  ┌───────────┐       ┌───────────────────────────────┐  │
  │  Client  │──/targets──┼─►│ ingestor  │──────►│           Redis 7             │  │
  │ (curl /  │            │  │ :8090     │       │  AOF persistence, 256 MB cap  │  │
  │  browser)│◄──────────┼──│ FastAPI   │◄──────│                               │  │
  └──────────┘  JSON      │  └─────┬─────┘       └──────────────┬────────────────┘  │
                          │        │                             │                   │
                          │        │ enqueue                     │ BLMOVE            │
                          │        │ recon_domain                │                   │
                          │        ▼                             ▼                   │
                          │  ┌─────────────────────────────────────────────────┐    │
                          │  │                  Queue Pipeline                  │    │
                          │  │                                                  │    │
                          │  │  recon_domain ──► probe_host ──► scan_http      │    │
                          │  │       │                │              │          │    │
                          │  │       ▼                ▼              ▼          │    │
                          │  │  worker-recon  worker-httpx  worker-nuclei      │    │
                          │  │  subfinder     httpx         nuclei             │    │
                          │  │  amass                                          │    │
                          │  │       │                │              │          │    │
                          │  │       └────────────────┴──────────────┘          │    │
                          │  │                        │                          │    │
                          │  │                        ▼                          │    │
                          │  │                 notify_finding                    │    │
                          │  │                        │                          │    │
                          │  │                        ▼                          │    │
                          │  │                  worker-notify                    │    │
                          │  └─────────────────────────────────────────────────┘    │
                          │                                                           │
                          │  ┌──────────────────────┐  ┌──────────────────────┐     │
                          │  │  SQLite (recon.db)   │  │  JSONL output files  │     │
                          │  │  bind mount          │  │  bind mount          │     │
                          │  └──────────────────────┘  └──────────────────────┘     │
                          └─────────────────────────────────────────────────────────┘
                                                                 │
                                          ┌──────────────────────┘
                                          ▼
                               ┌─────────────────────┐
                               │  External channels   │
                               │  Telegram / Discord  │
                               └─────────────────────┘
```

## Services and Their Roles

| Service | Image / Build | Role |
|---|---|---|
| `redis` | `redis:7-alpine` | Message broker and task queue. Persists all queues to disk via AOF. Also holds deduplication keys with TTLs. |
| `ingestor` | `ingestor/` (Python 3.12, FastAPI) | REST API. Accepts target submissions, exposes query endpoints, drives periodic reschedule via background thread. |
| `worker-recon` | `workers/recon/` (Python 3.12 + subfinder + amass) | Subdomain discovery. Consumes `recon_domain`, runs subfinder and amass in passive mode, upserts results, fans out `probe_host` tasks. |
| `worker-httpx` | `workers/httpx_worker/` (Python 3.12 + httpx) | HTTP probing. Consumes `probe_host`, runs httpx against each hostname, detects new/changed endpoints, fans out `scan_http` tasks. |
| `worker-nuclei` | `workers/nuclei/` (Python 3.12 + nuclei) | Vulnerability scanning. Consumes `scan_http`, runs nuclei against each URL, deduplicates findings, fans out `notify_finding` tasks. Background thread keeps templates fresh. |
| `worker-notify` | `workers/notify/` (Python 3.12) | Notification dispatch. Consumes `notify_finding`, formats messages for new findings, subdomains, and endpoints, and delivers to Telegram and/or Discord. |

## Inter-Service Communication

All inter-service communication passes through Redis queues. No service calls another directly over HTTP.

### Queue Names and Task Payloads

| Queue | Producer | Consumer | Payload fields |
|---|---|---|---|
| `recon_domain` | ingestor (on POST + refresh loop) | worker-recon | `domain`, `retry_count` |
| `probe_host` | worker-recon | worker-httpx | `hostname`, `target_id`, `scope_root`, `retry_count` |
| `scan_http` | worker-httpx | worker-nuclei | `url`, `endpoint_id`, `retry_count` |
| `notify_finding` | worker-recon, worker-httpx, worker-nuclei | worker-notify | `notification_type`, type-specific fields, `retry_count` |

### Processing Queues (per-worker inflight lists)

Each worker moves tasks from the main queue into a processing queue atomically via `BLMOVE`. Tasks remain there until acknowledged or nack'd.

| Processing queue | Owned by |
|---|---|
| `recon_domain:processing` | worker-recon |
| `probe_host:processing` | worker-httpx |
| `scan_http:processing` | worker-nuclei |
| `notify_finding:processing` | worker-notify |

### Dead-Letter Queues

Tasks that exhaust retries are pushed to:

| DLQ key | Feeds from |
|---|---|
| `dlq:recon_domain` | worker-recon |
| `dlq:probe_host` | worker-httpx |
| `dlq:scan_http` | worker-nuclei |
| `dlq:notify_finding` | worker-notify |

### Deduplication Keys

Before enqueuing a task, the queue module checks:

```
inflight:<queue>:<dedup_key>   (Redis string, with TTL = interval in seconds)
```

Examples:

| Key | TTL | Purpose |
|---|---|---|
| `inflight:recon_domain:example.com` | `DEFAULT_RECON_INTERVAL_HOURS × 3600` | Prevent duplicate recon runs within the interval |
| `inflight:probe_host:sub.example.com` | `DEFAULT_HTTPX_INTERVAL_HOURS × 3600` | Prevent duplicate HTTP probes |
| `inflight:scan_http:https://sub.example.com` | `DEFAULT_NUCLEI_INTERVAL_HOURS × 3600` | Prevent duplicate nuclei scans |

## Data Persistence Model

| Data | Storage | Format | Notes |
|---|---|---|---|
| Task queues | Redis (AOF) | Redis lists | Survive container restarts; lost only on Redis data wipe |
| Dedup guards | Redis (AOF) | Redis strings with TTL | Expire automatically; survive restarts |
| DLQ tasks | Redis (AOF) | Redis lists | Persist until manually inspected |
| Targets, subdomains, endpoints, findings, jobs | SQLite (`recon.db`) | Relational tables | WAL mode for concurrent readers/writers |
| Raw tool output | JSONL files on disk | JSONL / plain text | Referenced by path in SQLite |
| Notification records | SQLite (`notifications` table) | Relational | Tracks per-channel delivery |

### What lives only in Redis

- Queue contents (unprocessed tasks)
- Processing-queue contents (inflight tasks)
- DLQ contents (failed tasks)
- Dedup inflight keys

### What lives only in SQLite

- All entity metadata (targets, subdomains, endpoints, findings)
- Job history and retry counts
- Failed job records (DLQ mirror for structured querying)
- Notification delivery history

## Network Topology

```
                    Host (Raspberry Pi 5)
      ┌──────────────────────────────────────────┐
      │                                            │
      │   ┌──────────────────────────────────┐   │
      │   │        recon-net (bridge)         │   │
      │   │                                    │   │
      │   │  redis          (no host port)    │   │
      │   │  ingestor       (no host port)    │   │
      │   │  worker-recon   (no host port)    │   │
      │   │  worker-httpx   (no host port)    │   │
      │   │  worker-nuclei  (no host port)    │   │
      │   │  worker-notify  (no host port)    │   │
      │   └──────────────────────────────────┘   │
      │              │ port 8090                   │
      │   ───────────┤                            │
      │              ▼                             │
      │         0.0.0.0:8090 (ingestor)           │
      └──────────────────────────────────────────┘
                     │
               LAN clients
```

Only the ingestor exposes a host port (`8090:8090`). All other services communicate exclusively over the internal `recon-net` bridge network. Redis is not reachable from outside the Docker network.

The Ollama stack (`ollama-stack.yml`) runs as a separate compose stack with its own network and ports (`3001`, `8081`) and shares no network with the recon platform.
