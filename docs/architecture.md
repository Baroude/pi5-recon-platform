# Architecture

## Runtime Topology

The platform runs as a single Docker Compose project on a Raspberry Pi 5.

- Internal network: `recon-net` (bridge)
- Publicly exposed service: `ingestor` on `8090/tcp`
- Internal-only services: `redis`, `resolver`, and all workers

Current service graph:

```text
client -> ingestor -> redis queues -> workers
                              |- worker-recon
                              |- worker-dns-brute (optional branch)
                              |- worker-httpx
                              |- worker-nuclei
                              |- worker-notify

worker-recon --\
worker-httpx ---+-> gluetun -> internet
worker-nuclei --/

worker-dns-brute -> resolver (unbound)
workers <-> sqlite (/data/db/recon.db)
workers -> /data/output/* + /logs
```

## Services

| Service | Image/Build | Role |
|---|---|---|
| `redis` | `redis:7-alpine` | Queue broker + dedup key store. Configured with AOF, `maxmemory 512mb`, `volatile-lru`. |
| `gluetun` | `qmcgaw/gluetun:v3` | VPN gateway for outbound traffic from `worker-recon`, `worker-httpx`, and `worker-nuclei`. |
| `ingestor` | `ingestor/` | FastAPI API + periodic refresh scheduler + dashboard endpoints. |
| `worker-recon` | `workers/recon/` | Passive subdomain discovery (subfinder + amass passive), enqueues `probe_host`, optionally enqueues `brute_domain`, and egresses through `gluetun`. |
| `resolver` | `klutchell/unbound:1.19.3` | Internal recursive DNS resolver used by `worker-dns-brute`. |
| `worker-dns-brute` | `workers/dns_brute/` | Active DNS brute force + permutations (shuffledns/alterx/dnsx), enqueues `probe_host`. |
| `worker-httpx` | `workers/httpx_worker/` | Probes hostnames with httpx, upserts endpoints, enqueues `scan_http`, and egresses through `gluetun`. |
| `worker-nuclei` | `workers/nuclei/` | Scans endpoints with nuclei, deduplicates findings, enqueues `notify_finding`, honors per-target template selection, and egresses through `gluetun`. |
| `worker-notify` | `workers/notify/` | Sends notifications to Telegram/Discord, records delivery rows. |

## Queue Pipeline

Primary flow:

```text
recon_domain -> probe_host -> scan_http -> notify_finding
```

Optional active-recon branch:

```text
recon_domain -> brute_domain -> probe_host
```

`brute_domain` is only enqueued when the target has `active_recon=true`.

## Redis Keys

### Work Queues

| Queue | Producer | Consumer |
|---|---|---|
| `recon_domain` | ingestor | worker-recon |
| `brute_domain` | worker-recon | worker-dns-brute |
| `probe_host` | worker-recon, worker-dns-brute | worker-httpx |
| `scan_http` | worker-httpx | worker-nuclei |
| `notify_finding` | worker-recon, worker-dns-brute, worker-httpx, worker-nuclei | worker-notify |

### Processing Queues

| Key | Owner |
|---|---|
| `recon_domain:processing` | worker-recon |
| `brute_domain:processing` | worker-dns-brute |
| `probe_host:processing` | worker-httpx |
| `scan_http:processing` | worker-nuclei |
| `notify_finding:processing` | worker-notify |

### Dead-Letter Queues

| Key | Owner |
|---|---|
| `dlq:recon_domain` | worker-recon |
| `dlq:brute_domain` | worker-dns-brute |
| `dlq:probe_host` | worker-httpx |
| `dlq:scan_http` | worker-nuclei |
| `dlq:notify_finding` | worker-notify |

### Dedup Guards

Key format:

```text
inflight:<queue>:<dedup_key>
```

Current examples:

- `inflight:recon_domain:example.com`
- `inflight:recon_domain:manual:example.com`
- `inflight:brute_domain:brute:example.com`

`probe_host` and `scan_http` rely on SQLite freshness checks rather than Redis
inflight guards in the current implementation.

## Persistence

- SQLite: `/data/db/recon.db` (bind-mounted from `/opt/recon-platform/data/db`)
- Redis AOF: `/opt/recon-platform/data/redis`
- Raw output: `/opt/recon-platform/data/output/{recon,httpx,nuclei}`
- Logs: `/opt/recon-platform/logs`
- Nuclei templates: `/opt/recon-platform/nuclei-templates`
- DNS wordlists: `/opt/recon-platform/wordlists`

## Network Boundary

Only `ingestor` publishes a host port (`8090:8090`).
All other services communicate only inside `recon-net`.
Outbound traffic for `worker-recon`, `worker-httpx`, and `worker-nuclei` is
routed via `gluetun` because those services use `network_mode: service:gluetun`.
