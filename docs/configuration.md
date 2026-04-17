# Configuration

All runtime configuration is environment-variable based.

## Core

| Variable | Default | Required | Notes |
|---|---|---|---|
| `REDIS_URL` | `redis://redis:6379` | Yes | Used by ingestor and all workers. |
| `SQLITE_PATH` | `/data/db/recon.db` | Yes | Shared SQLite path in containers. |
| `OUTPUT_DIR` | `/data/output` | Workers only | Base output directory for tool artifacts. |
| `INGESTOR_PORT` | `8090` | No | Exposed host port for API/dashboard. |

## Scan Intervals

| Variable | Default | Notes |
|---|---|---|
| `DEFAULT_RECON_INTERVAL_HOURS` | `24` | Minimum interval between recon runs per target. |
| `DEFAULT_HTTPX_INTERVAL_HOURS` | `12` | Minimum interval between HTTP probe runs per hostname. |
| `DEFAULT_NUCLEI_INTERVAL_HOURS` | `24` | Minimum interval between nuclei scans per endpoint URL. |

## Worker Concurrency and Timeouts

| Variable | Default | Used by |
|---|---|---|
| `MAX_RECON_CONCURRENCY` | `2` | subfinder thread count |
| `AMASS_TIMEOUT_MINUTES` | `20` | amass timeout |
| `MAX_HTTPX_CONCURRENCY` | `10` | httpx thread count |
| `MAX_NUCLEI_CONCURRENCY` | `1` | nuclei `-c` concurrency |
| `NUCLEI_PROC_TIMEOUT` | `1800` | nuclei process kill timeout (seconds) |
| `NUCLEI_THROTTLE_SECS` | `30` | Per-scope throttle between nuclei tasks |

## Active Recon (DNS Brute)

| Variable | Default | Used by |
|---|---|---|
| `DNS_BRUTE_THREADS` | `20` | shuffledns threads |
| `DNS_BRUTE_RETRIES` | `3` | shuffledns retries |
| `MAX_PERMUTATION_CANDIDATES` | `50000` | alterx candidate cap before dnsx resolve |
| `DNS_TIMEOUT_SECS` | `900` | shuffledns process timeout |
| `PERM_TIMEOUT_SECS` | `600` | alterx/dnsx permutation timeout |

Per-target controls live in SQLite (`targets.active_recon`, `targets.brute_wordlist`) and are set via API.

## Nuclei Templates

| Variable | Default | Notes |
|---|---|---|
| `NUCLEI_TEMPLATES_DIR` | `/templates` | Mounted template directory in container. |
| `NUCLEI_TEMPLATES_UPDATE_INTERVAL_HOURS` | `24` | Background template refresh interval. |
| `NUCLEI_SEVERITY_MIN` | `medium` | Minimum severity to scan and notify. |

## Notifications

| Variable | Default | Notes |
|---|---|---|
| `TELEGRAM_BOT_TOKEN` | empty | Required with `TELEGRAM_CHAT_ID` to enable Telegram. |
| `TELEGRAM_CHAT_ID` | empty | Telegram destination. |
| `DISCORD_WEBHOOK_URL` | empty | Enables Discord notifications. |

## Optional Provider Keys

| Variable |
|---|
| `SUBFINDER_SHODAN_API_KEY` |
| `SUBFINDER_CENSYS_API_ID` |
| `SUBFINDER_CENSYS_API_SECRET` |
| `SUBFINDER_SECURITYTRAILS_API_KEY` |
| `SUBFINDER_VIRUSTOTAL_API_KEY` |
| `AMASS_SHODAN_API_KEY` |

## Redis Runtime Settings (from compose)

Redis is started with:

- `appendonly yes`
- `appendfsync everysec`
- `maxmemory 512mb`
- `maxmemory-policy volatile-lru`
- `save ""` (AOF only)

Operational implication: with `volatile-lru`, Redis only evicts keys that have TTLs (for example `inflight:*` guards). Queue lists and DLQ lists are not volatile keys and should not be evicted under this policy.

## Pi 5 Tuning Baseline

Reasonable defaults for a Raspberry Pi 5:

- Recon/HTTPX/Nuclei intervals: `24/12/24`
- Concurrency: `2/10/1`
- Active brute: enabled per target only

Raise one limit at a time and watch CPU, memory, and queue depth.
