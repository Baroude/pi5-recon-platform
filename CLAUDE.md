# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This repository is for building a **self-hosted OSINT/recon platform** on a Raspberry Pi 5, managed via Portainer. The platform is intended for bug bounty and authorized external attack-surface workflows — not internal network defense.

The architecture spec is in `pi5-recon-architecture-functional.md`. The `ollama-stack.yml` is a separate AI stack (Ollama + Open-WebUI + SearXNG) running alongside the recon platform.

## Access

**SSH:** `ssh mathias@192.168.1.191`

**Portainer:** `http://192.168.1.191:9000` (manage stacks, containers, volumes)

### Current Portainer stack: `ollama-stack` (`ollama-stack.yml`)
| Container | Image | Port |
|---|---|---|
| ollama | `ollama/ollama:latest` | — (internal) |
| open-webui | `ghcr.io/open-webui/open-webui:v0.8.12` | `3001→8080` |
| searxng | `searxng/searxng:latest` | `8081→8080` |

Open-WebUI is configured to use SearXNG for RAG web search. Ollama keeps models loaded for 24h (`OLLAMA_KEEP_ALIVE=24h`), runs up to 2 parallel requests. Named volumes (`ollama`, `open-webui`) persist model and UI data; SearXNG config is bind-mounted from `./searxng`.

---

## Architecture

The recon platform is event-driven and queue-based:

```
Target → ingestor → Redis queue → workers (recon/httpx/nuclei) → SQLite + JSONL → notifications
```

Workers chain: `recon_domain` → `probe_host` → `scan_http` → `notify_finding`

### Key design decisions
- **Redis with AOF** (`appendonly yes`) for queue persistence across restarts
- **LMOVE/BRPOPLPUSH** pattern for safe task consumption (tasks move to a per-worker processing list atomically)
- **Dead-letter queue** at `dlq:<task_type>` in Redis + `failed_jobs` table in SQLite
- **SQLite** for structured metadata; bind-mounted JSONL for raw tool output
- **ARM64 images required** — use `linux/arm64` platform tags for all ProjectDiscovery tools

### Workers
| Worker | Tool | Consumes | Produces |
|---|---|---|---|
| recon | subfinder + amass (passive) | `recon_domain` | `probe_host` |
| httpx | httpx | `probe_host` | `scan_http` |
| nuclei | nuclei | `scan_http` | `notify_finding` |
| notify | — | `notify_finding` | Telegram/Discord |

### Nuclei templates
Templates mount at `/opt/recon-platform/nuclei-templates`. A sidecar runs `nuclei -update-templates` on container start and daily. Workers wait for templates before consuming tasks.

## Deployment

**Stack layout** (Portainer, single stack):
- `redis`, `ingestor`, `worker-recon`, `worker-httpx`, `worker-nuclei`, `worker-notify`
- Single internal Docker network; no external exposure unless a web viewer is added

**Bind mounts:**
```
/opt/recon-platform/data/db      → SQLite DB
/opt/recon-platform/data/output  → raw JSONL results
/opt/recon-platform/config       → app configs / secrets
/opt/recon-platform/logs         → service logs
```

**Key env vars:** `REDIS_URL`, `SQLITE_PATH`, `OUTPUT_DIR`, `DEFAULT_RECON_INTERVAL_HOURS`, `DEFAULT_HTTPX_INTERVAL_HOURS`, `DEFAULT_NUCLEI_INTERVAL_HOURS`, `MAX_RECON_CONCURRENCY`, `MAX_HTTPX_CONCURRENCY`, `MAX_NUCLEI_CONCURRENCY`, `NUCLEI_SEVERITY_MIN`, `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID`, `DISCORD_WEBHOOK_URL`

## Build Order

**Phase 1:** Redis → SQLite controller → recon worker → httpx worker → nuclei worker → file logs  
**Phase 2:** Notification worker → minimal API/dashboard → periodic refresh logic  
**Phase 3:** Enrichment workers, smarter change detection

## Scope / Constraints

- Passive-first: Subfinder default, Amass passive mode, active Amass disabled in v1
- Low concurrency by default to reduce rate-limit pressure
- Only scan in-scope hostnames (scope filter before enqueuing)
- No screenshots, headless browser, JS analysis, or multi-user RBAC in v1
- Deduplication required at every stage (domain+hostname, URL+port, template+endpoint, task freshness window)
- Retry policy: up to 2 retries for transient errors; permanent failures go to DLQ without retry
