# Deployment

## Prerequisites

### Hardware
- Raspberry Pi 5 (ARM64)
- Sufficient storage for Docker images, SQLite DB, and raw output files (recommend ≥ 32 GB SD card or SSD)

### Software on the Pi

| Tool | Minimum version | Purpose |
|---|---|---|
| Docker Engine | 24+ | Container runtime |
| Docker Compose plugin | v2 | Stack management |
| Portainer CE | any recent | Stack deployment UI (optional — compose CLI works too) |
| bash | any | init script |

Install Docker and Portainer following the official ARM64 instructions. No other tools need to be installed on the host — all recon binaries (subfinder, amass, httpx, nuclei) are baked into their respective Docker images.

---

## Host Directory Setup

Run this **once** before deploying the stack, as root or with sudo:

```bash
bash scripts/init-dirs.sh
```

This creates:

```
/opt/recon-platform/
├── data/
│   ├── db/          ← SQLite database
│   ├── output/      ← raw tool output (JSONL / TXT)
│   │   ├── recon/
│   │   ├── httpx/
│   │   └── nuclei/
│   └── redis/       ← Redis AOF persistence
├── config/          ← bind-mounted into worker-recon (read-only)
├── logs/            ← all service log files
└── nuclei-templates/ ← nuclei template directory
```

All directories are created with mode `755`. No secrets are written to disk by the init script.

---

## Environment Variables

Copy `.env.example` to `.env` (for local `docker compose` use) or paste the values directly into Portainer's stack environment editor. In production, use Portainer's environment injection — never commit a populated `.env` to git.

### Complete variable reference

| Variable | Default | Required | Description |
|---|---|---|---|
| `REDIS_URL` | `redis://redis:6379` | Yes | Redis connection URI. The service name `redis` resolves inside the Docker network. |
| `SQLITE_PATH` | `/data/db/recon.db` | Yes | Path inside containers to the SQLite file. Matches the bind-mount at `/opt/recon-platform/data/db`. |
| `OUTPUT_DIR` | `/data/output` | Yes | Path inside containers for raw tool output. Matches the bind-mount at `/opt/recon-platform/data/output`. |
| `INGESTOR_PORT` | `8090` | No | HTTP port exposed by the ingestor. Change only if 8090 conflicts with another service. |
| `DEFAULT_RECON_INTERVAL_HOURS` | `24` | No | How many hours between subdomain rediscovery runs per target. |
| `DEFAULT_HTTPX_INTERVAL_HOURS` | `12` | No | How many hours between HTTP re-probes per hostname. |
| `DEFAULT_NUCLEI_INTERVAL_HOURS` | `24` | No | How many hours between nuclei rescans per endpoint URL. |
| `MAX_RECON_CONCURRENCY` | `2` | No | Subfinder `-t` thread count. Keep low to avoid rate-limits. |
| `MAX_HTTPX_CONCURRENCY` | `10` | No | httpx `-threads` count. |
| `MAX_NUCLEI_CONCURRENCY` | `1` | No | Nuclei `-c` count. High values exhaust Pi 5 CPU. |
| `NUCLEI_TEMPLATES_DIR` | `/templates` | No | Path inside the nuclei container where templates are stored. |
| `NUCLEI_TEMPLATES_UPDATE_INTERVAL_HOURS` | `24` | No | How often the nuclei worker background thread refreshes templates. |
| `NUCLEI_SEVERITY_MIN` | `medium` | No | Minimum nuclei severity to scan and alert on. One of: `info`, `low`, `medium`, `high`, `critical`. |
| `TELEGRAM_BOT_TOKEN` | _(empty)_ | No | Telegram bot token. Leave blank to disable Telegram notifications. |
| `TELEGRAM_CHAT_ID` | _(empty)_ | No | Telegram chat or channel ID. Required if token is set. |
| `DISCORD_WEBHOOK_URL` | _(empty)_ | No | Discord incoming webhook URL. Leave blank to disable. |
| `SUBFINDER_SHODAN_API_KEY` | _(empty)_ | No | Shodan API key passed to subfinder provider config. |
| `SUBFINDER_CENSYS_API_ID` | _(empty)_ | No | Censys API ID for subfinder. |
| `SUBFINDER_CENSYS_API_SECRET` | _(empty)_ | No | Censys API secret for subfinder. |
| `SUBFINDER_SECURITYTRAILS_API_KEY` | _(empty)_ | No | SecurityTrails API key for subfinder. |
| `SUBFINDER_VIRUSTOTAL_API_KEY` | _(empty)_ | No | VirusTotal API key for subfinder. |
| `AMASS_SHODAN_API_KEY` | _(empty)_ | No | Shodan API key for amass passive. |

All API keys are optional. Subfinder and amass run without any keys (using only free, unauthenticated sources), but adding keys increases coverage significantly.

---

## Deploying via Portainer

### Option A — Upload the compose file

1. Open Portainer at `http://192.168.1.191:9000`.
2. Navigate to **Stacks → Add stack**.
3. Name the stack (e.g. `recon-platform`).
4. Select **Upload** and upload `docker-compose.yml`.
5. Scroll to **Environment variables** and add all required variables from the table above.
6. Click **Deploy the stack**.

### Option B — Paste the compose file

Same steps, but select **Web editor** and paste the contents of `docker-compose.yml` directly.

### Option C — docker compose CLI (no Portainer)

```bash
# On the Pi, in the repository directory
docker compose --env-file .env up -d
```

---

## First-Run Checklist

- [ ] `scripts/init-dirs.sh` has been run and all directories under `/opt/recon-platform/` exist.
- [ ] All required environment variables are set (at minimum: `REDIS_URL`, `SQLITE_PATH`, `OUTPUT_DIR`).
- [ ] At least one notification channel is configured (`TELEGRAM_BOT_TOKEN` + `TELEGRAM_CHAT_ID`, or `DISCORD_WEBHOOK_URL`), or you accept that findings will only be logged to stdout.
- [ ] Docker can pull ARM64 images from Docker Hub and `ghcr.io`. Test with `docker pull redis:7-alpine --platform linux/arm64`.
- [ ] The stack is deployed and all 6 services are `healthy` or `running` in Portainer.
- [ ] Verify the ingestor is reachable: `curl http://192.168.1.191:8090/health` should return `{"status":"ok"}`.
- [ ] Submit a test target: `curl -X POST http://192.168.1.191:8090/targets -H 'Content-Type: application/json' -d '{"scope_root":"example.com"}'`
- [ ] Confirm a `recon_domain` task appears and is consumed by checking `worker-recon` logs.

---

## Updating and Redeploying

### Pull new images / rebuild

```bash
# Rebuild all images
docker compose build --no-cache

# Restart stack with new images
docker compose up -d --force-recreate
```

Via Portainer: navigate to the stack, click **Editor**, make changes if needed, then click **Update the stack** with **Re-pull image** checked.

### Rolling update (zero-downtime for stateless workers)

Workers are stateless — Redis and SQLite hold all state. You can restart individual workers without losing tasks:

```bash
docker compose restart worker-recon
docker compose restart worker-httpx
docker compose restart worker-nuclei
docker compose restart worker-notify
```

Restarting a worker triggers `recover_processing_queue()` on startup, so any in-flight tasks are safely re-queued.

### Updating nuclei templates manually

```bash
docker exec -it <nuclei-container-name> nuclei -update-templates -ud /templates -silent
```

Or simply restart `worker-nuclei` — the entrypoint script updates templates before the Python worker starts.

---

## Monitoring

### Check service health

```bash
# Portainer: Containers panel shows status for each service

# CLI:
docker compose ps
```

### View worker logs

```bash
# Live logs for a specific service
docker compose logs -f worker-recon
docker compose logs -f worker-httpx
docker compose logs -f worker-nuclei
docker compose logs -f worker-notify
docker compose logs -f ingestor

# Persistent log files (on Pi host):
tail -f /opt/recon-platform/logs/worker-recon.log
tail -f /opt/recon-platform/logs/worker-nuclei.log
```

### Check queue depth

Use `redis-cli` inside the Redis container:

```bash
docker exec -it <redis-container-name> redis-cli

# Queue lengths
LLEN recon_domain
LLEN probe_host
LLEN scan_http
LLEN notify_finding

# Dead-letter queue contents
LLEN dlq:recon_domain
LRANGE dlq:recon_domain 0 -1

# Inflight dedup keys
KEYS inflight:*
```

### Inspect SQLite state

```bash
docker exec -it <ingestor-container-name> sqlite3 /data/db/recon.db

# Inside sqlite3:
.tables
SELECT count(*) FROM subdomains;
SELECT count(*) FROM endpoints WHERE alive=1;
SELECT count(*) FROM findings;
SELECT * FROM failed_jobs ORDER BY failed_at DESC LIMIT 10;
SELECT type, status, count(*) FROM jobs GROUP BY type, status;
```

### Check raw output files

```bash
ls /opt/recon-platform/data/output/recon/
ls /opt/recon-platform/data/output/httpx/
ls /opt/recon-platform/data/output/nuclei/
```

Each file is named `<hostname>-<timestamp>.txt` (recon) or `<hostname>-<timestamp>.jsonl` (httpx/nuclei).
