# Deployment

## Prerequisites

- Raspberry Pi 5 (ARM64)
- Docker Engine 24+
- Docker Compose v2 plugin
- Optional: Portainer CE

## 1. Clone and Prepare

On the Pi:

```bash
git clone <repo-url> /opt/recon-platform/repo
cd /opt/recon-platform/repo
bash scripts/init-dirs.sh
```

`init-dirs.sh` prepares:

- `/opt/recon-platform/data/db`
- `/opt/recon-platform/data/output/{recon,httpx,nuclei}`
- `/opt/recon-platform/data/redis`
- `/opt/recon-platform/config/unbound/root.hints`
- `/opt/recon-platform/logs`
- `/opt/recon-platform/nuclei-templates`
- `/opt/recon-platform/wordlists`

Notes:

- `dns-small.txt` is auto-downloaded.
- `dns-medium.txt` and `dns-large.txt` are optional/manual.
- The script repairs a bad `root.hints` directory if Docker previously created it.

## 2. Environment Variables

Use either:

- Portainer stack environment variables (recommended in production), or
- local `.env` for `docker compose` CLI.

Start from `.env.example`.

## 3. Deploy

### Portainer

Use stack name `recon-platform` and deploy from the repository compose file.

### CLI

```bash
cd /opt/recon-platform/repo
docker compose -p recon-platform --env-file .env -f docker-compose.yml up -d --build
```

Using `-p recon-platform` keeps service/container names consistent with operational docs.

## 4. First-Run Validation

```bash
docker compose -p recon-platform -f docker-compose.yml ps
curl http://<pi-ip>:8090/health
```

Expected services (8 total):

- `redis`
- `ingestor`
- `worker-recon`
- `resolver`
- `worker-dns-brute`
- `worker-httpx`
- `worker-nuclei`
- `worker-notify`

`resolver` should be `healthy`.

## 5. Smoke Test

```bash
curl -X POST http://<pi-ip>:8090/targets \
  -H "Content-Type: application/json" \
  -d '{"scope_root":"example.com","active_recon":true,"brute_wordlist":"dns-small.txt"}'
```

Then watch logs:

```bash
docker compose -p recon-platform -f docker-compose.yml logs -f worker-recon worker-dns-brute worker-httpx
```

## 6. Routine Operations

### Restart selected services

```bash
docker compose -p recon-platform -f docker-compose.yml restart worker-recon worker-dns-brute worker-httpx worker-nuclei worker-notify resolver
```

### Rebuild and redeploy

```bash
docker compose -p recon-platform -f docker-compose.yml build --no-cache
docker compose -p recon-platform -f docker-compose.yml up -d --force-recreate
```

### Check queue depth

```bash
docker exec -it recon-platform-redis-1 redis-cli
LLEN recon_domain
LLEN brute_domain
LLEN probe_host
LLEN scan_http
LLEN notify_finding
LLEN dlq:recon_domain
LLEN dlq:brute_domain
LLEN dlq:probe_host
LLEN dlq:scan_http
LLEN dlq:notify_finding
```

### Tail host logs

```bash
tail -f /opt/recon-platform/logs/worker-recon.log
tail -f /opt/recon-platform/logs/worker-dns-brute.log
tail -f /opt/recon-platform/logs/worker-nuclei.log
```

## 7. Troubleshooting Notes

- If `resolver` is unhealthy, verify:
  - `/opt/recon-platform/config/unbound/root.hints` exists and is a file
  - compose uses `klutchell/unbound:1.19.3`
  - mount path maps root hints to `/etc/unbound/named.cache`
- If active recon does not run, verify target has `active_recon=true`.
- If brute worker starts but resolves nothing, verify wordlist file exists under `/opt/recon-platform/wordlists`.
