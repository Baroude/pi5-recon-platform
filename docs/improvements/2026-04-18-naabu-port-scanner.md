# Spec: Naabu Port Scanner Worker

**Date:** 2026-04-18  
**Status:** Approved

## Goal

Extend the discovery pipeline to find open non-standard ports per hostname. Today httpx only probes 80 and 443, leaving services on 8080, 8443, 9090, 3000, etc. invisible. A naabu worker fills this gap by scanning ports per hostname and feeding discovered open ports back into the existing `probe_host` queue.

## Queue Integration

```
recon_domain → probe_host          (existing — 80/443 as today)
            → scan_ports           (new — only when target.port_scan = true)
                      → probe_host (non-standard open ports only)
```

`scan_ports` tasks are enqueued by `worker-recon` immediately after it enqueues `probe_host` for each discovered subdomain, but only when the target's `port_scan` flag is enabled.

## Data Model Changes

### `targets` table

Add one column:

```sql
ALTER TABLE targets ADD COLUMN port_scan BOOLEAN NOT NULL DEFAULT 0;
```

No other table changes. Discovered ports feed the existing `endpoints` table via the normal `probe_host` → httpx path.

## New Worker: `worker-naabu`

**Image:** `projectdiscovery/naabu:latest` (`platform: linux/arm64`)  
**Network:** `network_mode: service:gluetun` (same VPN routing as other scan workers)  
**Consumes:** `scan_ports`  
**Produces:** `probe_host` (for non-standard open ports only)

### Task Payload

Enqueued by `worker-recon`:
```json
{
  "hostname": "sub.example.com",
  "target_id": 1,
  "scope_root": "example.com"
}
```

### Worker Logic

1. Dequeue `scan_ports` task via `BLMOVE`.
2. Validate target is enabled and `port_scan = true`.
3. Run naabu against the hostname with the configured port list.
4. Parse open ports from naabu JSONL output.
5. Filter out ports 80 and 443 (already covered by the main pipeline).
6. For each remaining open port, enqueue `probe_host`:
   ```json
   {
     "hostname": "sub.example.com:8080",
     "target_id": 1,
     "scope_root": "example.com"
   }
   ```
7. Ack task on success; nack on failure (up to `MAX_RETRIES`).

### Naabu Command

```bash
naabu \
  -host <hostname> \
  -p <NAABU_PORTS> \
  -rate <NAABU_RATE_LIMIT> \
  -c <NAABU_CONCURRENCY> \
  -timeout <NAABU_TIMEOUT> \
  -silent \
  -json
```

## Configuration

| Env Var | Default | Description |
|---|---|---|
| `NAABU_PORTS` | `8080,8443,8888,9000,9090,9443,3000,4000,4443,5000,5001,6443,7443,10000,10443,8000,8001,8008,8181,8280,8880,8983,9200,9300,9999` | Comma-separated port list |
| `NAABU_RATE_LIMIT` | `100` | Packets per second |
| `NAABU_CONCURRENCY` | `10` | Concurrent hosts |
| `NAABU_TIMEOUT` | `5` | Probe timeout in seconds |
| `MAX_RETRIES` | `2` | Queue retry limit |

## API Changes

### `POST /targets`

Add optional field:
```json
{ "port_scan": false }
```

### `PATCH /targets/{target_id}`

Accept `port_scan` (bool).

### `GET /targets` and `GET /admin/progress`

Include `port_scan` in target rows.

### `GET /admin/meta`

No change needed — port_scan is a boolean, not a list-constrained field.

## Dedup

Uses the standard Redis inflight key pattern:
```
inflight:scan_ports:portscan:<hostname>
```

TTL matches the recon interval so a hostname is not re-scanned more frequently than configured.

## Docker Compose Addition

```yaml
worker-naabu:
  image: projectdiscovery/naabu:latest
  platform: linux/arm64
  network_mode: service:gluetun
  depends_on:
    gluetun:
      condition: service_healthy
    redis:
      condition: service_healthy
  volumes:
    - /opt/recon-platform/data/db:/data/db
    - /opt/recon-platform/logs:/logs
  environment:
    - REDIS_URL=${REDIS_URL}
    - SQLITE_PATH=${SQLITE_PATH}
    - NAABU_PORTS=${NAABU_PORTS:-8080,8443,8888,...}
    - NAABU_RATE_LIMIT=${NAABU_RATE_LIMIT:-100}
    - NAABU_CONCURRENCY=${NAABU_CONCURRENCY:-10}
    - NAABU_TIMEOUT=${NAABU_TIMEOUT:-5}
  restart: unless-stopped
```

## Failure Handling

- Naabu subprocess timeout: kill and nack task.
- No open ports found: ack task normally (valid empty result).
- Target disabled mid-scan: ack and discard.
- All failures after `MAX_RETRIES`: move to `dlq:scan_ports` + insert `failed_jobs` row.

## Out of Scope

- Top-1000 port scans (too slow on Pi 5).
- UDP port scanning.
- Service version detection (covered by httpx/nuclei downstream).
- Screenshots (explicitly excluded from v1).
