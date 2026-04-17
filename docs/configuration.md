# Configuration

## Environment Variable Reference

All configuration is injected via environment variables. There are no configuration files parsed by the application code (the only file-based config is the subfinder provider YAML, which the recon worker generates from env vars at startup).

### Storage and Connectivity

| Variable | Default | Required | Effect |
|---|---|---|---|
| `REDIS_URL` | `redis://redis:6379` | Yes | Redis connection URI used by all services. The hostname `redis` resolves to the Redis container over the internal Docker network. Change only if using an external Redis instance. |
| `SQLITE_PATH` | `/data/db/recon.db` | Yes | Path to the SQLite database inside each container. All workers and the ingestor share the same file via the bind mount at `/opt/recon-platform/data/db`. |
| `OUTPUT_DIR` | `/data/output` | Yes | Base directory for raw tool output files inside worker containers. Subdirectories `recon/`, `httpx/`, and `nuclei/` are used automatically. |

### Ingestor

| Variable | Default | Required | Effect |
|---|---|---|---|
| `INGESTOR_PORT` | `8090` | No | Port uvicorn listens on inside the ingestor container. The compose file maps this to the same host port. |
| `DEFAULT_RECON_INTERVAL_HOURS` | `24` | No | Controls two things: (1) how long the ingestor waits before re-enqueuing a recon task in its refresh loop, and (2) the TTL (in seconds) set on the `inflight:recon_domain:<domain>` Redis key that prevents duplicate enqueues. |

### Worker Concurrency

| Variable | Default | Required | Effect |
|---|---|---|---|
| `MAX_RECON_CONCURRENCY` | `2` | No | Passed as `-t` to subfinder. Controls the number of parallel HTTP requests subfinder makes to passive DNS sources. Low values reduce the risk of hitting provider rate limits. |
| `MAX_HTTPX_CONCURRENCY` | `10` | No | Passed as `-threads` to httpx. Controls parallel probing per hostname. Higher values speed up discovery but increase load on targets. |
| `MAX_NUCLEI_CONCURRENCY` | `1` | No | Passed as `-c` to nuclei. Controls the number of templates running in parallel per URL. Nuclei templates are CPU-intensive; values above `2` are not recommended on Pi 5. |

### Scan Freshness Intervals

| Variable | Default | Required | Effect |
|---|---|---|---|
| `DEFAULT_RECON_INTERVAL_HOURS` | `24` | No | Minimum hours between subdomain rediscovery runs per target. See ingestor section above. |
| `DEFAULT_HTTPX_INTERVAL_HOURS` | `12` | No | Minimum hours between HTTP re-probes per hostname. Controls both the Redis inflight TTL and the worker's own TTL check before running httpx. |
| `DEFAULT_NUCLEI_INTERVAL_HOURS` | `24` | No | Minimum hours between nuclei rescans per endpoint URL. Controls both the Redis inflight TTL and the worker's own TTL check before running nuclei. |

### Recon Worker

| Variable | Default | Required | Effect |
|---|---|---|---|
| `AMASS_TIMEOUT_MINUTES` | `20` | No | Passed as `-timeout` (in minutes) to amass. The process-level kill timeout is this value × 60 + 60 seconds. Increase if amass consistently times out on large domains. |

### Nuclei

| Variable | Default | Required | Effect |
|---|---|---|---|
| `NUCLEI_TEMPLATES_DIR` | `/templates` | No | Path inside the nuclei container where templates are stored. Matches the bind mount at `/opt/recon-platform/nuclei-templates`. |
| `NUCLEI_TEMPLATES_UPDATE_INTERVAL_HOURS` | `24` | No | How often the background thread inside `worker-nuclei` runs `nuclei -update-templates`. Does not affect the template update that runs at container startup via `entrypoint.sh`. |
| `NUCLEI_SEVERITY_MIN` | `medium` | No | Minimum finding severity that triggers a notification. Also used as the floor for the `-severity` flag passed to nuclei — templates below this threshold are not run at all, saving scan time. Accepted values: `info`, `low`, `medium`, `high`, `critical`. |
| `NUCLEI_PROC_TIMEOUT` | `1800` | No | Process-level kill timeout in seconds for a single nuclei scan. Nuclei is killed and the task marked done if this is exceeded. Increase only for very large template sets. |

**Severity threshold behavior:** Both the nuclei worker and the notify worker apply `severity_meets_threshold()`. The nuclei worker uses it to filter which templates to run. The notify worker uses it again as a final check before dispatching — a safeguard in case a task was enqueued before the threshold was raised.

### Notifications

| Variable | Default | Required | Effect |
|---|---|---|---|
| `TELEGRAM_BOT_TOKEN` | _(empty)_ | No | Telegram bot token. Both this and `TELEGRAM_CHAT_ID` must be set to enable Telegram. |
| `TELEGRAM_CHAT_ID` | _(empty)_ | No | Telegram chat or channel ID where messages are sent. |
| `DISCORD_WEBHOOK_URL` | _(empty)_ | No | Discord incoming webhook URL. Set this to enable Discord notifications. |

If neither Telegram nor Discord is configured, the notify worker logs the message to stdout only. The system continues to function — notifications will appear in `docker logs worker-notify`.

### Subfinder API Keys (Optional)

These are injected into the subfinder provider YAML file at container startup by `workers/recon/entrypoint.sh`.

| Variable | Provider |
|---|---|
| `SUBFINDER_SHODAN_API_KEY` | Shodan |
| `SUBFINDER_CENSYS_API_ID` | Censys (paired with secret) |
| `SUBFINDER_CENSYS_API_SECRET` | Censys (paired with ID) |
| `SUBFINDER_SECURITYTRAILS_API_KEY` | SecurityTrails |
| `SUBFINDER_VIRUSTOTAL_API_KEY` | VirusTotal |

### Amass API Keys (Optional)

| Variable | Provider |
|---|---|
| `AMASS_SHODAN_API_KEY` | Shodan |

---

## Tuning Guide

### Scan Interval Recommendations

| Scenario | Recon interval | HTTP interval | Nuclei interval |
|---|---|---|---|
| Low noise, passive monitoring | `48`–`72` h | `24` h | `48` h |
| Default (recommended for Pi 5) | `24` h | `12` h | `24` h |
| Active bug bounty campaign | `12` h | `6` h | `12` h |
| Aggressive (not recommended on Pi 5) | `6` h | `3` h | `6` h |

Reducing intervals increases Redis queue depth, CPU load, and the rate at which you hit passive DNS provider rate limits. The default `24/12/24` balance works well for a few dozen targets on a Pi 5.

### Concurrency Recommendations

The Pi 5 has 4 ARM Cortex-A76 cores. The workers share the host. Recommended maximums:

| Worker | Recommended max | Reasoning |
|---|---|---|
| `MAX_RECON_CONCURRENCY` | `3` | Passive DNS queries are network-bound, but provider rate limits are the real ceiling. |
| `MAX_HTTPX_CONCURRENCY` | `15` | httpx is network-bound. Pi 5 handles this well. Going higher risks false negatives from target rate-limiting. |
| `MAX_NUCLEI_CONCURRENCY` | `2` | Nuclei is CPU-bound (template matching). `2` is the practical limit on Pi 5 without impacting Redis and other workers. |

Setting all three to their maximums simultaneously is not recommended. If running an active campaign, increase one at a time and observe CPU/memory.

### Redis Memory Sizing

Redis is configured with `maxmemory 256mb` and `allkeys-lru` eviction. This is appropriate for the expected workload:

- Each task payload is roughly 100–300 bytes of JSON.
- With 50 targets and 1,000 subdomains, peak queue depth is unlikely to exceed 10,000 entries (≈ 3 MB).
- Dedup inflight keys are small strings with TTLs; they self-expire.
- DLQ entries accumulate until manually cleared.

If you monitor Redis with `redis-cli INFO memory` and see `used_memory_human` approaching `200mb`, either increase `maxmemory` (edit the Redis command in `docker-compose.yml`) or investigate DLQ accumulation.

**Important:** `allkeys-lru` means Redis will evict any key — including dedup guards and DLQ entries — when memory pressure is reached. Increase `maxmemory` before this happens rather than relying on LRU eviction for correctness.

### Nuclei Template Management

Templates are stored at `/opt/recon-platform/nuclei-templates` on the Pi host (bind-mounted into `worker-nuclei` at `/templates`).

**Automatic updates:** Two mechanisms keep templates fresh:
1. `entrypoint.sh` runs `nuclei -update-templates` every time the container starts.
2. A background thread inside the worker runs the same command every `NUCLEI_TEMPLATES_UPDATE_INTERVAL_HOURS` (default 24 h).

**Manual update:**
```bash
docker exec -it <nuclei-container-name> nuclei -update-templates -ud /templates -silent
```

**Template directory size:** The full nuclei template pack is typically 50–150 MB. Ensure the host filesystem has adequate space.

**Controlling which templates run:**

The `-severity` flag passed to nuclei is derived from `NUCLEI_SEVERITY_MIN`. Only templates at or above the threshold run. This is the primary tool for controlling scan duration and noise.

To further restrict templates, you could mount a custom subset directory instead of the full pack, but this is not exposed as a configuration option in v1.
