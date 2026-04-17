# Active Recon Implementation Plan
## pi5-recon-platform — Optional DNS Brute-Force & Permutation Stage

---

## Overview

This plan adds an **optional, per-target active recon stage** between passive subdomain discovery and HTTP probing. It is off by default and enabled per target via a flag. The approach uses a local unbound resolver container to bypass public resolver rate limits while keeping query traffic within the Docker network.

```
[CURRENT PIPELINE]
recon_domain (passive) → probe_host → scan_http → notify_finding

[NEW PIPELINE]
recon_domain (passive)
    ↓
brute_domain (active DNS brute-force + permutation)   ← NEW STAGE
    ↓
probe_host (httpx)
    ↓
scan_http (nuclei)
    ↓
notify_finding
```

The active stage is skipped entirely when `active_recon=false` on the target row.

---

## Phase 1 — Infrastructure

### 1.1 Local Unbound Resolver Service

Add a new service to `docker-compose.yml`:

```yaml
resolver:
  image: --platform=linux/arm64 mvance/unbound:1.19.3
  networks:
    - recon-net
  volumes:
    - ./config/unbound/unbound.conf:/etc/unbound/unbound.conf:ro
    - ./config/unbound/root.hints:/etc/unbound/root.hints:ro
  restart: unless-stopped
  healthcheck:
    test: ["CMD", "drill", "@127.0.0.1", "health.check."]
    interval: 10s
    timeout: 5s
    retries: 3
```

Create `config/unbound/unbound.conf`:

```
server:
  interface: 0.0.0.0
  port: 53
  access-control: 172.0.0.0/8 allow
  do-ip4: yes
  do-udp: yes
  do-tcp: yes

  # Recursive resolution — no forwarding to public resolvers
  do-not-query-localhost: no
  root-hints: "/etc/unbound/root.hints"

  # Cache tuning for Pi 5
  num-threads: 4
  msg-cache-size: 64m
  rrset-cache-size: 128m
  outgoing-range: 512
  cache-max-ttl: 300
  cache-min-ttl: 0

  # Noise reduction
  hide-identity: yes
  hide-version: yes
  qname-minimisation: yes
```

Add `init-dirs.sh` entry to create `config/unbound/` and download fresh `root.hints` from `https://www.internic.net/domain/named.cache` on first run.

**All dns-brute worker tool invocations pass `-r resolver:53`** — never a public resolver.

---

### 1.2 Wordlist Management

Create a managed wordlist volume on the host:

```
/opt/recon-platform/wordlists/
  dns-small.txt          # ~100K words  — fast sweeps, default
  dns-medium.txt         # ~500K words  — standard bug bounty
  dns-large.txt          # ~2M words    — deep targets
  resolvers.txt          # fallback public resolvers (5–10 entries)
```

Add to `init-dirs.sh`:

```bash
mkdir -p /opt/recon-platform/wordlists
# Download SecLists DNS wordlists on first run if not present
[ -f /opt/recon-platform/wordlists/dns-small.txt ] || \
  curl -sL https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt \
  -o /opt/recon-platform/wordlists/dns-small.txt
```

Add bind-mount to `worker-dns-brute` service in compose:
```yaml
- /opt/recon-platform/wordlists:/wordlists:ro
```

---

## Phase 2 — Schema Changes

### 2.1 `targets` table — add `active_recon` flag

```sql
ALTER TABLE targets ADD COLUMN active_recon BOOLEAN NOT NULL DEFAULT 0;
ALTER TABLE targets ADD COLUMN brute_wordlist TEXT NOT NULL DEFAULT 'dns-small.txt';
```

Add to `init_db()` in `workers/common/db.py` (wrapped in `try/except OperationalError`).

### 2.2 No new tables needed

Discovered subdomains from active recon insert into the existing `subdomains` table with appropriate `source` values (`dnsx`, `permutation`). The existing pipeline handles them identically from that point on.

---

## Phase 3 — API Changes

### 3.1 `POST /targets` — expose new fields

Extend the `TargetCreate` Pydantic model:

```python
class TargetCreate(BaseModel):
    scope_root: str
    active_recon: bool = False
    brute_wordlist: str = "dns-small.txt"  # small | medium | large
```

Validate `brute_wordlist` against the allowed set. Return the flag in `GET /targets` responses.

### 3.2 `PATCH /targets/{id}` — toggle active recon without re-adding

New endpoint to update `active_recon` and `brute_wordlist` on an existing target without deleting and re-adding it.

```python
@app.patch("/targets/{target_id}")
async def update_target(target_id: int, body: TargetUpdate): ...
```

---

## Phase 4 — Recon Worker Changes

### 4.1 Enqueue `brute_domain` after passive recon (if enabled)

In `workers/recon/worker.py`, at the end of `process_task()`:

```python
if target["active_recon"]:
    enqueue(r, "brute_domain", {
        "target_id": target_id,
        "domain": domain,
        "scope_root": scope_root,
        "wordlist": target["brute_wordlist"],
    }, dedup_key=f"brute:{domain}", dedup_ttl_secs=int(RECON_INTERVAL_HOURS * 3600))
else:
    # existing behaviour — enqueue probe_host for discovered subdomains directly
    ...
```

When active recon is enabled, the recon worker still enqueues passive findings into `probe_host` immediately (no reason to wait for brute-force to complete). The brute worker adds new subdomains to the same pool as they are discovered.

---

## Phase 5 — New Worker: `worker-dns-brute`

### 5.1 Directory structure

```
workers/dns_brute/
  Dockerfile
  entrypoint.sh
  requirements.txt
  worker.py
```

### 5.2 Dockerfile

```dockerfile
FROM --platform=linux/arm64 python:3.12-slim AS base

# Install dnsx and shuffledns from pinned ProjectDiscovery releases
FROM --platform=linux/arm64 ghcr.io/projectdiscovery/dnsx:v1.2.1 AS dnsx-src
FROM --platform=linux/arm64 ghcr.io/projectdiscovery/shuffledns:v1.1.0 AS shuffledns-src

FROM base
COPY --from=dnsx-src /usr/local/bin/dnsx /usr/local/bin/dnsx
COPY --from=shuffledns-src /usr/local/bin/shuffledns /usr/local/bin/shuffledns

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt --break-system-packages

COPY worker.py .
COPY ../common /app/common

RUN mkdir -p /logs /data/output
CMD ["python", "worker.py"]
```

### 5.3 Core `worker.py` logic

```
process_task(task):
    domain     = task["domain"]
    scope_root = task["scope_root"]
    target_id  = task["target_id"]
    wordlist   = task["wordlist"]   # filename only, resolved to /wordlists/<name>

    1. WILDCARD DETECTION
       Run: dnsx -d domain -r resolver:53 -resp -silent -a
       Generate 3 random non-existent labels (e.g. xk7z9.domain)
       If all 3 resolve → wildcard detected
       Log WARNING "wildcard DNS on <domain>, skipping brute-force"
       Ack task and return early

    2. DNS BRUTE-FORCE (shuffledns)
       Run: shuffledns -d domain -w /wordlists/<wordlist>
                       -r /wordlists/resolvers.txt
                       -mode resolve
                       -t 20
                       -silent
                       -o /data/output/brute_<domain>_<ts>.txt
       Timeout: 900s (15 min)

    3. PERMUTATION (dnsx on generated mutations)
       Take existing subdomains from DB for this target (SELECT hostname FROM subdomains WHERE target_id=?)
       Run: alterx (or gotator) on discovered hostnames → candidates file
       Cap candidates at MAX_PERMUTATION_CANDIDATES (default 50,000)
       Resolve candidates with dnsx -r resolver:53 -l candidates.txt -silent -a

    4. MERGE RESULTS
       Union brute results + permutation results
       Remove duplicates
       Filter: reject any hostname not passing is_in_scope(h, scope_root)
       Filter: reject hostnames matching ^_ (service labels)

    5. INSERT NEW SUBDOMAINS
       For each new hostname (INSERT OR IGNORE INTO subdomains):
         source = 'dnsx' or 'permutation'
         Enqueue probe_host if not already in scope queue (dedup_key)

    6. CLEANUP
       cleanup_old_outputs("/data/output", "brute_*.txt", max_age_days=7)
       cleanup_old_outputs("/data/output", "perm_*.txt", max_age_days=7)
```

### 5.4 New environment variables

| Variable | Default | Effect |
|---|---|---|
| `DNS_BRUTE_THREADS` | `20` | shuffledns `-t` value |
| `DNS_BRUTE_RETRIES` | `3` | shuffledns `-retries` |
| `MAX_PERMUTATION_CANDIDATES` | `50000` | Hard cap before resolving permutations |
| `DNS_TIMEOUT_SECS` | `900` | Subprocess timeout for brute-force pass |
| `PERM_TIMEOUT_SECS` | `600` | Subprocess timeout for permutation pass |

---

## Phase 6 — Docker Compose Changes

### 6.1 New `worker-dns-brute` service

```yaml
worker-dns-brute:
  build:
    context: .
    dockerfile: workers/dns_brute/Dockerfile
  platform: linux/arm64
  networks:
    - recon-net
  volumes:
    - /opt/recon-platform/data:/data
    - /opt/recon-platform/logs:/logs
    - /opt/recon-platform/wordlists:/wordlists:ro
  environment:
    - REDIS_HOST
    - REDIS_PORT
    - SQLITE_PATH
    - DNS_BRUTE_THREADS
    - DNS_BRUTE_RETRIES
    - MAX_PERMUTATION_CANDIDATES
    - DNS_TIMEOUT_SECS
    - PERM_TIMEOUT_SECS
  depends_on:
    redis:
      condition: service_healthy
    resolver:
      condition: service_healthy
  restart: unless-stopped
  mem_limit: 512m
  logging:
    driver: json-file
    options:
      max-size: "10m"
      max-file: "3"
```

### 6.2 Add `resolver` to `depends_on` for `worker-dns-brute` only

Other workers do not need the resolver — only the dns-brute worker interacts with it.

---

## Phase 7 — Queue & DLQ Updates

### 7.1 Register new queue in DLQ monitoring

In `ingestor/app.py`, add `"brute_domain"` to the list of monitored queues in both `_refresh_loop()` DLQ logging and the `/admin/dlq` endpoint.

### 7.2 Dedup key strategy for `brute_domain`

```python
enqueue(r, "brute_domain", payload,
        dedup_key=f"brute:{domain}",
        dedup_ttl_secs=int(RECON_INTERVAL_HOURS * 3600))
```

Same TTL window as passive recon — active brute-force runs at most once per `RECON_INTERVAL_HOURS`.

---

## Phase 8 — Documentation Updates

Update `docs/architecture.md`:
- Add `worker-dns-brute` and `resolver` services to the ASCII diagram
- Document the conditional pipeline branch

Update `docs/flows.md`:
- Add DNS brute-force flow section
- Add wildcard detection decision point to flow diagram

Update `docs/configuration.md`:
- Document all new env vars
- Add wordlist management section

Update `docs/deployment.md`:
- Add wordlist download step to first-run checklist
- Document `PATCH /targets/{id}` for enabling active recon post-deploy

Update `docs/api.md`:
- Document new `active_recon` and `brute_wordlist` fields on `POST /targets`
- Document `PATCH /targets/{id}` endpoint

---

## Risks & Mitigations Specific to This Feature

| Risk | Mitigation |
|---|---|
| Wildcard DNS floods `probe_host` queue | Wildcard detection in step 1 aborts before any brute-forcing |
| Permutation explosion | Hard cap at `MAX_PERMUTATION_CANDIDATES` |
| root.hints goes stale | `init-dirs.sh` refreshes from internic.net on each container start if file >30 days old |
| Unbound crashes mid-brute | `depends_on: resolver: condition: service_healthy`; tool subprocess returns non-zero on DNS failure; task nacked and retried |
| Brute-force wordlist missing | Worker checks `os.path.exists(wordlist_path)` on startup; exits with error if missing rather than silently producing empty results |
| Pi CPU saturation from concurrent brute + nuclei | `mem_limit: 512m` on dns-brute worker; consider adding `cpus: "1.5"` compose limit to leave headroom for nuclei |
| Target's authoritative NS rate-limits the Pi | Reduce `DNS_BRUTE_THREADS` to 10; add jitter between permutation passes |
| Active recon enabled on wrong target accidentally | `active_recon=false` default; requires explicit opt-in per target via `PATCH /targets/{id}` |

---

## Implementation Order

| Phase | Effort | Dependency |
|---|---|---|
| Phase 1 — Unbound + wordlists | Small | None |
| Phase 2 — Schema | Trivial | None |
| Phase 3 — API changes | Small | Phase 2 |
| Phase 4 — Recon worker enqueue | Small | Phase 2, 3 |
| Phase 5 — dns-brute worker | Medium | Phase 1, 2, 4 |
| Phase 6 — Compose | Small | Phase 5 |
| Phase 7 — Queue/DLQ updates | Trivial | Phase 5 |
| Phase 8 — Docs | Small | All phases |

Total estimated effort: **2–3 focused sessions** for a working implementation. The dns-brute worker (Phase 5) is the largest single piece; the rest is plumbing and configuration.
