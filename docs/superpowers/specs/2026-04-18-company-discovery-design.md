# Spec: Company Discovery

**Date:** 2026-04-18
**Status:** Approved

## Goal

Allow the user to enter a company name (e.g. "Kering") and have the platform automatically discover associated root domains (including subsidiaries), ASNs, and CIDR ranges using `amass intel`. Discovered domains land in a review queue; approved domains are automatically added to the targets table and fed into the existing recon pipeline.

---

## Architecture Overview

```
POST /companies
      │
      ▼
  company_intel queue
      │
      ▼
  worker-intel (pass 1)
  amass intel -org "<name>"
  → parse ASNs
  → store in discovered_asns
  → enqueue one company_intel_asn job per ASN
      │
      ▼
  company_intel_asn queue
      │
      ▼
  worker-intel (pass 2, per ASN)
  amass intel -asn <N> -whois -ip
  → parse domains + IPs
  → store in discovered_domains (status=pending)
  → when all ASN jobs done → company.status = done
```

---

## Data Model

Three new SQLite tables. Schema added to `common/db.py` `init_db()`.

### `companies`

| Column | Type | Notes |
|---|---|---|
| `id` | INTEGER PK AUTOINCREMENT | |
| `name` | TEXT UNIQUE NOT NULL | e.g. `"Kering"` |
| `status` | TEXT NOT NULL default `'idle'` | `idle` / `running` / `done` / `failed` |
| `created_at` | TEXT NOT NULL default `datetime('now')` | |
| `last_run_at` | TEXT | |

### `discovered_asns`

| Column | Type | Notes |
|---|---|---|
| `id` | INTEGER PK AUTOINCREMENT | |
| `company_id` | INTEGER NOT NULL FK → companies.id | |
| `asn` | TEXT NOT NULL | e.g. `"1234"` |
| `description` | TEXT | e.g. `"KERING-NET -- Kering SA"` |
| `cidr_ranges` | TEXT | JSON array of CIDR strings (stored for future use) |
| `created_at` | TEXT NOT NULL default `datetime('now')` | |

Unique key: `(company_id, asn)`.

### `discovered_domains`

| Column | Type | Notes |
|---|---|---|
| `id` | INTEGER PK AUTOINCREMENT | |
| `company_id` | INTEGER NOT NULL FK → companies.id | |
| `domain` | TEXT NOT NULL | root domain |
| `ip` | TEXT | IP from amass `-ip` flag |
| `source_asn` | TEXT | ASN that produced this domain |
| `status` | TEXT NOT NULL default `'pending'` | `pending` / `approved` / `rejected` |
| `created_at` | TEXT NOT NULL default `datetime('now')` | |

Unique key: `(company_id, domain)`. Re-running discovery on a company skips domains already present (any status).

---

## Queue Design

Two new queues, following the existing LMOVE/BRPOPLPUSH pattern.

| Queue | Producer | Consumer |
|---|---|---|
| `company_intel` | ingestor | worker-intel (pass 1) |
| `company_intel_asn` | worker-intel | worker-intel (pass 2) |

**DLQ:** `dlq:company_intel`, `dlq:company_intel_asn` — automatically surfaced in the existing Ops page DLQ panel.

### Task Payloads

Pass 1:
```json
{ "company_id": 1, "org": "Kering" }
```

Pass 2:
```json
{ "company_id": 1, "asn": "1234", "asn_index": 0, "total_asns": 3 }
```

`asn_index` / `total_asns` let the pass 2 worker detect when the final ASN job completes and flip `company.status` to `done`.

---

## Worker: `worker-intel`

Single new container consuming both queues sequentially. One BRPOPLPUSH loop per queue, same pattern as existing workers.

### Docker image

Python 3.12 slim ARM64 base image with the amass binary installed from the official GitHub releases ARM64 tarball. No ProjectDiscovery image dependency.

### Environment variables

| Var | Default | Notes |
|---|---|---|
| `REDIS_URL` | — | required |
| `SQLITE_PATH` | — | required |
| `INTEL_TIMEOUT_MINUTES` | `10` | per-amass-call timeout |

### Pass 1 logic

```
amass intel -org "<org>" -timeout <INTEL_TIMEOUT_MINUTES>
```

Parse output lines matching: `<ASN>, <description>`

For each ASN:
- Upsert row in `discovered_asns`
- Enqueue `company_intel_asn` task

If no ASNs found: set `company.status = done` (nothing to expand).

### Pass 2 logic

```
amass intel -asn <N> -whois -ip -timeout <INTEL_TIMEOUT_MINUTES>
```

Parse output lines matching: `<domain> <ip>`

For each domain:
- Insert into `discovered_domains` with `status=pending`, skip if `(company_id, domain)` already exists
- Deduplicate against existing `targets` table: if domain already exists as an enabled target, set `status=approved` directly (no need to re-add)

When `asn_index == total_asns - 1`: set `company.status = done`.

---

## API Endpoints

All added to `ingestor/app.py`.

| Method | Path | Description |
|---|---|---|
| `POST` | `/companies` | Submit company name; enqueues pass 1 job |
| `GET` | `/companies` | List all companies with status + pending count |
| `GET` | `/companies/{id}` | Detail: ASNs, domain counts by status |
| `POST` | `/companies/{id}/discover` | Re-run discovery (re-enqueues pass 1) |
| `GET` | `/companies/{id}/pending` | Paginated pending domains |
| `POST` | `/companies/{id}/approve` | Approve domains → insert to targets + enqueue recon_domain |
| `POST` | `/companies/{id}/reject` | Reject domains → mark rejected (soft, not deleted) |

### Approve / Reject body

```json
{ "domain_ids": [1, 2, 3] }
```
or
```json
{ "all": true }
```

### Approve logic

For each approved domain:
1. Check `targets` table — if already present and `enabled=1`, skip silently
2. If absent or `enabled=0`: insert/re-enable row in `targets`
3. Enqueue `recon_domain` task
4. Set `discovered_domains.status = approved`

---

## UI — Companies Page

New static page: `ingestor/static/companies.html`. Added to the nav alongside Targets, Findings, Subdomains, Ops.

### List view (`/companies`)

- "Add company" text input + submit button at top
- Table: company name, status badge, pending domain count, last run date, "Run" button (triggers `/companies/{id}/discover`)
- Status badges: `idle` (grey), `running` (blue/spinner), `done` (green), `failed` (red)

### Detail view (`/companies/{id}`)

Three sections on a single scrollable page:

**1. ASNs & CIDRs** — read-only table: ASN, description, CIDR ranges. Informational only, no actions.

**2. Pending review** — table: domain, IP, source ASN, checkbox. Bulk actions: "Approve selected", "Reject selected", "Approve all". Approved rows disappear; rejected rows dim with a "rejected" badge.

**3. Approved** — compact list of domains added to targets, each linking to the target detail page.

**Auto-refresh:** while `company.status = running`, page polls `/companies/{id}` every 5 seconds and updates counts live. Same pattern as the dashboard.

---

## Docker Compose Changes

New service in `docker-compose.yml`:

```yaml
worker-intel:
  build:
    context: .
    dockerfile: docker/Dockerfile.intel
  platform: linux/arm64
  restart: unless-stopped
  environment:
    - REDIS_URL=${REDIS_URL}
    - SQLITE_PATH=${SQLITE_PATH}
    - INTEL_TIMEOUT_MINUTES=${INTEL_TIMEOUT_MINUTES:-10}
    - LOG_DIR=/logs
    - OUTPUT_DIR=/data/output
  volumes:
    - ./ingestor:/app
    - /opt/recon-platform/data/db:/data/db
    - /opt/recon-platform/logs:/logs
  depends_on:
    - redis
  networks:
    - recon-net
```

New `docker/Dockerfile.intel`:

```dockerfile
FROM python:3.12-slim
RUN apt-get update && apt-get install -y curl tar && rm -rf /var/lib/apt/lists/*
# Install amass ARM64 binary from GitHub releases
RUN curl -L https://github.com/owasp-amass/amass/releases/latest/download/amass_Linux_arm64.zip \
    -o /tmp/amass.zip && unzip /tmp/amass.zip -d /tmp/amass && \
    mv /tmp/amass/amass_Linux_arm64/amass /usr/local/bin/amass && \
    rm -rf /tmp/amass /tmp/amass.zip
WORKDIR /app
COPY ingestor/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
CMD ["python3", "/app/workers/worker_intel.py"]
```

---

## Out of Scope

- Three-pass reverse WHOIS expansion (option 3) — too much noise without tighter org filtering
- Automatic CIDR → naabu port scan integration — CIDR data is stored for future wiring
- Multi-user RBAC on the review queue
