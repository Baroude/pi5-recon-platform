# Spec: Smarter Company Discovery

**Date:** 2026-04-19
**Status:** Approved
**Supersedes:** `2026-04-18-company-discovery-design.md`

## Goal

Replace the `amass intel -org` / `amass intel -asn` pipeline (which proved nearly useless in practice — 1 ASN found for Kering over 4 minutes) with a multi-source, trust-scored discovery pipeline that finds root domains for a company and all its subsidiaries, including ones not routed through known ASNs.

The user provides a company name + optional seed domain. Discovered domains land in a review queue with a trust score to guide manual validation before being sent to the recon pipeline.

---

## Architecture Overview

```
Company name + seed domain
  │
  ├─► Pass 1: GLEIF API
  │     → legal entity names (parent + all direct children)
  │     → enqueue one crt.sh job per entity name
  │     → enqueue one crt.sh wildcard job for seed domain
  │
  ├─► Pass 2: crt.sh (per entity name or seed domain)
  │     → root domains from cert O field + SANs
  │     → insert discovered_domains with trust score
  │     → if SecurityTrails configured: extract registrant emails
  │       → enqueue pivot job per new email (hop_depth=1)
  │
  ├─► Pass 3: SecurityTrails pivot [OPTIONAL]
  │     → reverse WHOIS on registrant email
  │     → new domains → insert discovered_domains
  │     → if hop_depth < 2: enqueue more pivot jobs from new emails
  │
  └─► Pass 4: RIPEstat
        → WHOIS per discovered domain → ASN + CIDR ranges
        → upsert discovered_asns
```

**amass removed entirely.** `worker-intel` becomes a pure Python HTTP worker — no binary dependency.

**Completion detection** — Redis counter per company:
- `INCR company:{id}:pending_jobs` on every enqueue
- `DECR company:{id}:pending_jobs` on every ack
- When counter reaches 0: `company.status = done`

---

## Trust Scoring

Discovered domains carry a trust score (1–3) indicating confidence that the domain belongs to the target company. Trust guides manual review — it does not automate approval.

| Score | Label | Signals |
|---|---|---|
| 3 | HIGH | Cert O field exactly matches company or subsidiary name; OR domain is subdomain of seed domain; OR WHOIS registrant email matches seed domain's registrant |
| 2 | MEDIUM | Domain name contains the company/subsidiary string (e.g. "kering" in "keringapps.com"); OR 1-hop SecurityTrails pivot from a HIGH-trust domain |
| 1 | LOW | 2-hop pivot; OR only signal is shared ASN with seed domain |

Multiple signals per domain are stored as a JSON array (e.g. `["cert_org_match", "name_contains_target"]`). When signals conflict, the highest applies.

---

## Data Model

### Changes to `companies`

```sql
ALTER TABLE companies ADD COLUMN seed_domain TEXT;
```

### Changes to `discovered_domains`

Four new columns:

```sql
ALTER TABLE discovered_domains ADD COLUMN trust_score   INTEGER NOT NULL DEFAULT 1;
ALTER TABLE discovered_domains ADD COLUMN trust_signals TEXT;   -- JSON array of signal keys
ALTER TABLE discovered_domains ADD COLUMN source        TEXT;   -- "crt_org"|"crt_seed"|"gleif"|"pivot_1"|"pivot_2"
ALTER TABLE discovered_domains ADD COLUMN hop_depth     INTEGER NOT NULL DEFAULT 0;
```

### New table: `discovered_emails`

Tracks registrant emails found during pivoting to prevent re-queuing the same email and to enforce the 2-hop bound.

```sql
CREATE TABLE IF NOT EXISTS discovered_emails (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    company_id  INTEGER NOT NULL REFERENCES companies(id),
    email       TEXT    NOT NULL,
    hop_depth   INTEGER NOT NULL DEFAULT 1,
    created_at  TEXT    NOT NULL DEFAULT (datetime('now')),
    UNIQUE(company_id, email)
);
```

### `discovered_asns`

Unchanged in structure. Still populated — now by RIPEstat instead of amass.

---

## Queue Design

Replaces both old amass queues (`company_intel`, `company_intel_asn`).

| Queue | Pass | Producer | Consumer |
|---|---|---|---|
| `company_intel` | 1 | ingestor | worker-intel (GLEIF) |
| `company_intel_crt` | 2 | worker-intel | worker-intel (crt.sh) |
| `company_intel_pivot` | 3 | worker-intel | worker-intel (SecurityTrails) |
| `company_intel_ripestat` | 4 | worker-intel | worker-intel (RIPEstat) |

DLQ keys: `dlq:company_intel`, `dlq:company_intel_crt`, `dlq:company_intel_pivot`, `dlq:company_intel_ripestat` — all surfaced in the existing Ops DLQ panel.

### Task Payloads

**Pass 1:**
```json
{ "company_id": 1, "name": "Kering", "seed_domain": "kering.com" }
```

**Pass 2:**
```json
{ "company_id": 1, "query_type": "org", "value": "Kering SA" }
{ "company_id": 1, "query_type": "seed", "value": "kering.com" }
```

**Pass 3:**
```json
{ "company_id": 1, "email": "legal@kering.com", "hop_depth": 1 }
```

**Pass 4:**
```json
{ "company_id": 1, "domain": "keringapps.com" }
```

---

## Worker: `worker-intel`

Single container, four queue loops running as threads.

### Pass 1 — GLEIF

```
GET https://api.gleif.org/api/v1/fuzzycompletions?field=fulltext&q=<name>
  → pick best match → get LEI

GET https://api.gleif.org/api/v1/lei-records/<lei>/direct-children (paginated)
  → collect all subsidiary entity names
```

For each entity name + seed domain: enqueue `company_intel_crt` job, INCR pending counter.

If GLEIF returns no match: enqueue one `company_intel_crt` job using the raw company name as org query.

### Pass 2 — crt.sh

Two query types:

- **org query:** `https://crt.sh/?o=<entity_name>&output=json`
- **seed wildcard:** `https://crt.sh/?q=%.<seed_domain>&output=json`

Extract root domains from `common_name` and `name_value` (SAN) fields. Strip wildcard prefixes (`*.`). Deduplicate to root domain (e.g. `api.gucci.com` → `gucci.com`).

**Trust assignment per domain:**

```
cert O field exactly matches entity name       → HIGH (cert_org_match)
domain == seed_domain or subdomain of seed     → HIGH (seed_match)
domain name contains company name string       → MEDIUM (name_contains_target)
otherwise                                      → LOW
```

For each new domain:
- Insert `discovered_domains` (skip if `(company_id, domain)` already exists)
- Enqueue `company_intel_ripestat`, INCR counter
- If `SECURITYTRAILS_API_KEY` set: extract WHOIS registrant email, insert `discovered_emails` (skip if exists), enqueue `company_intel_pivot`, INCR counter

### Pass 3 — SecurityTrails pivot (optional)

Skipped entirely if `SECURITYTRAILS_API_KEY` not set in environment.

```
GET https://api.securitytrails.com/v1/domains/list
  body: { "filter": { "whois_email": "<email>" } }
```

New domains → insert `discovered_domains`:
- hop_depth=1 → trust MEDIUM (`pivot_1`)
- hop_depth=2 → trust LOW (`pivot_2`)

If `hop_depth < 2`: extract registrant emails from new domains → insert `discovered_emails` → enqueue more pivot jobs with `hop_depth + 1`.

### Pass 4 — RIPEstat

```
GET https://stat.ripe.net/data/prefix-overview/data.json?resource=<domain>
```

Parse `asns` array from response → upsert `discovered_asns` with ASN number, description, and `cidr_ranges` (JSON array of prefix strings).

### Environment variables

| Var | Default | Notes |
|---|---|---|
| `REDIS_URL` | — | required |
| `SQLITE_PATH` | — | required |
| `SECURITYTRAILS_API_KEY` | — | optional; pivot pass disabled if absent |
| `LOG_DIR` | `/logs` | |

### Dockerfile

```dockerfile
FROM --platform=linux/arm64 python:3.12-slim
WORKDIR /app
COPY workers/common /app/common
COPY workers/intel/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY workers/intel/worker.py .
ENTRYPOINT ["python3", "/app/worker.py"]
```

`requirements.txt`: `redis==5.0.4`, `requests==2.32.3`

---

## API Changes

### `POST /companies`

Body gains `seed_domain` (optional):
```json
{ "name": "Kering", "seed_domain": "kering.com" }
```

### `GET /companies/{id}`

`domain_counts` gains trust breakdown:
```json
{
  "domain_counts": {
    "pending": 42,
    "pending_by_trust": { "high": 18, "medium": 15, "low": 9 },
    "approved": 5,
    "rejected": 3
  }
}
```

### `GET /companies/{id}/pending`

Gains optional `trust` filter (1/2/3):
```
GET /companies/{id}/pending?trust=3
```

### `POST /companies/{id}/approve`

Gains `min_trust` shortcut:
```json
{ "min_trust": 3 }
```
Approves all pending domains with `trust_score >= min_trust`.

All other endpoints unchanged.

---

## UI Changes

- **Add company form** — gains optional **Seed domain** input (`kering.com`)
- **Pending review table** — new **Trust** column with colour-coded badges (HIGH=green, MEDIUM=amber, LOW=red); default sort trust-descending
- **Trust badge tooltip** — shows contributing signal keys on hover
- **Trust filter tabs** — above pending table: All / HIGH / MEDIUM / LOW
- **"Approve all HIGH"** — new quick-action button alongside existing "Approve all"

---

## Migration Notes

The existing `company_intel` and `company_intel_asn` queues are replaced. Any jobs in flight at deploy time will be nacked to DLQ — acceptable since discovery is re-triggerable by the user. The `discovered_asns` table continues to be used; existing rows are preserved.

---

## Out of Scope

- Automatic CIDR → naabu port scan integration (CIDR stored for future wiring)
- GLEIF Level 2 ultimate-parent traversal (direct children only)
- Amass v5 upgrade (deferred — amass is removed from this worker entirely)
- Multi-hop SecurityTrails pivot beyond depth 2
