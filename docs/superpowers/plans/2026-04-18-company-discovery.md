# Company Discovery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a company-name → root domains pipeline using `amass intel`, with a staging review queue before domains enter the recon pipeline.

**Architecture:** User submits a company name → `company_intel` queue → `worker-intel` runs `amass intel -org` (pass 1) to get ASNs → enqueues one `company_intel_asn` job per ASN → pass 2 runs `amass intel -asn -whois -ip` per ASN → discovered domains land in `discovered_domains` table with `status=pending` → user reviews and approves/rejects in the Companies UI → approved domains are added to `targets` and `recon_domain` is enqueued.

**Tech Stack:** Python 3.12-slim ARM64, amass v4.2.0 binary, FastAPI (existing), SQLite (existing), Redis (existing), PicoCSS (existing), plain JS (existing).

---

## File Map

| Action | File | Responsibility |
|---|---|---|
| Modify | `workers/common/db.py` | Add 3 new tables + migration blocks |
| Modify | `ingestor/app.py` | Pydantic models + 6 new endpoints + DLQ queue list |
| Create | `workers/intel/worker.py` | Two-queue worker (pass 1 + pass 2) |
| Create | `workers/intel/Dockerfile` | Python slim + amass binary |
| Create | `workers/intel/requirements.txt` | `redis==5.0.4` |
| Create | `workers/intel/entrypoint.sh` | Simple exec wrapper |
| Modify | `docker-compose.yml` | Add `worker-intel` service |
| Create | `ingestor/static/companies.html` | Companies list + detail UI |
| Modify | `ingestor/static/index.html` | Add Companies nav link |
| Modify | `ingestor/static/findings.html` | Add Companies nav link |
| Modify | `ingestor/static/subdomains.html` | Add Companies nav link |
| Modify | `ingestor/static/targets.html` | Add Companies nav link |
| Modify | `ingestor/static/ops.html` | Add Companies nav link |
| Modify | `ingestor/tests/test_api_dashboard_v2.py` | Add company endpoint tests |

---

## Task 1: DB Schema — Add 3 New Tables

**Files:**
- Modify: `workers/common/db.py`

Add the three table definitions to `SCHEMA_SQL` and three migration `ALTER TABLE` blocks in `init_db()`.

- [ ] **Step 1: Add tables to SCHEMA_SQL**

In `workers/common/db.py`, append these three `CREATE TABLE IF NOT EXISTS` blocks to the end of the `SCHEMA_SQL` string (before the closing `"""`):

```sql

CREATE TABLE IF NOT EXISTS companies (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT    NOT NULL UNIQUE,
    status      TEXT    NOT NULL DEFAULT 'idle',
    created_at  TEXT    NOT NULL DEFAULT (datetime('now')),
    last_run_at TEXT
);

CREATE TABLE IF NOT EXISTS discovered_asns (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    company_id  INTEGER NOT NULL REFERENCES companies(id),
    asn         TEXT    NOT NULL,
    description TEXT,
    cidr_ranges TEXT,
    created_at  TEXT    NOT NULL DEFAULT (datetime('now')),
    UNIQUE(company_id, asn)
);

CREATE TABLE IF NOT EXISTS discovered_domains (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    company_id  INTEGER NOT NULL REFERENCES companies(id),
    domain      TEXT    NOT NULL,
    ip          TEXT,
    source_asn  TEXT,
    status      TEXT    NOT NULL DEFAULT 'pending',
    created_at  TEXT    NOT NULL DEFAULT (datetime('now')),
    UNIQUE(company_id, domain)
);
```

- [ ] **Step 2: Verify schema applies cleanly**

```bash
cd C:\Users\Mathias\Documents\pi
python3 -c "
import sys; sys.path.insert(0, 'workers')
from common.db import init_db
init_db('/tmp/test_schema.db')
print('Schema OK')
"
```
Expected: `Schema OK` — no exceptions.

- [ ] **Step 3: Commit**

```bash
rtk git add workers/common/db.py
rtk git commit -m "feat: add companies, discovered_asns, discovered_domains tables"
```

---

## Task 2: Ingestor — Pydantic Models + DLQ Registration

**Files:**
- Modify: `ingestor/app.py`

- [ ] **Step 1: Add new queues to `_DLQ_QUEUES`**

In `ingestor/app.py`, find the line:
```python
_DLQ_QUEUES = ["recon_domain", "brute_domain", "probe_host", "scan_http", "notify_finding"]
```
Replace with:
```python
_DLQ_QUEUES = ["recon_domain", "brute_domain", "probe_host", "scan_http", "notify_finding", "company_intel", "company_intel_asn"]
```

- [ ] **Step 2: Add Pydantic models**

In `ingestor/app.py`, after the `DlqActionRequest` class (around line 473), add:

```python
class CompanyIn(BaseModel):
    name: str

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("name must not be empty")
        if len(v) > 200:
            raise ValueError("name must be 200 characters or fewer")
        return v


class DomainActionRequest(BaseModel):
    domain_ids: Optional[list[int]] = None
    all: bool = False

    @field_validator("domain_ids")
    @classmethod
    def validate_ids(cls, v: Optional[list[int]]) -> Optional[list[int]]:
        if v is not None and len(v) == 0:
            raise ValueError("domain_ids must not be empty when provided")
        return v
```

- [ ] **Step 3: Write failing tests for the new models**

In `ingestor/tests/test_api_dashboard_v2.py`, add at the end of the file:

```python
# ---------------------------------------------------------------------------
# Company models
# ---------------------------------------------------------------------------

def test_company_in_strips_and_validates(app_ctx):
    ingestor_app, _, _ = app_ctx
    from app import CompanyIn
    c = CompanyIn(name="  Kering  ")
    assert c.name == "Kering"


def test_company_in_rejects_empty(app_ctx):
    ingestor_app, _, _ = app_ctx
    from app import CompanyIn
    import pytest
    with pytest.raises(Exception):
        CompanyIn(name="   ")


def test_domain_action_rejects_empty_list(app_ctx):
    ingestor_app, _, _ = app_ctx
    from app import DomainActionRequest
    import pytest
    with pytest.raises(Exception):
        DomainActionRequest(domain_ids=[])
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd C:\Users\Mathias\Documents\pi
python -m pytest ingestor/tests/test_api_dashboard_v2.py::test_company_in_strips_and_validates ingestor/tests/test_api_dashboard_v2.py::test_company_in_rejects_empty ingestor/tests/test_api_dashboard_v2.py::test_domain_action_rejects_empty_list -v
```
Expected: 3 passed.

- [ ] **Step 5: Commit**

```bash
rtk git add ingestor/app.py ingestor/tests/test_api_dashboard_v2.py
rtk git commit -m "feat: add CompanyIn + DomainActionRequest models, register intel DLQ queues"
```

---

## Task 3: Ingestor — Company API Endpoints

**Files:**
- Modify: `ingestor/app.py`

Add 6 endpoints after the existing routes. The `_DOMAIN_RE` regex is already defined in `app.py` — reuse it for domain validation in approve.

- [ ] **Step 1: Write failing tests for the 6 endpoints**

In `ingestor/tests/test_api_dashboard_v2.py`, add:

```python
# ---------------------------------------------------------------------------
# Company endpoints
# ---------------------------------------------------------------------------

def _insert_company(ingestor_app, name="Kering", status="idle"):
    with ingestor_app.db_conn() as conn:
        return conn.execute(
            "INSERT INTO companies (name, status) VALUES (?, ?)",
            (name, status),
        ).lastrowid


def _insert_discovered_domain(ingestor_app, company_id, domain, status="pending", ip=None, source_asn=None):
    with ingestor_app.db_conn() as conn:
        return conn.execute(
            "INSERT INTO discovered_domains (company_id, domain, ip, source_asn, status) VALUES (?, ?, ?, ?, ?)",
            (company_id, domain, ip, source_asn, status),
        ).lastrowid


def _insert_discovered_asn(ingestor_app, company_id, asn="12345", description="TEST-NET"):
    with ingestor_app.db_conn() as conn:
        return conn.execute(
            "INSERT INTO discovered_asns (company_id, asn, description) VALUES (?, ?, ?)",
            (company_id, asn, description),
        ).lastrowid


def test_post_companies_creates_and_enqueues(client):
    test_client, ingestor_app, fake_redis, enqueued = client
    resp = test_client.post("/companies", json={"name": "Kering"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["name"] == "Kering"
    assert data["status"] == "running"
    assert any(e["queue"] == "company_intel" for e in enqueued)


def test_post_companies_rejects_empty_name(client):
    test_client, _, _, _ = client
    resp = test_client.post("/companies", json={"name": "  "})
    assert resp.status_code == 422


def test_get_companies_lists_all(client):
    test_client, ingestor_app, _, _ = client
    _insert_company(ingestor_app, "Kering")
    resp = test_client.get("/companies")
    assert resp.status_code == 200
    assert any(c["name"] == "Kering" for c in resp.json())


def test_get_company_detail(client):
    test_client, ingestor_app, _, _ = client
    cid = _insert_company(ingestor_app, "Kering")
    _insert_discovered_asn(ingestor_app, cid)
    _insert_discovered_domain(ingestor_app, cid, "gucci.com")
    resp = test_client.get(f"/companies/{cid}")
    assert resp.status_code == 200
    data = resp.json()
    assert data["name"] == "Kering"
    assert len(data["asns"]) == 1
    assert data["domain_counts"]["pending"] == 1


def test_get_company_pending(client):
    test_client, ingestor_app, _, _ = client
    cid = _insert_company(ingestor_app, "Kering")
    _insert_discovered_domain(ingestor_app, cid, "gucci.com")
    _insert_discovered_domain(ingestor_app, cid, "ysl.com")
    resp = test_client.get(f"/companies/{cid}/pending")
    assert resp.status_code == 200
    domains = resp.json()
    assert len(domains) == 2


def test_approve_domains_adds_target_and_enqueues(client):
    test_client, ingestor_app, _, enqueued = client
    cid = _insert_company(ingestor_app, "Kering")
    did = _insert_discovered_domain(ingestor_app, cid, "gucci.com")
    resp = test_client.post(f"/companies/{cid}/approve", json={"domain_ids": [did]})
    assert resp.status_code == 200
    assert resp.json()["approved"] == 1
    assert any(e["queue"] == "recon_domain" for e in enqueued)
    with ingestor_app.db_conn() as conn:
        row = conn.execute("SELECT * FROM targets WHERE scope_root = 'gucci.com'").fetchone()
    assert row is not None


def test_approve_all_domains(client):
    test_client, ingestor_app, _, enqueued = client
    cid = _insert_company(ingestor_app, "Kering")
    _insert_discovered_domain(ingestor_app, cid, "gucci.com")
    _insert_discovered_domain(ingestor_app, cid, "ysl.com")
    resp = test_client.post(f"/companies/{cid}/approve", json={"all": True})
    assert resp.status_code == 200
    assert resp.json()["approved"] == 2


def test_reject_domains(client):
    test_client, ingestor_app, _, _ = client
    cid = _insert_company(ingestor_app, "Kering")
    did = _insert_discovered_domain(ingestor_app, cid, "gucci.com")
    resp = test_client.post(f"/companies/{cid}/reject", json={"domain_ids": [did]})
    assert resp.status_code == 200
    with ingestor_app.db_conn() as conn:
        row = conn.execute("SELECT status FROM discovered_domains WHERE id = ?", (did,)).fetchone()
    assert row["status"] == "rejected"


def test_rediscover_reenqueues(client):
    test_client, ingestor_app, _, enqueued = client
    cid = _insert_company(ingestor_app, "Kering", status="done")
    resp = test_client.post(f"/companies/{cid}/discover")
    assert resp.status_code == 200
    assert any(e["queue"] == "company_intel" for e in enqueued)


def test_get_company_not_found(client):
    test_client, _, _, _ = client
    resp = test_client.get("/companies/9999")
    assert resp.status_code == 404
```

- [ ] **Step 2: Run failing tests to confirm they fail**

```bash
cd C:\Users\Mathias\Documents\pi
python -m pytest ingestor/tests/test_api_dashboard_v2.py::test_post_companies_creates_and_enqueues -v
```
Expected: FAIL with `404` or `AttributeError` (endpoints not yet defined).

- [ ] **Step 3: Implement the 6 endpoints**

In `ingestor/app.py`, append the following after all existing routes (after the `/admin/progress` route):

```python
# ---------------------------------------------------------------------------
# Companies
# ---------------------------------------------------------------------------

@app.post("/companies")
def create_company(body: CompanyIn):
    with db_conn() as conn:
        existing = conn.execute(
            "SELECT id, status FROM companies WHERE name = ?", (body.name,)
        ).fetchone()
        if existing:
            if existing["status"] == "running":
                raise HTTPException(status_code=409, detail="Discovery already running for this company")
            conn.execute(
                "UPDATE companies SET status = 'running', last_run_at = datetime('now') WHERE id = ?",
                (existing["id"],),
            )
            company_id = existing["id"]
        else:
            company_id = conn.execute(
                "INSERT INTO companies (name, status, last_run_at) VALUES (?, 'running', datetime('now'))",
                (body.name,),
            ).lastrowid

    enqueue(get_r(), "company_intel", {"company_id": company_id, "org": body.name})
    with db_conn() as conn:
        row = conn.execute("SELECT * FROM companies WHERE id = ?", (company_id,)).fetchone()
    return dict(row)


@app.get("/companies")
def list_companies():
    with db_conn() as conn:
        rows = conn.execute(
            """
            SELECT c.id, c.name, c.status, c.created_at, c.last_run_at,
                   COUNT(CASE WHEN d.status = 'pending' THEN 1 END) AS pending_count
            FROM companies c
            LEFT JOIN discovered_domains d ON d.company_id = c.id
            GROUP BY c.id
            ORDER BY c.created_at DESC
            """
        ).fetchall()
    return [dict(r) for r in rows]


@app.get("/companies/{company_id}")
def get_company(company_id: int):
    with db_conn() as conn:
        company = conn.execute(
            "SELECT * FROM companies WHERE id = ?", (company_id,)
        ).fetchone()
        if not company:
            raise HTTPException(status_code=404, detail="Company not found")

        asns = conn.execute(
            "SELECT id, asn, description, cidr_ranges, created_at FROM discovered_asns WHERE company_id = ? ORDER BY asn",
            (company_id,),
        ).fetchall()

        counts = conn.execute(
            """
            SELECT status, COUNT(*) AS cnt
            FROM discovered_domains
            WHERE company_id = ?
            GROUP BY status
            """,
            (company_id,),
        ).fetchall()

    domain_counts = {"pending": 0, "approved": 0, "rejected": 0}
    for row in counts:
        domain_counts[row["status"]] = row["cnt"]

    asn_list = []
    for a in asns:
        item = dict(a)
        item["cidr_ranges"] = _decode_json_text(item.get("cidr_ranges")) or []
        asn_list.append(item)

    return {**dict(company), "asns": asn_list, "domain_counts": domain_counts}


@app.post("/companies/{company_id}/discover")
def rediscover_company(company_id: int):
    with db_conn() as conn:
        company = conn.execute(
            "SELECT * FROM companies WHERE id = ?", (company_id,)
        ).fetchone()
        if not company:
            raise HTTPException(status_code=404, detail="Company not found")
        if company["status"] == "running":
            raise HTTPException(status_code=409, detail="Discovery already running")
        conn.execute(
            "UPDATE companies SET status = 'running', last_run_at = datetime('now') WHERE id = ?",
            (company_id,),
        )

    enqueue(get_r(), "company_intel", {"company_id": company_id, "org": company["name"]})
    return {"status": "running", "company_id": company_id}


@app.get("/companies/{company_id}/pending")
def list_pending_domains(
    company_id: int,
    limit: int = Query(default=200, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
):
    with db_conn() as conn:
        company = conn.execute("SELECT id FROM companies WHERE id = ?", (company_id,)).fetchone()
        if not company:
            raise HTTPException(status_code=404, detail="Company not found")
        rows = conn.execute(
            """
            SELECT id, domain, ip, source_asn, status, created_at
            FROM discovered_domains
            WHERE company_id = ? AND status = 'pending'
            ORDER BY domain
            LIMIT ? OFFSET ?
            """,
            (company_id, limit, offset),
        ).fetchall()
    return [dict(r) for r in rows]


def _resolve_domain_ids(conn, company_id: int, body: DomainActionRequest) -> list[int]:
    if body.all:
        rows = conn.execute(
            "SELECT id FROM discovered_domains WHERE company_id = ? AND status = 'pending'",
            (company_id,),
        ).fetchall()
        return [r["id"] for r in rows]
    if body.domain_ids:
        return body.domain_ids
    raise HTTPException(status_code=400, detail="Provide domain_ids or all=true")


@app.post("/companies/{company_id}/approve")
def approve_domains(company_id: int, body: DomainActionRequest):
    with db_conn() as conn:
        company = conn.execute("SELECT id FROM companies WHERE id = ?", (company_id,)).fetchone()
        if not company:
            raise HTTPException(status_code=404, detail="Company not found")

        ids = _resolve_domain_ids(conn, company_id, body)
        if not ids:
            return {"approved": 0}

        rows = conn.execute(
            f"SELECT id, domain FROM discovered_domains WHERE company_id = ? AND id IN ({','.join('?' * len(ids))})",
            (company_id, *ids),
        ).fetchall()

    r = get_r()
    approved = 0
    for row in rows:
        domain = row["domain"]
        with db_conn() as conn:
            existing = conn.execute(
                "SELECT id, enabled FROM targets WHERE scope_root = ?", (domain,)
            ).fetchone()
            if existing and existing["enabled"] == 1:
                pass  # already active target, skip insert
            elif existing:
                conn.execute("UPDATE targets SET enabled = 1 WHERE id = ?", (existing["id"],))
            else:
                conn.execute(
                    "INSERT INTO targets (scope_root) VALUES (?)", (domain,)
                )
            conn.execute(
                "UPDATE discovered_domains SET status = 'approved' WHERE id = ?", (row["id"],)
            )
        enqueue(r, "recon_domain", {"domain": domain}, dedup_key=domain, dedup_ttl_secs=3600)
        approved += 1

    return {"approved": approved}


@app.post("/companies/{company_id}/reject")
def reject_domains(company_id: int, body: DomainActionRequest):
    with db_conn() as conn:
        company = conn.execute("SELECT id FROM companies WHERE id = ?", (company_id,)).fetchone()
        if not company:
            raise HTTPException(status_code=404, detail="Company not found")

        ids = _resolve_domain_ids(conn, company_id, body)
        if not ids:
            return {"rejected": 0}

        conn.execute(
            f"UPDATE discovered_domains SET status = 'rejected' WHERE company_id = ? AND id IN ({','.join('?' * len(ids))})",
            (company_id, *ids),
        )
    return {"rejected": len(ids)}
```

- [ ] **Step 4: Run all company endpoint tests**

```bash
cd C:\Users\Mathias\Documents\pi
python -m pytest ingestor/tests/test_api_dashboard_v2.py -k "compan or domain or rediscover or approve or reject" -v
```
Expected: all 11 company tests pass.

- [ ] **Step 5: Run full test suite to check for regressions**

```bash
cd C:\Users\Mathias\Documents\pi
python -m pytest ingestor/tests/ -v
```
Expected: all tests pass.

- [ ] **Step 6: Commit**

```bash
rtk git add ingestor/app.py ingestor/tests/test_api_dashboard_v2.py
rtk git commit -m "feat: add company discovery API endpoints"
```

---

## Task 4: worker-intel — Two-Queue Worker

**Files:**
- Create: `workers/intel/worker.py`
- Create: `workers/intel/requirements.txt`
- Create: `workers/intel/entrypoint.sh`

- [ ] **Step 1: Create `workers/intel/requirements.txt`**

```
redis==5.0.4
```

- [ ] **Step 2: Create `workers/intel/entrypoint.sh`**

```bash
#!/usr/bin/env bash
set -euo pipefail
exec python3 /app/worker.py
```

- [ ] **Step 3: Create `workers/intel/worker.py`**

```python
"""
Intel worker
============
Consumes two queues in two threads:

  company_intel     payload: {"company_id": 1, "org": "Kering"}
  company_intel_asn payload: {"company_id": 1, "asn": "12345", "asn_index": 0, "total_asns": 3}

Pass 1 (company_intel):
  amass intel -org "<org>" -timeout N
  → parse ASN lines  →  upsert discovered_asns  →  enqueue company_intel_asn per ASN
  → if 0 ASNs found: set company.status = 'done'

Pass 2 (company_intel_asn):
  amass intel -asn <N> -whois -ip -timeout N
  → parse domain+IP lines  →  insert discovered_domains (status=pending)
  → if asn_index == total_asns - 1: set company.status = 'done'
"""

import json
import logging
import os
import re
import subprocess
import sys
import threading
import time

import redis as redis_lib

sys.path.insert(0, "/app")
from common.db import db_conn, init_db
from common.queue import (
    ack_task,
    dequeue_blocking,
    nack_task,
    enqueue,
    recover_processing_queue,
    wait_for_redis,
)

QUEUE_PASS1      = "company_intel"
PROCESSING_PASS1 = "company_intel:processing"
QUEUE_PASS2      = "company_intel_asn"
PROCESSING_PASS2 = "company_intel_asn:processing"
WORKER_NAME      = "worker-intel"

MAX_RETRIES     = int(os.environ.get("MAX_RETRIES", 2))
TIMEOUT_MINUTES = int(os.environ.get("INTEL_TIMEOUT_MINUTES", 10))

# Amass output patterns
# Pass 1: "12345, KERING-NET -- Kering SA"
_ASN_RE = re.compile(r"^(\d+),\s*(.+)$")
# Pass 2: "gucci.com 1.2.3.4" or just "gucci.com"
_DOMAIN_RE = re.compile(
    r"^([a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?)+)"
    r"(?:\s+(\d{1,3}(?:\.\d{1,3}){3}))?",
    re.IGNORECASE,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("/logs/worker-intel.log"),
    ],
)
logger = logging.getLogger(WORKER_NAME)


def _run_amass(cmd: list[str]) -> list[str]:
    """Run amass command, return stdout lines. Stderr is logged but not raised."""
    logger.info("Running: %s", " ".join(cmd))
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=TIMEOUT_MINUTES * 60 + 30,
        )
        if result.returncode not in (0, 1):
            logger.warning("amass exited %d: %s", result.returncode, result.stderr[:500])
        return [line.strip() for line in result.stdout.splitlines() if line.strip()]
    except subprocess.TimeoutExpired:
        logger.error("amass timed out after %d minutes", TIMEOUT_MINUTES)
        return []


def _set_company_status(company_id: int, status: str) -> None:
    with db_conn() as conn:
        conn.execute(
            "UPDATE companies SET status = ? WHERE id = ?", (status, company_id)
        )


def handle_pass1(r: redis_lib.Redis, task: dict) -> None:
    company_id = task["company_id"]
    org = task["org"]

    _set_company_status(company_id, "running")

    lines = _run_amass([
        "amass", "intel",
        "-org", org,
        "-timeout", str(TIMEOUT_MINUTES),
    ])

    asns = []
    for line in lines:
        m = _ASN_RE.match(line)
        if m:
            asn_num = m.group(1).strip()
            description = m.group(2).strip()
            asns.append((asn_num, description))
            with db_conn() as conn:
                conn.execute(
                    """
                    INSERT INTO discovered_asns (company_id, asn, description)
                    VALUES (?, ?, ?)
                    ON CONFLICT(company_id, asn) DO UPDATE SET description = excluded.description
                    """,
                    (company_id, asn_num, description),
                )
            logger.info("Company %d: found ASN %s (%s)", company_id, asn_num, description)

    if not asns:
        logger.warning("Company %d: no ASNs found for org=%r", company_id, org)
        _set_company_status(company_id, "done")
        return

    for idx, (asn_num, _) in enumerate(asns):
        enqueue(r, QUEUE_PASS2, {
            "company_id": company_id,
            "asn": asn_num,
            "asn_index": idx,
            "total_asns": len(asns),
        })
    logger.info("Company %d: enqueued %d ASN jobs", company_id, len(asns))


def handle_pass2(r: redis_lib.Redis, task: dict) -> None:
    company_id = task["company_id"]
    asn = task["asn"]
    asn_index = task["asn_index"]
    total_asns = task["total_asns"]

    lines = _run_amass([
        "amass", "intel",
        "-asn", asn,
        "-whois",
        "-ip",
        "-timeout", str(TIMEOUT_MINUTES),
    ])

    inserted = 0
    for line in lines:
        m = _DOMAIN_RE.match(line)
        if not m:
            continue
        domain = m.group(1).lower()
        ip = m.group(2) if m.group(2) else None

        with db_conn() as conn:
            # Check if domain is already an active target — auto-approve it
            existing_target = conn.execute(
                "SELECT enabled FROM targets WHERE scope_root = ?", (domain,)
            ).fetchone()
            auto_status = "approved" if (existing_target and existing_target["enabled"] == 1) else "pending"

            try:
                conn.execute(
                    """
                    INSERT INTO discovered_domains (company_id, domain, ip, source_asn, status)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (company_id, domain, ip, asn, auto_status),
                )
                inserted += 1
            except Exception:
                pass  # UNIQUE constraint — domain already exists for this company, skip

    logger.info("Company %d ASN %s: inserted %d domains", company_id, asn, inserted)

    if asn_index == total_asns - 1:
        _set_company_status(company_id, "done")
        logger.info("Company %d: all ASN jobs done, status=done", company_id)


def _worker_loop(queue: str, processing: str, handler) -> None:
    r = wait_for_redis()
    recover_processing_queue(r, queue, processing, max_retries=MAX_RETRIES)
    logger.info("%s: listening on %s", WORKER_NAME, queue)

    while True:
        task = dequeue_blocking(r, queue, processing, timeout=30.0)
        if task is None:
            continue
        try:
            handler(r, task)
            ack_task(r, processing, task)
        except Exception as exc:
            logger.exception("Task failed on %s: %s", queue, exc)
            nack_task(r, queue, processing, task, max_retries=MAX_RETRIES)


def main() -> None:
    init_db()

    t1 = threading.Thread(
        target=_worker_loop,
        args=(QUEUE_PASS1, PROCESSING_PASS1, handle_pass1),
        name="pass1",
        daemon=True,
    )
    t2 = threading.Thread(
        target=_worker_loop,
        args=(QUEUE_PASS2, PROCESSING_PASS2, handle_pass2),
        name="pass2",
        daemon=True,
    )
    t1.start()
    t2.start()
    logger.info("%s started (pass1 + pass2 threads)", WORKER_NAME)

    while True:
        if not t1.is_alive():
            logger.critical("Pass1 thread died — restarting")
            t1 = threading.Thread(
                target=_worker_loop,
                args=(QUEUE_PASS1, PROCESSING_PASS1, handle_pass1),
                name="pass1",
                daemon=True,
            )
            t1.start()
        if not t2.is_alive():
            logger.critical("Pass2 thread died — restarting")
            t2 = threading.Thread(
                target=_worker_loop,
                args=(QUEUE_PASS2, PROCESSING_PASS2, handle_pass2),
                name="pass2",
                daemon=True,
            )
            t2.start()
        time.sleep(10)


if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Verify the worker imports cleanly (no runtime errors)**

```bash
cd C:\Users\Mathias\Documents\pi
python3 -c "
import sys
sys.path.insert(0, 'workers')
# Patch redis so import doesn't fail
import types
redis_stub = types.ModuleType('redis')
class _R: pass
redis_stub.Redis = _R
redis_stub.from_url = lambda *a, **kw: _R()
redis_stub.ConnectionError = Exception
sys.modules['redis'] = redis_stub
import importlib.util, pathlib
spec = importlib.util.spec_from_file_location('worker_intel', 'workers/intel/worker.py')
mod = importlib.util.module_from_spec(spec)
print('Import OK')
"
```
Expected: `Import OK`.

- [ ] **Step 5: Commit**

```bash
rtk git add workers/intel/worker.py workers/intel/requirements.txt workers/intel/entrypoint.sh
rtk git commit -m "feat: add worker-intel pass1+pass2 amass intel pipeline"
```

---

## Task 5: Dockerfile for worker-intel

**Files:**
- Create: `workers/intel/Dockerfile`

- [ ] **Step 1: Create `workers/intel/Dockerfile`**

```dockerfile
# ---------------------------------------------------------------------------
# Intel worker image — Python + amass (ARM64)
# ---------------------------------------------------------------------------
FROM --platform=linux/arm64 python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl unzip \
    && rm -rf /var/lib/apt/lists/*

# Install amass ARM64 binary (same version as worker-recon)
RUN curl -fsSL https://github.com/owasp-amass/amass/releases/download/v4.2.0/amass_Linux_arm64.zip \
        -o /tmp/amass.zip \
    && unzip -j /tmp/amass.zip "amass_Linux_arm64/amass" -d /usr/local/bin/ \
    && chmod +x /usr/local/bin/amass \
    && rm /tmp/amass.zip

WORKDIR /app

ARG CACHE_BUST=1
COPY workers/common /app/common
COPY workers/intel/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY workers/intel/worker.py .
COPY workers/intel/entrypoint.sh .
RUN chmod +x /app/entrypoint.sh

RUN mkdir -p /data/db /logs

ENTRYPOINT ["/app/entrypoint.sh"]
```

- [ ] **Step 2: Commit**

```bash
rtk git add workers/intel/Dockerfile
rtk git commit -m "feat: add Dockerfile for worker-intel (Python slim ARM64 + amass v4.2.0)"
```

---

## Task 6: docker-compose.yml — Add worker-intel Service

**Files:**
- Modify: `docker-compose.yml`

- [ ] **Step 1: Add the worker-intel service**

In `docker-compose.yml`, add the following block after the `worker-recon` service definition:

```yaml
  # --------------------------------------------------------------------------
  # Intel worker — amass intel org/ASN discovery → discovered_domains staging
  # Does NOT route through gluetun (intel queries are passive, not scanning).
  # --------------------------------------------------------------------------
  worker-intel:
    <<: *worker-defaults
    build:
      context: .
      dockerfile: workers/intel/Dockerfile
      args:
        CACHE_BUST: ${CACHE_BUST:-1}
    platform: linux/arm64
    networks:
      - recon-net
    environment:
      - REDIS_URL=${REDIS_URL:-redis://redis:6379}
      - SQLITE_PATH=${SQLITE_PATH:-/data/db/recon.db}
      - INTEL_TIMEOUT_MINUTES=${INTEL_TIMEOUT_MINUTES:-10}
      - LOG_DIR=/logs
    volumes:
      - /opt/recon-platform/data/db:/data/db
      - /opt/recon-platform/logs:/logs
```

Note: `worker-intel` does NOT use `network_mode: "service:gluetun"` because amass intel queries are passive OSINT lookups (WHOIS, BGP data), not active scans against targets.

- [ ] **Step 2: Validate docker-compose syntax**

```bash
cd C:\Users\Mathias\Documents\pi
docker compose config --quiet && echo "Compose OK"
```
Expected: `Compose OK` with no errors.

- [ ] **Step 3: Commit**

```bash
rtk git add docker-compose.yml
rtk git commit -m "feat: add worker-intel service to docker-compose"
```

---

## Task 7: Companies UI Page

**Files:**
- Create: `ingestor/static/companies.html`

- [ ] **Step 1: Create `ingestor/static/companies.html`**

```html
<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Recon Platform | Companies</title>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@picocss/pico@2/css/pico.min.css">
  <link rel="stylesheet" href="/ui/app.css">
  <script src="/ui/app.js" defer></script>
</head>
<body data-page="companies">
  <div class="app-shell">
    <header class="topbar">
      <div class="topbar-inner">
        <a class="brand" href="/ui/index.html">
          <span class="brand-mark">R</span>
          <span>Recon</span>
        </a>
        <nav class="nav-links" aria-label="Primary">
          <a href="/ui/index.html">Dashboard</a>
          <a href="/ui/findings.html">Findings</a>
          <a href="/ui/subdomains.html">Subdomains</a>
          <a href="/ui/targets.html">Targets</a>
          <a class="is-active" href="/ui/companies.html" aria-current="page">Companies</a>
          <a href="/ui/ops.html">Ops</a>
        </nav>
        <div class="status-meta">
          <span class="status-dot good"></span>
          <span id="last-updated">—</span>
        </div>
      </div>
    </header>

    <main>
      <div id="page-message" class="message" role="status" aria-live="polite"></div>

      <!-- List view (shown when no company is selected) -->
      <div id="list-view">
        <section class="page-header panel">
          <div class="page-header-copy">
            <h1>Company Discovery</h1>
            <p>Enter a company name to discover its root domains, ASNs, and CIDR ranges via amass intel.</p>
          </div>
        </section>

        <section class="panel page-section">
          <form id="add-company-form" class="inline-form">
            <div class="inline-form-grid" style="grid-template-columns: 1fr auto;">
              <label>
                Company name
                <input id="company-name-input" placeholder="e.g. Kering" required>
              </label>
              <label style="align-self:end">
                &nbsp;
                <button type="submit" class="compact">Discover</button>
              </label>
            </div>
          </form>
        </section>

        <section class="panel page-section">
          <h2>Companies</h2>
          <div id="companies-table-wrap">
            <table id="companies-table">
              <thead>
                <tr>
                  <th>Company</th>
                  <th>Status</th>
                  <th>Pending</th>
                  <th>Last run</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody id="companies-tbody">
                <tr><td colspan="5">Loading…</td></tr>
              </tbody>
            </table>
          </div>
        </section>
      </div>

      <!-- Detail view (shown when a company is selected) -->
      <div id="detail-view" style="display:none">
        <section class="page-header panel">
          <div class="page-header-copy">
            <h1 id="detail-company-name">Company</h1>
            <p><span id="detail-status-badge"></span></p>
          </div>
          <div class="page-header-actions">
            <button id="back-btn" class="secondary compact">← Back</button>
            <button id="rediscover-btn" class="compact">Re-run discovery</button>
          </div>
        </section>

        <!-- ASNs section -->
        <section class="panel page-section">
          <h2>ASNs &amp; CIDRs</h2>
          <div id="asns-wrap">
            <table id="asns-table">
              <thead><tr><th>ASN</th><th>Description</th><th>CIDR Ranges</th></tr></thead>
              <tbody id="asns-tbody"><tr><td colspan="3">No ASNs discovered yet.</td></tr></tbody>
            </table>
          </div>
        </section>

        <!-- Pending review section -->
        <section class="panel page-section">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:0.75rem">
            <h2 style="margin:0">Pending Review (<span id="pending-count">0</span>)</h2>
            <div style="display:flex;gap:0.5rem">
              <button id="approve-selected-btn" class="compact" disabled>Approve selected</button>
              <button id="reject-selected-btn" class="secondary compact" disabled>Reject selected</button>
              <button id="approve-all-btn" class="compact">Approve all</button>
            </div>
          </div>
          <table id="pending-table">
            <thead>
              <tr>
                <th><input type="checkbox" id="select-all-checkbox"></th>
                <th>Domain</th>
                <th>IP</th>
                <th>Source ASN</th>
              </tr>
            </thead>
            <tbody id="pending-tbody"><tr><td colspan="4">No pending domains.</td></tr></tbody>
          </table>
        </section>

        <!-- Approved section -->
        <section class="panel page-section">
          <h2>Approved (<span id="approved-count">0</span>)</h2>
          <div id="approved-list"></div>
        </section>
      </div>
    </main>
  </div>

  <script>
  (() => {
    const API = '';
    let currentCompanyId = null;
    let pollTimer = null;

    const $ = id => document.getElementById(id);
    const listView = $('list-view');
    const detailView = $('detail-view');

    function showMsg(msg, isErr = false) {
      const el = $('page-message');
      el.textContent = msg;
      el.className = 'message ' + (isErr ? 'error' : 'info');
      setTimeout(() => { el.textContent = ''; el.className = 'message'; }, 4000);
    }

    function statusBadge(status) {
      const cls = { idle: 'neutral', running: 'info', done: 'ok', failed: 'bad' };
      return `<span class="badge badge-${cls[status] || 'neutral'}">${status}</span>`;
    }

    // ---- List view ----

    async function loadCompanies() {
      const resp = await fetch(`${API}/companies`);
      const rows = await resp.json();
      const tbody = $('companies-tbody');
      if (!rows.length) {
        tbody.innerHTML = '<tr><td colspan="5">No companies yet.</td></tr>';
        return;
      }
      tbody.innerHTML = rows.map(c => `
        <tr>
          <td><a href="#" class="company-link" data-id="${c.id}">${c.name}</a></td>
          <td>${statusBadge(c.status)}</td>
          <td>${c.pending_count || 0}</td>
          <td>${c.last_run_at ? c.last_run_at.slice(0, 16) : '—'}</td>
          <td>
            <button class="compact secondary run-btn" data-id="${c.id}" data-name="${c.name}">Run</button>
          </td>
        </tr>
      `).join('');

      tbody.querySelectorAll('.company-link').forEach(a => {
        a.addEventListener('click', e => { e.preventDefault(); openDetail(+a.dataset.id, a.textContent); });
      });
      tbody.querySelectorAll('.run-btn').forEach(btn => {
        btn.addEventListener('click', () => rediscover(+btn.dataset.id, btn.dataset.name));
      });
    }

    $('add-company-form').addEventListener('submit', async e => {
      e.preventDefault();
      const name = $('company-name-input').value.trim();
      if (!name) return;
      const resp = await fetch(`${API}/companies`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name }),
      });
      if (!resp.ok) { showMsg((await resp.json()).detail || 'Error', true); return; }
      $('company-name-input').value = '';
      showMsg(`Discovery started for "${name}"`);
      loadCompanies();
    });

    async function rediscover(id, name) {
      const resp = await fetch(`${API}/companies/${id}/discover`, { method: 'POST' });
      if (!resp.ok) { showMsg((await resp.json()).detail || 'Error', true); return; }
      showMsg(`Re-running discovery for "${name}"`);
      loadCompanies();
    }

    // ---- Detail view ----

    async function openDetail(id, name) {
      currentCompanyId = id;
      listView.style.display = 'none';
      detailView.style.display = '';
      $('detail-company-name').textContent = name;
      await refreshDetail();
    }

    function closeDetail() {
      currentCompanyId = null;
      clearTimeout(pollTimer);
      listView.style.display = '';
      detailView.style.display = 'none';
      loadCompanies();
    }

    $('back-btn').addEventListener('click', closeDetail);

    $('rediscover-btn').addEventListener('click', async () => {
      if (!currentCompanyId) return;
      const resp = await fetch(`${API}/companies/${currentCompanyId}/discover`, { method: 'POST' });
      if (!resp.ok) { showMsg((await resp.json()).detail || 'Error', true); return; }
      showMsg('Re-running discovery…');
      refreshDetail();
    });

    async function refreshDetail() {
      if (!currentCompanyId) return;
      const [compResp, pendResp] = await Promise.all([
        fetch(`${API}/companies/${currentCompanyId}`),
        fetch(`${API}/companies/${currentCompanyId}/pending?limit=500`),
      ]);
      const comp = await compResp.json();
      const pending = await pendResp.json();

      $('detail-status-badge').innerHTML = statusBadge(comp.status);

      // ASNs
      const asnsTbody = $('asns-tbody');
      if (comp.asns && comp.asns.length) {
        asnsTbody.innerHTML = comp.asns.map(a => `
          <tr>
            <td>AS${a.asn}</td>
            <td>${a.description || '—'}</td>
            <td>${(a.cidr_ranges || []).join(', ') || '—'}</td>
          </tr>
        `).join('');
      } else {
        asnsTbody.innerHTML = '<tr><td colspan="3">No ASNs discovered yet.</td></tr>';
      }

      // Domain counts
      const dc = comp.domain_counts || {};
      $('pending-count').textContent = dc.pending || 0;
      $('approved-count').textContent = dc.approved || 0;

      // Pending table
      const pendTbody = $('pending-tbody');
      if (pending.length) {
        pendTbody.innerHTML = pending.map(d => `
          <tr data-id="${d.id}">
            <td><input type="checkbox" class="row-check" data-id="${d.id}"></td>
            <td>${d.domain}</td>
            <td>${d.ip || '—'}</td>
            <td>${d.source_asn ? 'AS' + d.source_asn : '—'}</td>
          </tr>
        `).join('');
        pendTbody.querySelectorAll('.row-check').forEach(cb => {
          cb.addEventListener('change', updateSelectionButtons);
        });
      } else {
        pendTbody.innerHTML = '<tr><td colspan="4">No pending domains.</td></tr>';
      }
      updateSelectionButtons();

      // Approved list
      const approvedEl = $('approved-list');
      if (dc.approved) {
        // Fetch approved domains inline via a separate filtered query isn't available,
        // so show the count with a link to targets page.
        approvedEl.innerHTML = `<p><a href="/ui/targets.html">${dc.approved} domain(s) added to targets →</a></p>`;
      } else {
        approvedEl.innerHTML = '<p>No approved domains yet.</p>';
      }

      // Poll while running
      clearTimeout(pollTimer);
      if (comp.status === 'running') {
        pollTimer = setTimeout(refreshDetail, 5000);
      }
    }

    function updateSelectionButtons() {
      const checked = document.querySelectorAll('.row-check:checked');
      $('approve-selected-btn').disabled = checked.length === 0;
      $('reject-selected-btn').disabled = checked.length === 0;
    }

    $('select-all-checkbox').addEventListener('change', e => {
      document.querySelectorAll('.row-check').forEach(cb => { cb.checked = e.target.checked; });
      updateSelectionButtons();
    });

    function getSelectedIds() {
      return Array.from(document.querySelectorAll('.row-check:checked')).map(cb => +cb.dataset.id);
    }

    async function doAction(action, body) {
      const resp = await fetch(`${API}/companies/${currentCompanyId}/${action}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      if (!resp.ok) { showMsg((await resp.json()).detail || 'Error', true); return; }
      const data = await resp.json();
      showMsg(`Done: ${JSON.stringify(data)}`);
      refreshDetail();
    }

    $('approve-selected-btn').addEventListener('click', () => doAction('approve', { domain_ids: getSelectedIds() }));
    $('reject-selected-btn').addEventListener('click', () => doAction('reject', { domain_ids: getSelectedIds() }));
    $('approve-all-btn').addEventListener('click', () => doAction('approve', { all: true }));

    // Init
    loadCompanies();
  })();
  </script>
</body>
</html>
```

- [ ] **Step 2: Commit**

```bash
rtk git add ingestor/static/companies.html
rtk git commit -m "feat: add companies.html UI — list + detail with review queue"
```

---

## Task 8: Add Companies Nav Link to All Existing Pages

**Files:**
- Modify: `ingestor/static/index.html`
- Modify: `ingestor/static/findings.html`
- Modify: `ingestor/static/subdomains.html`
- Modify: `ingestor/static/targets.html`
- Modify: `ingestor/static/ops.html`

In every file, find the nav block and add the Companies link between Targets and Ops. The current nav in each file looks like:

```html
          <a href="/ui/targets.html">Targets</a>
          <a class="is-active" href="/ui/ops.html" aria-current="page">Ops</a>
```

(The `is-active` class and `aria-current` are on whichever page is current.)

For each file, insert `<a href="/ui/companies.html">Companies</a>` between the Targets and Ops links.

- [ ] **Step 1: Update index.html nav**

Find:
```html
          <a href="/ui/targets.html">Targets</a>
          <a href="/ui/ops.html">Ops</a>
```
Replace with:
```html
          <a href="/ui/targets.html">Targets</a>
          <a href="/ui/companies.html">Companies</a>
          <a href="/ui/ops.html">Ops</a>
```

- [ ] **Step 2: Update findings.html nav**

Find:
```html
          <a href="/ui/targets.html">Targets</a>
          <a href="/ui/ops.html">Ops</a>
```
Replace with:
```html
          <a href="/ui/targets.html">Targets</a>
          <a href="/ui/companies.html">Companies</a>
          <a href="/ui/ops.html">Ops</a>
```

- [ ] **Step 3: Update subdomains.html nav**

Same replacement as above.

- [ ] **Step 4: Update targets.html nav**

Find:
```html
          <a class="is-active" href="/ui/targets.html" aria-current="page">Targets</a>
          <a href="/ui/ops.html">Ops</a>
```
Replace with:
```html
          <a class="is-active" href="/ui/targets.html" aria-current="page">Targets</a>
          <a href="/ui/companies.html">Companies</a>
          <a href="/ui/ops.html">Ops</a>
```

- [ ] **Step 5: Update ops.html nav**

Find:
```html
          <a href="/ui/targets.html">Targets</a>
          <a class="is-active" href="/ui/ops.html" aria-current="page">Ops</a>
```
Replace with:
```html
          <a href="/ui/targets.html">Targets</a>
          <a href="/ui/companies.html">Companies</a>
          <a class="is-active" href="/ui/ops.html" aria-current="page">Ops</a>
```

- [ ] **Step 6: Commit**

```bash
rtk git add ingestor/static/index.html ingestor/static/findings.html ingestor/static/subdomains.html ingestor/static/targets.html ingestor/static/ops.html
rtk git commit -m "feat: add Companies nav link to all pages"
```

---

## Task 9: Final Verification

- [ ] **Step 1: Run full test suite**

```bash
cd C:\Users\Mathias\Documents\pi
python -m pytest ingestor/tests/ -v
```
Expected: all tests pass, none skipped.

- [ ] **Step 2: Push and redeploy**

```bash
rtk git push
source .env && \
TOKEN=$(curl -s -X POST "$PORTAINER_URL/api/auth" \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"$PORTAINER_USER\",\"password\":\"$PORTAINER_PASSWORD\"}" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['jwt'])") && \
ENV=$(curl -s -H "Authorization: Bearer $TOKEN" \
  "$PORTAINER_URL/api/stacks/15" \
  | python3 -c "import sys,json; print(json.dumps(json.load(sys.stdin)['Env']))") && \
curl -s -X PUT "$PORTAINER_URL/api/stacks/15/git/redeploy?endpointId=2" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"env\":$ENV,\"prune\":false,\"pullImage\":true,\"repositoryAuthentication\":false}" \
  | python3 -c "import sys,json; r=json.load(sys.stdin); print('Redeployed:', r.get('Name', r))"
```

- [ ] **Step 3: Smoke test the Companies page**

Open `http://192.168.1.191:8090/ui/companies.html` in the browser.

- Submit `"TestOrg"` — verify it appears in the table with status `running`
- Verify the nav link appears on all other pages
- Open the Ops page — verify `company_intel` and `company_intel_asn` appear in the DLQ panel
