# Smarter Company Discovery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the `amass intel` pipeline with a multi-source discovery pipeline (GLEIF → crt.sh → optional SecurityTrails pivot → RIPEstat) that finds root domains for a company and all its subsidiaries, with trust scoring to guide manual review before recon is triggered.

**Architecture:** GLEIF resolves the company's LEI and all direct-child entity names; one crt.sh job is enqueued per entity + one for the seed domain wildcard; each crt.sh job produces root domains with trust scores (1–3) and optionally enqueues a SecurityTrails pivot from the seed domain's registrant email; RIPEstat enriches every discovered domain with ASN and CIDR ranges. A Redis counter per company (`company:{id}:pending_jobs`) tracks in-flight jobs and flips `company.status = done` when it reaches zero.

**Tech Stack:** Python 3.12-slim ARM64, FastAPI (existing), SQLite (existing), Redis (existing), `requests==2.32.3`, GLEIF API (free), crt.sh API (free), SecurityTrails API (optional, 50 calls/month free tier), RIPEstat API (free).

---

## File Map

| Action | File | Responsibility |
|---|---|---|
| Modify | `workers/common/db.py` | Add `seed_domain` to companies, 4 new columns to discovered_domains, `discovered_emails` table |
| Rewrite | `workers/intel/worker.py` | 4 pass handlers (GLEIF, crt.sh, pivot, RIPEstat) + completion counter + 4-thread main |
| Modify | `workers/intel/requirements.txt` | Add `requests==2.32.3` |
| Modify | `workers/intel/Dockerfile` | Remove amass install; pure Python slim image |
| Modify | `docker-compose.yml` | Add `SECURITYTRAILS_API_KEY` env var to worker-intel service |
| Modify | `ingestor/app.py` | `seed_domain` in `CompanyIn`, `min_trust` in `DomainActionRequest`, DLQ queue names, endpoint updates, Redis counter INCR |
| Modify | `ingestor/tests/test_api_dashboard_v2.py` | `FakeRedis.incr/decr`, new API tests |
| Create | `workers/intel/tests/__init__.py` | Package marker |
| Create | `workers/intel/tests/test_worker_utils.py` | Unit tests for `_extract_root_domain` and `_compute_trust` |
| Modify | `ingestor/static/companies.html` | Seed domain input, trust column, filter tabs, "Approve all HIGH" button |

---

## Task 1: DB Schema — Add New Columns and `discovered_emails` Table

**Files:**
- Modify: `workers/common/db.py`

- [ ] **Step 1: Add `discovered_emails` to SCHEMA_SQL**

In `workers/common/db.py`, find the closing `"""` of `SCHEMA_SQL` (after the `discovered_domains` block, line ~131) and insert before it:

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

- [ ] **Step 2: Add migration blocks to `init_db()`**

In `workers/common/db.py`, after the last existing migration block (the `discovered_domains ADD COLUMN status` block, around line 208), add:

```python
    # Smarter company discovery migrations (idempotent).
    for col_sql in [
        "ALTER TABLE companies ADD COLUMN seed_domain TEXT",
        "ALTER TABLE discovered_domains ADD COLUMN trust_score   INTEGER NOT NULL DEFAULT 1",
        "ALTER TABLE discovered_domains ADD COLUMN trust_signals TEXT",
        "ALTER TABLE discovered_domains ADD COLUMN source        TEXT",
        "ALTER TABLE discovered_domains ADD COLUMN hop_depth     INTEGER NOT NULL DEFAULT 0",
    ]:
        try:
            conn.execute(col_sql)
            conn.commit()
        except sqlite3.OperationalError:
            pass  # column already exists
```

- [ ] **Step 3: Verify schema applies cleanly**

```bash
cd C:\Users\Mathias\Documents\pi
python3 -c "
import sys; sys.path.insert(0, 'workers')
from common.db import init_db
init_db('/tmp/test_schema2.db')
print('Schema OK')
"
```
Expected: `Schema OK` with no exceptions.

- [ ] **Step 4: Commit**

```bash
rtk git add workers/common/db.py
rtk git commit -m "feat: add seed_domain, trust columns, discovered_emails table"
```

---

## Task 2: Worker Utility Functions + Unit Tests

**Files:**
- Create: `workers/intel/tests/__init__.py`
- Create: `workers/intel/tests/test_worker_utils.py`

These pure functions have no dependencies and are the core of the trust scoring logic.

- [ ] **Step 1: Create package marker**

Create `workers/intel/tests/__init__.py` as an empty file.

- [ ] **Step 2: Write failing tests**

Create `workers/intel/tests/test_worker_utils.py`:

```python
"""
Unit tests for pure utility functions in worker-intel.
Stubs redis and requests at module level so worker.py can be imported
without a running Redis or network.
"""

import os
import sys
import types
from pathlib import Path

# ── Path + env setup (must happen before importing worker) ────────────────────
_PROJ_ROOT = Path(__file__).resolve().parents[3]
os.environ.setdefault("LOG_DIR", str(_PROJ_ROOT / "logs"))
os.environ.setdefault("SQLITE_PATH", str(_PROJ_ROOT / "tests" / "test_utils.db"))

sys.path.insert(0, str(_PROJ_ROOT / "workers"))
sys.path.insert(0, str(_PROJ_ROOT / "workers" / "intel"))

# Stub redis
if "redis" not in sys.modules:
    _r = types.ModuleType("redis")
    class _FakeR:
        def incr(self, *a): pass
        def decr(self, *a): return 1
        def delete(self, *a): pass
    _r.Redis = _FakeR
    _r.from_url = lambda *a, **kw: _FakeR()
    _r.ConnectionError = Exception
    sys.modules["redis"] = _r

# Stub requests
if "requests" not in sys.modules:
    _req = types.ModuleType("requests")
    _req.get = lambda *a, **kw: None
    _req.post = lambda *a, **kw: None
    sys.modules["requests"] = _req

import pytest
from worker import _compute_trust, _extract_root_domain


# ---------------------------------------------------------------------------
# _extract_root_domain
# ---------------------------------------------------------------------------

def test_extract_strips_wildcard():
    assert _extract_root_domain("*.kering.com") == "kering.com"

def test_extract_keeps_apex():
    assert _extract_root_domain("kering.com") == "kering.com"

def test_extract_strips_subdomain():
    assert _extract_root_domain("api.gucci.com") == "gucci.com"

def test_extract_handles_deep_subdomain():
    assert _extract_root_domain("a.b.c.kering.com") == "kering.com"

def test_extract_lowercases():
    assert _extract_root_domain("KERING.COM") == "kering.com"


# ---------------------------------------------------------------------------
# _compute_trust
# ---------------------------------------------------------------------------

def test_trust_cert_org_match_is_high():
    score, signals = _compute_trust("gucci.com", "Kering", "kering.com", "crt_org")
    assert score == 3
    assert "cert_org_match" in signals

def test_trust_seed_subdomain_is_high():
    score, signals = _compute_trust("api.kering.com", "Kering", "kering.com", "crt_seed")
    assert score == 3
    assert "seed_match" in signals

def test_trust_seed_exact_match_is_high():
    score, signals = _compute_trust("kering.com", "Kering", "kering.com", "crt_seed")
    assert score == 3
    assert "seed_match" in signals

def test_trust_name_in_domain_is_medium():
    score, signals = _compute_trust("keringapps.com", "Kering", "kering.com", "crt_seed")
    assert score == 2
    assert "name_contains_target" in signals

def test_trust_pivot_1_is_medium():
    score, signals = _compute_trust("unrelated.com", "Kering", "kering.com", "pivot_1")
    assert score == 2
    assert "pivot_1" in signals

def test_trust_pivot_2_is_always_low():
    score, signals = _compute_trust("keringtest.com", "Kering", "kering.com", "pivot_2")
    assert score == 1
    assert "pivot_2" in signals

def test_trust_no_signals_is_low():
    score, signals = _compute_trust("randomdomain.com", "Kering", "kering.com", "crt_seed")
    assert score == 1

def test_trust_no_seed_domain():
    score, signals = _compute_trust("kering.com", "Kering", None, "crt_org")
    assert score == 3
    assert "cert_org_match" in signals

def test_trust_short_company_name_not_matched():
    # "ab" is < 4 chars, should not match "abcdef.com"
    score, signals = _compute_trust("abcdef.com", "AB", None, "crt_seed")
    assert "name_contains_target" not in signals
```

- [ ] **Step 3: Run tests to confirm they all fail**

```bash
cd C:\Users\Mathias\Documents\pi
python -m pytest workers/intel/tests/test_worker_utils.py -v 2>&1 | head -20
```
Expected: `ImportError` or `ModuleNotFoundError` — `worker` module not yet written.

- [ ] **Step 4: Commit failing tests**

```bash
rtk git add workers/intel/tests/
rtk git commit -m "test: add unit tests for worker-intel utility functions"
```

---

## Task 3: Worker Full Rewrite

**Files:**
- Rewrite: `workers/intel/worker.py`

- [ ] **Step 1: Rewrite `workers/intel/worker.py`**

Replace the entire file with:

```python
"""
Intel worker — smarter company discovery
=========================================
Four passes, four threads:

  company_intel          (pass 1): GLEIF → entity names → enqueue crt.sh jobs
  company_intel_crt      (pass 2): crt.sh → root domains + trust scores
  company_intel_pivot    (pass 3): SecurityTrails reverse WHOIS (optional)
  company_intel_ripestat (pass 4): RIPEstat → ASN + CIDR enrichment
"""

import json
import logging
import os
import re
import sys
import threading
import time

import requests
import redis as redis_lib

sys.path.insert(0, "/app")
from common.db import db_conn, init_db
from common.queue import (
    ack_task,
    dequeue_blocking,
    enqueue,
    nack_task,
    recover_processing_queue,
    wait_for_redis,
)

QUEUE_GLEIF    = "company_intel"
PROC_GLEIF     = "company_intel:processing"
QUEUE_CRT      = "company_intel_crt"
PROC_CRT       = "company_intel_crt:processing"
QUEUE_PIVOT    = "company_intel_pivot"
PROC_PIVOT     = "company_intel_pivot:processing"
QUEUE_RIPESTAT = "company_intel_ripestat"
PROC_RIPESTAT  = "company_intel_ripestat:processing"

WORKER_NAME = "worker-intel"
MAX_RETRIES = int(os.environ.get("MAX_RETRIES", 2))
ST_KEY      = os.environ.get("SECURITYTRAILS_API_KEY", "")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
    handlers=[logging.StreamHandler()],
)
logger = logging.getLogger(WORKER_NAME)
_LOG_DIR = os.environ.get("LOG_DIR", "/logs")
os.makedirs(_LOG_DIR, exist_ok=True)
logger.addHandler(logging.FileHandler(os.path.join(_LOG_DIR, "worker-intel.log")))


# ── Completion counter ────────────────────────────────────────────────────────

def _counter_key(company_id: int) -> str:
    return f"company:{company_id}:pending_jobs"


def _enqueue_job(r, queue: str, payload: dict, company_id: int) -> None:
    r.incr(_counter_key(company_id))
    enqueue(r, queue, payload)


def _job_done(r, company_id: int) -> None:
    val = r.decr(_counter_key(company_id))
    if val <= 0:
        r.delete(_counter_key(company_id))
        with db_conn() as conn:
            conn.execute(
                "UPDATE companies SET status = 'done' WHERE id = ?", (company_id,)
            )
        logger.info("Company %d: all jobs done → status=done", company_id)


# ── Pure utility functions ────────────────────────────────────────────────────

def _extract_root_domain(domain: str) -> str:
    domain = re.sub(r"^\*\.", "", domain.lower().strip())
    parts = domain.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return domain


def _compute_trust(
    domain: str,
    company_name: str,
    seed_domain: str | None,
    source: str,
) -> tuple[int, list[str]]:
    signals: list[str] = []

    if source == "crt_org":
        signals.append("cert_org_match")

    if seed_domain and (domain == seed_domain or domain.endswith("." + seed_domain)):
        signals.append("seed_match")

    name_slug = re.sub(r"[^a-z0-9]", "", company_name.lower())
    domain_slug = re.sub(r"[^a-z0-9]", "", domain.lower())
    if len(name_slug) >= 4 and name_slug in domain_slug:
        signals.append("name_contains_target")

    if source == "pivot_2":
        signals.append("pivot_2")
        return 1, signals

    if source == "pivot_1":
        signals.append("pivot_1")
        if "cert_org_match" in signals or "seed_match" in signals:
            return 3, signals
        return 2, signals

    if "cert_org_match" in signals or "seed_match" in signals:
        return 3, signals
    if "name_contains_target" in signals:
        return 2, signals
    return 1, signals


# ── HTTP helpers ──────────────────────────────────────────────────────────────

def _get_json(url: str, headers: dict | None = None, params: dict | None = None) -> dict | list | None:
    try:
        resp = requests.get(url, headers=headers, params=params, timeout=30)
        resp.raise_for_status()
        return resp.json()
    except Exception as exc:
        logger.warning("GET %s failed: %s", url, exc)
        return None


def _post_json(url: str, headers: dict | None = None, body: dict | None = None) -> dict | None:
    try:
        resp = requests.post(url, headers=headers, json=body, timeout=30)
        resp.raise_for_status()
        return resp.json()
    except Exception as exc:
        logger.warning("POST %s failed: %s", url, exc)
        return None


# ── DB helpers ────────────────────────────────────────────────────────────────

def _insert_domain(
    company_id: int,
    domain: str,
    source: str,
    trust_score: int,
    trust_signals: list[str],
) -> bool:
    """Insert domain if (company_id, domain) not yet present. Returns True if inserted."""
    try:
        with db_conn() as conn:
            existing_target = conn.execute(
                "SELECT enabled FROM targets WHERE scope_root = ?", (domain,)
            ).fetchone()
            auto_status = (
                "approved"
                if (existing_target and existing_target["enabled"] == 1)
                else "pending"
            )
            conn.execute(
                """
                INSERT INTO discovered_domains
                    (company_id, domain, source, trust_score, trust_signals, status)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (company_id, domain, source, trust_score, json.dumps(trust_signals), auto_status),
            )
            return True
    except Exception:
        return False  # UNIQUE constraint — domain already exists for this company


# ── Pass 1: GLEIF ─────────────────────────────────────────────────────────────

def handle_gleif(r, task: dict) -> None:
    company_id  = task["company_id"]
    name        = task["name"]
    seed_domain = task.get("seed_domain")

    with db_conn() as conn:
        conn.execute(
            "UPDATE companies SET status = 'running' WHERE id = ?", (company_id,)
        )

    entity_names: list[str] = [name]

    data = _get_json(
        "https://api.gleif.org/api/v1/fuzzycompletions",
        params={"field": "fulltext", "q": name},
    )
    lei = None
    if data and data.get("data"):
        lei = data["data"][0]["id"]
        logger.info("Company %d: GLEIF LEI=%s", company_id, lei)

    if lei:
        url: str | None = (
            f"https://api.gleif.org/api/v1/lei-records/{lei}/direct-children"
        )
        while url:
            page = _get_json(url, params={"page[size]": 100})
            if not page or not page.get("data"):
                break
            for record in page["data"]:
                try:
                    child_name = record["attributes"]["entity"]["legalName"]["name"]
                    if child_name not in entity_names:
                        entity_names.append(child_name)
                except (KeyError, TypeError):
                    pass
            url = (page.get("links") or {}).get("next")

    logger.info("Company %d: %d entities to probe via crt.sh", company_id, len(entity_names))

    for entity in entity_names:
        _enqueue_job(r, QUEUE_CRT, {
            "company_id": company_id,
            "query_type": "org",
            "value": entity,
            "company_name": name,
            "seed_domain": seed_domain,
        }, company_id)

    if seed_domain:
        _enqueue_job(r, QUEUE_CRT, {
            "company_id": company_id,
            "query_type": "seed",
            "value": seed_domain,
            "company_name": name,
            "seed_domain": seed_domain,
        }, company_id)
        if ST_KEY:
            _enqueue_job(r, QUEUE_PIVOT, {
                "company_id": company_id,
                "domain": seed_domain,
                "hop_depth": 0,
                "company_name": name,
                "seed_domain": seed_domain,
            }, company_id)


# ── Pass 2: crt.sh ────────────────────────────────────────────────────────────

def handle_crt(r, task: dict) -> None:
    company_id   = task["company_id"]
    query_type   = task["query_type"]
    value        = task["value"]
    company_name = task["company_name"]
    seed_domain  = task.get("seed_domain")

    if query_type == "org":
        params = {"o": value, "output": "json"}
        source = "crt_org"
    else:
        params = {"q": f"%.{value}", "output": "json"}
        source = "crt_seed"

    certs = _get_json("https://crt.sh/", params=params)
    if not certs or not isinstance(certs, list):
        return

    seen: set[str] = set()
    for cert in certs:
        raw_names: list[str] = []
        if cert.get("common_name"):
            raw_names.append(cert["common_name"])
        for san in (cert.get("name_value") or "").splitlines():
            if san.strip():
                raw_names.append(san.strip())

        for raw in raw_names:
            root = _extract_root_domain(raw)
            if not root or root in seen or "." not in root:
                continue
            seen.add(root)
            trust_score, trust_signals = _compute_trust(
                root, company_name, seed_domain, source
            )
            if _insert_domain(company_id, root, source, trust_score, trust_signals):
                _enqueue_job(r, QUEUE_RIPESTAT, {
                    "company_id": company_id,
                    "domain": root,
                }, company_id)

    logger.info(
        "Company %d: crt.sh %s=%r → %d unique root domains",
        company_id, query_type, value, len(seen),
    )


# ── Pass 3: SecurityTrails pivot ──────────────────────────────────────────────

def handle_pivot(r, task: dict) -> None:
    """
    Two sub-types determined by task key:
      "domain" → WHOIS lookup to extract registrant email → enqueue email task
      "email"  → reverse WHOIS to find domains registered by that email
    """
    company_id   = task["company_id"]
    company_name = task.get("company_name", "")
    seed_domain  = task.get("seed_domain")
    hop_depth    = task.get("hop_depth", 1)

    if "domain" in task:
        _pivot_whois_lookup(r, task["domain"], company_id, company_name, seed_domain, hop_depth)
    elif "email" in task:
        _pivot_reverse_whois(r, task["email"], company_id, company_name, seed_domain, hop_depth)


def _pivot_whois_lookup(
    r,
    domain: str,
    company_id: int,
    company_name: str,
    seed_domain: str | None,
    hop_depth: int,
) -> None:
    data = _get_json(
        f"https://api.securitytrails.com/v1/domain/{domain}/whois",
        headers={"APIKEY": ST_KEY},
    )
    if not data:
        return

    for contact in (data.get("contacts") or []):
        email = (contact.get("email") or "").strip().lower()
        if not email or "@" not in email:
            continue
        try:
            with db_conn() as conn:
                conn.execute(
                    "INSERT INTO discovered_emails (company_id, email, hop_depth) VALUES (?, ?, ?)",
                    (company_id, email, hop_depth + 1),
                )
            _enqueue_job(r, QUEUE_PIVOT, {
                "company_id": company_id,
                "email": email,
                "hop_depth": hop_depth + 1,
                "company_name": company_name,
                "seed_domain": seed_domain,
            }, company_id)
            logger.info("Company %d: pivot email %s (hop %d)", company_id, email, hop_depth + 1)
        except Exception:
            pass  # UNIQUE constraint — already queued this email


def _pivot_reverse_whois(
    r,
    email: str,
    company_id: int,
    company_name: str,
    seed_domain: str | None,
    hop_depth: int,
) -> None:
    data = _post_json(
        "https://api.securitytrails.com/v1/domains/list",
        headers={"APIKEY": ST_KEY, "Content-Type": "application/json"},
        body={"filter": {"whois_email": email}},
    )
    if not data:
        return

    source = f"pivot_{hop_depth}"
    inserted = 0
    for record in (data.get("records") or []):
        domain = (record.get("hostname") or "").strip().lower()
        if not domain or "." not in domain:
            continue
        root = _extract_root_domain(domain)
        trust_score, trust_signals = _compute_trust(root, company_name, seed_domain, source)
        if _insert_domain(company_id, root, source, trust_score, trust_signals):
            inserted += 1
            _enqueue_job(r, QUEUE_RIPESTAT, {"company_id": company_id, "domain": root}, company_id)
            if hop_depth < 2:
                _enqueue_job(r, QUEUE_PIVOT, {
                    "company_id": company_id,
                    "domain": root,
                    "hop_depth": hop_depth,
                    "company_name": company_name,
                    "seed_domain": seed_domain,
                }, company_id)

    logger.info(
        "Company %d: reverse WHOIS email=%s hop=%d → %d domains",
        company_id, email, hop_depth, inserted,
    )


# ── Pass 4: RIPEstat ──────────────────────────────────────────────────────────

def handle_ripestat(r, task: dict) -> None:
    company_id = task["company_id"]
    domain     = task["domain"]

    data = _get_json(
        "https://stat.ripe.net/data/prefix-overview/data.json",
        params={"resource": domain},
    )
    if not data:
        return

    result   = data.get("data") or {}
    asns_raw = result.get("asns") or []
    prefixes = [p["prefix"] for p in (result.get("prefixes") or []) if p.get("prefix")]

    for entry in asns_raw:
        asn = str(entry.get("asn", "")).strip()
        if not asn:
            continue
        description = entry.get("holder", "")
        try:
            with db_conn() as conn:
                conn.execute(
                    """
                    INSERT INTO discovered_asns (company_id, asn, description, cidr_ranges)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(company_id, asn) DO UPDATE SET
                        description = excluded.description,
                        cidr_ranges = excluded.cidr_ranges
                    """,
                    (company_id, asn, description, json.dumps(prefixes)),
                )
        except Exception as exc:
            logger.warning("Company %d: failed upsert ASN %s: %s", company_id, asn, exc)


# ── Worker loop ───────────────────────────────────────────────────────────────

def _worker_loop(queue: str, processing: str, handler, r) -> None:
    recover_processing_queue(r, queue, processing, max_retries=MAX_RETRIES)
    logger.info("%s: listening on %s", WORKER_NAME, queue)

    while True:
        task = dequeue_blocking(r, queue, processing, timeout=30.0)
        if task is None:
            continue
        company_id = task.get("company_id")
        try:
            handler(r, task)
            ack_task(r, processing, task)
            if company_id is not None:
                _job_done(r, company_id)
        except Exception as exc:
            logger.exception("Task failed on %s: %s", queue, exc)
            nack_task(r, queue, processing, task, max_retries=MAX_RETRIES)


def main() -> None:
    init_db()
    r = wait_for_redis()

    specs = [
        (QUEUE_GLEIF,    PROC_GLEIF,    handle_gleif,    "gleif"),
        (QUEUE_CRT,      PROC_CRT,      handle_crt,      "crt"),
        (QUEUE_PIVOT,    PROC_PIVOT,    handle_pivot,    "pivot"),
        (QUEUE_RIPESTAT, PROC_RIPESTAT, handle_ripestat, "ripestat"),
    ]

    threads = [
        threading.Thread(
            target=_worker_loop, args=(q, p, h, r), name=n, daemon=True
        )
        for q, p, h, n in specs
    ]
    for t in threads:
        t.start()
    logger.info("%s started (gleif + crt + pivot + ripestat threads)", WORKER_NAME)

    while True:
        for i, (t, (q, p, h, n)) in enumerate(zip(threads, specs)):
            if not t.is_alive():
                logger.critical("%s thread died — restarting", n)
                threads[i] = threading.Thread(
                    target=_worker_loop, args=(q, p, h, r), name=n, daemon=True
                )
                threads[i].start()
        time.sleep(10)


if __name__ == "__main__":
    main()
```

- [ ] **Step 2: Run unit tests — they should now pass**

```bash
cd C:\Users\Mathias\Documents\pi
python -m pytest workers/intel/tests/test_worker_utils.py -v
```
Expected: all 11 tests pass.

- [ ] **Step 3: Verify worker imports cleanly**

```bash
cd C:\Users\Mathias\Documents\pi
python3 -c "
import sys, types
sys.path.insert(0, 'workers')
# Stub redis
r = types.ModuleType('redis')
class _R:
    def incr(self, *a): pass
    def decr(self, *a): return 1
    def delete(self, *a): pass
r.Redis = _R
r.from_url = lambda *a, **kw: _R()
r.ConnectionError = Exception
sys.modules['redis'] = r
# Stub requests
req = types.ModuleType('requests')
req.get = lambda *a, **kw: None
req.post = lambda *a, **kw: None
sys.modules['requests'] = req
import importlib.util
spec = importlib.util.spec_from_file_location('worker', 'workers/intel/worker.py')
mod = importlib.util.module_from_spec(spec)
print('Import OK')
"
```
Expected: `Import OK`.

- [ ] **Step 4: Commit**

```bash
rtk git add workers/intel/worker.py workers/intel/tests/
rtk git commit -m "feat: rewrite worker-intel with GLEIF+crt.sh+pivot+RIPEstat pipeline"
```

---

## Task 4: Dockerfile + Requirements + docker-compose

**Files:**
- Modify: `workers/intel/requirements.txt`
- Modify: `workers/intel/Dockerfile`
- Modify: `docker-compose.yml`

- [ ] **Step 1: Update `workers/intel/requirements.txt`**

Replace the entire file with:

```
redis==5.0.4
requests==2.32.3
```

- [ ] **Step 2: Rewrite `workers/intel/Dockerfile`**

Replace the entire file with:

```dockerfile
# ---------------------------------------------------------------------------
# Intel worker image — Python only (no amass binary)
# ---------------------------------------------------------------------------
FROM --platform=linux/arm64 python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

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

- [ ] **Step 3: Add `SECURITYTRAILS_API_KEY` to docker-compose.yml**

In `docker-compose.yml`, find the `worker-intel` service's `environment` block and add:

```yaml
      - SECURITYTRAILS_API_KEY=${SECURITYTRAILS_API_KEY:-}
```

- [ ] **Step 4: Validate docker-compose syntax**

```bash
cd C:\Users\Mathias\Documents\pi
docker compose config --quiet && echo "Compose OK"
```
Expected: `Compose OK`.

- [ ] **Step 5: Commit**

```bash
rtk git add workers/intel/requirements.txt workers/intel/Dockerfile docker-compose.yml
rtk git commit -m "feat: simplify worker-intel Dockerfile (remove amass), add SECURITYTRAILS_API_KEY"
```

---

## Task 5: API Tests (Write Failing First)

**Files:**
- Modify: `ingestor/tests/test_api_dashboard_v2.py`

- [ ] **Step 1: Add `_counters` dict and `incr`/`decr` methods to `FakeRedis`**

In `ingestor/tests/test_api_dashboard_v2.py`, find `class FakeRedis:` and add `self._counters = {}` to `__init__`:

```python
    def __init__(self):
        self.lists = {}
        self._counters = {}
```

Then add two methods after `delete`:

```python
    def incr(self, key, amount=1):
        self._counters[key] = self._counters.get(key, 0) + amount
        return self._counters[key]

    def decr(self, key, amount=1):
        self._counters[key] = self._counters.get(key, 0) - amount
        return self._counters[key]
```

Also update the existing `delete` method to clear counters too — find:
```python
    def delete(self, *keys):
        deleted = 0
        for key in keys:
            if key in self.lists:
                del self.lists[key]
                deleted += 1
        return deleted
```
Replace with:
```python
    def delete(self, *keys):
        deleted = 0
        for key in keys:
            if key in self.lists:
                del self.lists[key]
                deleted += 1
            if key in self._counters:
                del self._counters[key]
                deleted += 1
        return deleted
```

- [ ] **Step 2: Add new API tests**

At the end of `ingestor/tests/test_api_dashboard_v2.py`, add:

```python
# ---------------------------------------------------------------------------
# Smarter company discovery — API changes
# ---------------------------------------------------------------------------

def test_post_companies_accepts_seed_domain(client):
    test_client, ingestor_app, _, enqueued = client
    resp = test_client.post("/companies", json={"name": "Kering", "seed_domain": "kering.com"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["seed_domain"] == "kering.com"


def test_post_companies_enqueues_with_new_payload(client):
    test_client, ingestor_app, _, enqueued = client
    resp = test_client.post("/companies", json={"name": "Kering", "seed_domain": "kering.com"})
    assert resp.status_code == 200
    job = next(e for e in enqueued if e["queue"] == "company_intel")
    assert job["payload"]["name"] == "Kering"
    assert job["payload"]["seed_domain"] == "kering.com"


def _insert_company_with_seed(ingestor_app, name="Kering", seed_domain="kering.com", status="idle"):
    with ingestor_app.db_conn() as conn:
        return conn.execute(
            "INSERT INTO companies (name, seed_domain, status) VALUES (?, ?, ?)",
            (name, seed_domain, status),
        ).lastrowid


def _insert_domain_with_trust(
    ingestor_app, company_id, domain, trust_score=1, status="pending"
):
    with ingestor_app.db_conn() as conn:
        return conn.execute(
            "INSERT INTO discovered_domains (company_id, domain, trust_score, trust_signals, source, status) VALUES (?, ?, ?, ?, ?, ?)",
            (company_id, domain, trust_score, '[]', 'crt_org', status),
        ).lastrowid


def test_get_company_detail_includes_trust_breakdown(client):
    test_client, ingestor_app, _, _ = client
    cid = _insert_company_with_seed(ingestor_app)
    _insert_domain_with_trust(ingestor_app, cid, "gucci.com", trust_score=3)
    _insert_domain_with_trust(ingestor_app, cid, "keringapps.com", trust_score=2)
    _insert_domain_with_trust(ingestor_app, cid, "unknown.com", trust_score=1)

    resp = test_client.get(f"/companies/{cid}")
    assert resp.status_code == 200
    dc = resp.json()["domain_counts"]
    assert dc["pending"] == 3
    assert dc["pending_by_trust"]["high"] == 1
    assert dc["pending_by_trust"]["medium"] == 1
    assert dc["pending_by_trust"]["low"] == 1


def test_get_pending_domains_trust_filter(client):
    test_client, ingestor_app, _, _ = client
    cid = _insert_company_with_seed(ingestor_app)
    _insert_domain_with_trust(ingestor_app, cid, "gucci.com", trust_score=3)
    _insert_domain_with_trust(ingestor_app, cid, "keringapps.com", trust_score=2)
    _insert_domain_with_trust(ingestor_app, cid, "unknown.com", trust_score=1)

    resp = test_client.get(f"/companies/{cid}/pending?trust=3")
    assert resp.status_code == 200
    domains = resp.json()
    assert len(domains) == 1
    assert domains[0]["domain"] == "gucci.com"


def test_get_pending_domains_no_filter_returns_all(client):
    test_client, ingestor_app, _, _ = client
    cid = _insert_company_with_seed(ingestor_app)
    _insert_domain_with_trust(ingestor_app, cid, "gucci.com", trust_score=3)
    _insert_domain_with_trust(ingestor_app, cid, "keringapps.com", trust_score=2)

    resp = test_client.get(f"/companies/{cid}/pending")
    assert resp.status_code == 200
    assert len(resp.json()) == 2


def test_approve_min_trust_approves_only_high(client):
    test_client, ingestor_app, _, enqueued = client
    cid = _insert_company_with_seed(ingestor_app)
    _insert_domain_with_trust(ingestor_app, cid, "gucci.com", trust_score=3)
    _insert_domain_with_trust(ingestor_app, cid, "keringapps.com", trust_score=2)
    _insert_domain_with_trust(ingestor_app, cid, "unknown.com", trust_score=1)

    resp = test_client.post(f"/companies/{cid}/approve", json={"min_trust": 3})
    assert resp.status_code == 200
    assert resp.json()["approved"] == 1

    with ingestor_app.db_conn() as conn:
        row = conn.execute(
            "SELECT status FROM discovered_domains WHERE domain = 'gucci.com'"
        ).fetchone()
    assert row["status"] == "approved"

    with ingestor_app.db_conn() as conn:
        row = conn.execute(
            "SELECT status FROM discovered_domains WHERE domain = 'keringapps.com'"
        ).fetchone()
    assert row["status"] == "pending"


def test_rediscover_uses_new_payload_format(client):
    test_client, ingestor_app, _, enqueued = client
    cid = _insert_company_with_seed(ingestor_app, status="done")
    resp = test_client.post(f"/companies/{cid}/discover")
    assert resp.status_code == 200
    job = next(e for e in enqueued if e["queue"] == "company_intel")
    assert "name" in job["payload"]
    assert "seed_domain" in job["payload"]
```

- [ ] **Step 3: Run new tests to confirm they fail**

```bash
cd C:\Users\Mathias\Documents\pi
python -m pytest ingestor/tests/test_api_dashboard_v2.py -k "seed_domain or trust or min_trust or new_payload" -v 2>&1 | tail -20
```
Expected: all new tests FAIL (columns/fields not yet implemented).

- [ ] **Step 4: Commit failing tests**

```bash
rtk git add ingestor/tests/test_api_dashboard_v2.py
rtk git commit -m "test: add failing tests for seed_domain, trust filter, min_trust approve"
```

---

## Task 6: API Implementation

**Files:**
- Modify: `ingestor/app.py`

- [ ] **Step 1: Update `_DLQ_QUEUES`**

Find (around line 79):
```python
_DLQ_QUEUES = [
    "recon_domain",
    "brute_domain",
    "probe_host",
    "scan_http",
    "notify_finding",
    "company_intel",
    "company_intel_asn",
]
```
Replace with:
```python
_DLQ_QUEUES = [
    "recon_domain",
    "brute_domain",
    "probe_host",
    "scan_http",
    "notify_finding",
    "company_intel",
    "company_intel_crt",
    "company_intel_pivot",
    "company_intel_ripestat",
]
```

- [ ] **Step 2: Update `CompanyIn`**

Find the `CompanyIn` class (around line 493) and replace it with:

```python
class CompanyIn(BaseModel):
    name: str
    seed_domain: Optional[str] = None

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        value = v.strip()
        if not value:
            raise ValueError("name must not be empty")
        if len(value) > 200:
            raise ValueError("name must be 200 characters or fewer")
        return value

    @field_validator("seed_domain")
    @classmethod
    def validate_seed_domain(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        v = v.strip().lower()
        if not v:
            return None
        if not re.match(r"^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?)+$", v):
            raise ValueError("seed_domain must be a valid domain name (e.g. kering.com)")
        return v
```

- [ ] **Step 3: Update `DomainActionRequest`**

Find the `DomainActionRequest` class (around line 507) and replace it with:

```python
class DomainActionRequest(BaseModel):
    domain_ids: Optional[list[int]] = None
    all: bool = False
    min_trust: Optional[int] = None

    @field_validator("domain_ids")
    @classmethod
    def validate_ids(cls, v: Optional[list[int]]) -> Optional[list[int]]:
        if v is not None and len(v) == 0:
            raise ValueError("domain_ids must not be empty when provided")
        return v

    @field_validator("min_trust")
    @classmethod
    def validate_min_trust(cls, v: Optional[int]) -> Optional[int]:
        if v is not None and v not in (1, 2, 3):
            raise ValueError("min_trust must be 1, 2, or 3")
        return v
```

- [ ] **Step 4: Update `create_company` endpoint**

Find the `create_company` function (around line 1346) and replace it with:

```python
@app.post("/companies")
def create_company(body: CompanyIn):
    r = get_r()
    with db_conn() as conn:
        existing = conn.execute(
            "SELECT id, status FROM companies WHERE name = ?",
            (body.name,),
        ).fetchone()
        if existing:
            if existing["status"] == "running":
                raise HTTPException(status_code=409, detail="Discovery already running for this company")
            conn.execute(
                "UPDATE companies SET status = 'running', last_run_at = datetime('now'), seed_domain = ? WHERE id = ?",
                (body.seed_domain, existing["id"]),
            )
            company_id = existing["id"]
        else:
            company_id = conn.execute(
                "INSERT INTO companies (name, seed_domain, status, last_run_at) VALUES (?, ?, 'running', datetime('now'))",
                (body.name, body.seed_domain),
            ).lastrowid

    r.incr(f"company:{company_id}:pending_jobs")
    enqueue(r, "company_intel", {
        "company_id": company_id,
        "name": body.name,
        "seed_domain": body.seed_domain,
    })
    with db_conn() as conn:
        row = conn.execute("SELECT * FROM companies WHERE id = ?", (company_id,)).fetchone()
    return dict(row)
```

- [ ] **Step 5: Update `get_company` to include trust breakdown**

Find the `get_company` function (around line 1389). Replace the `domain_counts` building logic:

Find:
```python
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
```

Replace with:
```python
        counts = conn.execute(
            """
            SELECT status, COUNT(*) AS cnt
            FROM discovered_domains
            WHERE company_id = ?
            GROUP BY status
            """,
            (company_id,),
        ).fetchall()

        trust_counts = conn.execute(
            """
            SELECT trust_score, COUNT(*) AS cnt
            FROM discovered_domains
            WHERE company_id = ? AND status = 'pending'
            GROUP BY trust_score
            """,
            (company_id,),
        ).fetchall()

    domain_counts = {"pending": 0, "approved": 0, "rejected": 0}
    for row in counts:
        domain_counts[row["status"]] = row["cnt"]

    pending_by_trust = {"high": 0, "medium": 0, "low": 0}
    _trust_labels = {3: "high", 2: "medium", 1: "low"}
    for row in trust_counts:
        label = _trust_labels.get(row["trust_score"], "low")
        pending_by_trust[label] = row["cnt"]
    domain_counts["pending_by_trust"] = pending_by_trust
```

- [ ] **Step 6: Update `list_pending_domains` to support trust filter**

Find the `list_pending_domains` function (around line 1447) and replace it with:

```python
@app.get("/companies/{company_id}/pending")
def list_pending_domains(
    company_id: int,
    limit: int = Query(default=200, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    trust: Optional[int] = Query(default=None, ge=1, le=3),
):
    with db_conn() as conn:
        company = conn.execute("SELECT id FROM companies WHERE id = ?", (company_id,)).fetchone()
        if not company:
            raise HTTPException(status_code=404, detail="Company not found")
        if trust is not None:
            rows = conn.execute(
                """
                SELECT id, domain, ip, source_asn, source, trust_score, trust_signals, status, created_at
                FROM discovered_domains
                WHERE company_id = ? AND status = 'pending' AND trust_score = ?
                ORDER BY domain
                LIMIT ? OFFSET ?
                """,
                (company_id, trust, limit, offset),
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT id, domain, ip, source_asn, source, trust_score, trust_signals, status, created_at
                FROM discovered_domains
                WHERE company_id = ? AND status = 'pending'
                ORDER BY trust_score DESC, domain
                LIMIT ? OFFSET ?
                """,
                (company_id, limit, offset),
            ).fetchall()
    return [dict(r) for r in rows]
```

- [ ] **Step 7: Update `_resolve_domain_ids` to handle `min_trust`**

Find the `_resolve_domain_ids` function (around line 1471) and replace it with:

```python
def _resolve_domain_ids(conn, company_id: int, body: DomainActionRequest) -> list[int]:
    if body.min_trust is not None:
        rows = conn.execute(
            "SELECT id FROM discovered_domains WHERE company_id = ? AND status = 'pending' AND trust_score >= ?",
            (company_id, body.min_trust),
        ).fetchall()
        return [r["id"] for r in rows]
    if body.all:
        rows = conn.execute(
            "SELECT id FROM discovered_domains WHERE company_id = ? AND status = 'pending'",
            (company_id,),
        ).fetchall()
        return [r["id"] for r in rows]
    if body.domain_ids:
        return body.domain_ids
    raise HTTPException(status_code=400, detail="Provide domain_ids, all=true, or min_trust")
```

- [ ] **Step 8: Update `rediscover_company` to use new payload format**

Find the `rediscover_company` function (around line 1432) and replace the enqueue call:

Find:
```python
    enqueue(get_r(), "company_intel", {"company_id": company_id, "org": company["name"]})
```
Replace with:
```python
    r = get_r()
    r.incr(f"company:{company_id}:pending_jobs")
    enqueue(r, "company_intel", {
        "company_id": company_id,
        "name": company["name"],
        "seed_domain": company["seed_domain"] if "seed_domain" in company.keys() else None,
    })
```

- [ ] **Step 9: Run the new tests — they should now pass**

```bash
cd C:\Users\Mathias\Documents\pi
python -m pytest ingestor/tests/test_api_dashboard_v2.py -k "seed_domain or trust or min_trust or new_payload" -v
```
Expected: all new tests pass.

- [ ] **Step 10: Run full test suite — no regressions**

```bash
cd C:\Users\Mathias\Documents\pi
python -m pytest ingestor/tests/ -v
```
Expected: all tests pass.

- [ ] **Step 11: Commit**

```bash
rtk git add ingestor/app.py ingestor/tests/test_api_dashboard_v2.py
rtk git commit -m "feat: update company API — seed_domain, trust filter, min_trust approve, new payload format"
```

---

## Task 7: UI Changes

**Files:**
- Modify: `ingestor/static/companies.html`

- [ ] **Step 1: Add seed domain input to the Add Company form**

Find in `companies.html`:
```html
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
```
Replace with:
```html
            <form id="add-company-form" class="inline-form">
              <div class="inline-form-grid" style="grid-template-columns: 1fr 1fr auto;">
                <label>
                  Company name
                  <input id="company-name-input" placeholder="e.g. Kering" required>
                </label>
                <label>
                  Seed domain <small style="opacity:.6">(optional but recommended)</small>
                  <input id="company-seed-input" placeholder="e.g. kering.com" type="text">
                </label>
                <label style="align-self:end">
                  &nbsp;
                  <button type="submit" class="compact">Discover</button>
                </label>
              </div>
            </form>
```

- [ ] **Step 2: Pass seed_domain in the form submit handler**

Find in `companies.html`:
```javascript
    $('add-company-form').addEventListener('submit', async e => {
      e.preventDefault();
      const name = $('company-name-input').value.trim();
      if (!name) return;
      const resp = await fetch(`${API}/companies`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name }),
      });
```
Replace with:
```javascript
    $('add-company-form').addEventListener('submit', async e => {
      e.preventDefault();
      const name = $('company-name-input').value.trim();
      if (!name) return;
      const seed = $('company-seed-input').value.trim() || null;
      const resp = await fetch(`${API}/companies`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, seed_domain: seed }),
      });
```

- [ ] **Step 3: Add trust filter tabs and "Approve all HIGH" button**

Find in `companies.html`:
```html
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:0.75rem">
            <h2 style="margin:0">Pending Review (<span id="pending-count">0</span>)</h2>
            <div style="display:flex;gap:0.5rem">
              <button id="approve-selected-btn" class="compact" disabled>Approve selected</button>
              <button id="reject-selected-btn" class="secondary compact" disabled>Reject selected</button>
              <button id="approve-all-btn" class="compact">Approve all</button>
            </div>
          </div>
```
Replace with:
```html
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:0.75rem">
            <h2 style="margin:0">Pending Review (<span id="pending-count">0</span>)</h2>
            <div style="display:flex;gap:0.5rem">
              <button id="approve-selected-btn" class="compact" disabled>Approve selected</button>
              <button id="reject-selected-btn" class="secondary compact" disabled>Reject selected</button>
              <button id="approve-high-btn" class="compact">Approve all HIGH</button>
              <button id="approve-all-btn" class="secondary compact">Approve all</button>
            </div>
          </div>
          <div style="display:flex;gap:0.5rem;margin-bottom:0.75rem">
            <button class="trust-filter-btn compact secondary is-active" data-trust="">All</button>
            <button class="trust-filter-btn compact" data-trust="3" style="color:#22c55e">HIGH</button>
            <button class="trust-filter-btn compact" data-trust="2" style="color:#f59e0b">MEDIUM</button>
            <button class="trust-filter-btn compact" data-trust="1" style="color:#ef4444">LOW</button>
          </div>
```

- [ ] **Step 4: Add Trust column to pending table header**

Find:
```html
              <tr>
                <th><input type="checkbox" id="select-all-checkbox"></th>
                <th>Domain</th>
                <th>IP</th>
                <th>Source ASN</th>
              </tr>
```
Replace with:
```html
              <tr>
                <th><input type="checkbox" id="select-all-checkbox"></th>
                <th>Domain</th>
                <th>Trust</th>
                <th>IP</th>
                <th>Source</th>
              </tr>
```

- [ ] **Step 5: Add trust variable and filter logic to the JS**

Find in the JS:
```javascript
    const $ = id => document.getElementById(id);
    let currentCompanyId = null;
    let pollTimer = null;
```
Replace with:
```javascript
    const $ = id => document.getElementById(id);
    let currentCompanyId = null;
    let pollTimer = null;
    let activeTrustFilter = '';

    const TRUST_LABELS = { 3: 'HIGH', 2: 'MEDIUM', 1: 'LOW' };
    const TRUST_COLORS = { 3: '#22c55e', 2: '#f59e0b', 1: '#ef4444' };
    function trustBadge(score) {
      const label = TRUST_LABELS[score] || 'LOW';
      const color = TRUST_COLORS[score] || '#ef4444';
      return `<span style="color:${color};font-weight:600;font-size:.8rem" title="${trustSignalsTitle(score)}">${label}</span>`;
    }
    function trustSignalsTitle(score) {
      return { 3: 'cert org match or seed subdomain', 2: 'name similarity or 1-hop pivot', 1: 'low confidence / 2-hop pivot' }[score] || '';
    }
```

- [ ] **Step 6: Update the pending table render to include trust column and filter**

Find the pending table rendering code:
```javascript
      if (pending.length) {
        pendTbody.innerHTML = pending.map(d => `
          <tr data-id="${d.id}">
            <td><input type="checkbox" class="row-check" data-id="${d.id}"></td>
            <td>${d.domain}</td>
            <td>${d.ip || '—'}</td>
            <td>${d.source_asn ? 'AS' + d.source_asn : '—'}</td>
          </tr>
        `).join('');
```
Replace with:
```javascript
      if (pending.length) {
        pendTbody.innerHTML = pending.map(d => `
          <tr data-id="${d.id}">
            <td><input type="checkbox" class="row-check" data-id="${d.id}"></td>
            <td>${d.domain}</td>
            <td>${trustBadge(d.trust_score)}</td>
            <td>${d.ip || '—'}</td>
            <td>${d.source || '—'}</td>
          </tr>
        `).join('');
```

- [ ] **Step 7: Update `refreshDetail` fetch to include trust filter**

Find in `refreshDetail`:
```javascript
      const [compResp, pendResp] = await Promise.all([
        fetch(`${API}/companies/${currentCompanyId}`),
        fetch(`${API}/companies/${currentCompanyId}/pending?limit=500`),
      ]);
```
Replace with:
```javascript
      const trustParam = activeTrustFilter ? `&trust=${activeTrustFilter}` : '';
      const [compResp, pendResp] = await Promise.all([
        fetch(`${API}/companies/${currentCompanyId}`),
        fetch(`${API}/companies/${currentCompanyId}/pending?limit=500${trustParam}`),
      ]);
```

- [ ] **Step 8: Wire up trust filter tab buttons and "Approve all HIGH"**

Find:
```javascript
    $('approve-selected-btn').addEventListener('click', () => doAction('approve', { domain_ids: getSelectedIds() }));
    $('reject-selected-btn').addEventListener('click', () => doAction('reject', { domain_ids: getSelectedIds() }));
    $('approve-all-btn').addEventListener('click', () => doAction('approve', { all: true }));
```
Replace with:
```javascript
    $('approve-selected-btn').addEventListener('click', () => doAction('approve', { domain_ids: getSelectedIds() }));
    $('reject-selected-btn').addEventListener('click', () => doAction('reject', { domain_ids: getSelectedIds() }));
    $('approve-high-btn').addEventListener('click', () => doAction('approve', { min_trust: 3 }));
    $('approve-all-btn').addEventListener('click', () => doAction('approve', { all: true }));

    document.addEventListener('click', e => {
      const btn = e.target.closest('.trust-filter-btn');
      if (!btn) return;
      document.querySelectorAll('.trust-filter-btn').forEach(b => b.classList.remove('is-active'));
      btn.classList.add('is-active');
      activeTrustFilter = btn.dataset.trust;
      refreshDetail();
    });
```

- [ ] **Step 9: Commit**

```bash
rtk git add ingestor/static/companies.html
rtk git commit -m "feat: update companies UI — seed domain input, trust column, filter tabs, Approve all HIGH"
```

---

## Task 8: Final Verification

- [ ] **Step 1: Run full test suite**

```bash
cd C:\Users\Mathias\Documents\pi
python -m pytest ingestor/tests/ workers/intel/tests/ -v
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

- [ ] **Step 3: Smoke test**

Open `http://192.168.1.191:8090/ui/companies.html` in the browser.

- Submit `"Kering"` with seed domain `"kering.com"` — verify it appears with status `running`
- Open the company detail — verify ASNs, pending review sections render
- Check Ops page DLQ panel — verify `company_intel_crt`, `company_intel_pivot`, `company_intel_ripestat` appear (replacing `company_intel_asn`)
- After discovery completes: verify domains appear with trust badges (HIGH/MEDIUM/LOW)
- Click "Approve all HIGH" — verify only HIGH-trust domains are approved and appear in targets
