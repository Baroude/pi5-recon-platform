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
