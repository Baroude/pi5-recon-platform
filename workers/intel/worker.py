"""
Intel worker
============
Consumes two queues in two threads:

  company_intel     payload: {"company_id": 1, "org": "Kering"}
  company_intel_asn payload: {"company_id": 1, "asn": "12345", "asn_index": 0, "total_asns": 3}

Pass 1 (company_intel):
  amass intel -org "<org>" -timeout N
  -> parse ASN lines -> upsert discovered_asns -> enqueue company_intel_asn per ASN
  -> if 0 ASNs found: set company.status = 'done'

Pass 2 (company_intel_asn):
  amass intel -asn <N> -whois -ip -timeout N
  -> parse domain+IP lines -> insert discovered_domains (status=pending)
  -> when no ASN jobs remain for this company: set company.status = 'done'
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
    enqueue,
    nack_task,
    recover_processing_queue,
    wait_for_redis,
)

QUEUE_PASS1 = "company_intel"
PROCESSING_PASS1 = "company_intel:processing"
QUEUE_PASS2 = "company_intel_asn"
PROCESSING_PASS2 = "company_intel_asn:processing"
WORKER_NAME = "worker-intel"

MAX_RETRIES = int(os.environ.get("MAX_RETRIES", 2))
TIMEOUT_MINUTES = int(os.environ.get("INTEL_TIMEOUT_MINUTES", 10))

# Pass 1 output format (common case): "12345, EXAMPLE-NET -- Example Corp"
_ASN_RE = re.compile(r"^(\d+),\s*(.+)$")
_ASN_PREFIX_RE = re.compile(
    r"^(?:AS|ASN)\s*[:#]?\s*(\d{1,10})\b(?:\s*[-,:]\s*(.+))?$",
    re.IGNORECASE,
)
_ASN_INLINE_RE = re.compile(r"\b(?:AS|ASN)\s*[:#]?\s*(\d{1,10})\b", re.IGNORECASE)
# Pass 2 output format (common case): "example.com 1.2.3.4" or "example.com"
_DOMAIN_RE = re.compile(
    r"^([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+)"
    r"(?:\s+(\d{1,3}(?:\.\d{1,3}){3}))?",
    re.IGNORECASE,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
    handlers=[logging.StreamHandler()],
)
logger = logging.getLogger(WORKER_NAME)

_LOG_DIR = os.environ.get("LOG_DIR", "/logs")
if not os.path.isdir(_LOG_DIR):
    _LOG_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "logs"))
os.makedirs(_LOG_DIR, exist_ok=True)
logger.addHandler(logging.FileHandler(os.path.join(_LOG_DIR, "worker-intel.log")))


def _run_amass(cmd: list[str]) -> list[str]:
    """Run amass command and return non-empty stdout lines."""
    logger.info("Running: %s", " ".join(cmd))
    lines: list[str] = []
    line_lock = threading.Lock()

    def _pump_stream(stream) -> None:
        if stream is None:
            return
        for raw_line in iter(stream.readline, ""):
            line = raw_line.strip()
            if not line:
                continue
            logger.info("%s", line)
            with line_lock:
                lines.append(line)

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        stdout_thread = threading.Thread(target=_pump_stream, args=(proc.stdout,), daemon=True)
        stderr_thread = threading.Thread(target=_pump_stream, args=(proc.stderr,), daemon=True)
        stdout_thread.start()
        stderr_thread.start()

        try:
            proc.wait(timeout=TIMEOUT_MINUTES * 60 + 30)
        except subprocess.TimeoutExpired:
            logger.error("amass timed out after %d minute(s)", TIMEOUT_MINUTES)
            proc.kill()
            stdout_thread.join(timeout=5)
            stderr_thread.join(timeout=5)
            return []

        stdout_thread.join(timeout=5)
        stderr_thread.join(timeout=5)
    except FileNotFoundError:
        logger.error("amass binary not found")
        return []

    if proc.returncode not in (0, 1):
        logger.warning("amass exited %d", proc.returncode)
    return lines


def _extract_asn_record(line: str) -> tuple[str, str] | None:
    """
    Best-effort ASN parsing across multiple amass output formats.
    Returns (asn, description) when recognized.
    """
    cleaned = " ".join(line.split())
    if not cleaned:
        return None

    # Common format: "12345, ORG -- Description"
    comma_match = _ASN_RE.match(cleaned)
    if comma_match:
        asn = comma_match.group(1).strip()
        description = comma_match.group(2).strip() or f"AS{asn}"
        return asn, description

    # Prefix formats: "AS12345 - Desc", "ASN: 12345", "ASN 12345, Desc"
    prefix_match = _ASN_PREFIX_RE.match(cleaned)
    if prefix_match:
        asn = prefix_match.group(1).strip()
        description = (prefix_match.group(2) or "").strip() or f"AS{asn}"
        return asn, description

    # Inline fallback: "... ASN 12345 ..."
    inline_match = _ASN_INLINE_RE.search(cleaned)
    if inline_match:
        asn = inline_match.group(1).strip()
        return asn, cleaned

    return None


def _set_company_status(company_id: int, status: str) -> None:
    with db_conn() as conn:
        conn.execute(
            "UPDATE companies SET status = ? WHERE id = ?",
            (status, company_id),
        )


def _company_has_remaining_asn_tasks(
    r: redis_lib.Redis,
    company_id: int,
    current_raw: str | None,
) -> bool:
    """True when company still has pending or processing ASN tasks."""
    for queue_name in (QUEUE_PASS2, PROCESSING_PASS2):
        raw_items = r.lrange(queue_name, 0, -1)
        for raw in raw_items:
            raw_text = raw if isinstance(raw, str) else raw.decode("utf-8", errors="replace")
            if current_raw and raw_text == current_raw:
                continue
            try:
                payload = json.loads(raw_text)
            except Exception:
                continue
            if payload.get("company_id") == company_id:
                return True
    return False


def handle_pass1(r: redis_lib.Redis, task: dict) -> None:
    company_id = int(task["company_id"])
    org = str(task["org"]).strip()

    if not org:
        raise ValueError("org must not be empty")

    _set_company_status(company_id, "running")

    lines = _run_amass([
        "amass",
        "intel",
        "-whois",
        "-org",
        org,
        "-timeout",
        str(TIMEOUT_MINUTES),
    ])

    asns: list[tuple[str, str]] = []
    seen_asns: set[str] = set()
    for line in lines:
        record = _extract_asn_record(line)
        if not record:
            continue
        asn, description = record
        if asn in seen_asns:
            continue
        seen_asns.add(asn)
        asns.append((asn, description))

        with db_conn() as conn:
            conn.execute(
                """
                INSERT INTO discovered_asns (company_id, asn, description)
                VALUES (?, ?, ?)
                ON CONFLICT(company_id, asn) DO UPDATE SET description = excluded.description
                """,
                (company_id, asn, description),
            )

    if not asns:
        sample = " | ".join(lines[:6]) if lines else "<no output>"
        logger.warning(
            "Company %d: no ASNs found for org=%r (amass lines=%d, sample=%s)",
            company_id,
            org,
            len(lines),
            sample,
        )
        _set_company_status(company_id, "done")
        return

    # enqueue() uses LPUSH; reverse preserves ascending asn_index processing order.
    total = len(asns)
    for asn_index, (asn, _) in reversed(list(enumerate(asns))):
        enqueue(
            r,
            QUEUE_PASS2,
            {
                "company_id": company_id,
                "asn": asn,
                "asn_index": asn_index,
                "total_asns": total,
            },
        )
    logger.info("Company %d: queued %d ASN task(s)", company_id, total)


def handle_pass2(r: redis_lib.Redis, task: dict) -> None:
    company_id = int(task["company_id"])
    asn = str(task["asn"]).strip()
    current_raw = task.get("__raw__")
    if not asn:
        raise ValueError("asn must not be empty")

    lines = _run_amass([
        "amass",
        "intel",
        "-asn",
        asn,
        "-whois",
        "-ip",
        "-timeout",
        str(TIMEOUT_MINUTES),
    ])

    inserted = 0
    for line in lines:
        match = _DOMAIN_RE.match(line)
        if not match:
            continue
        domain = match.group(1).lower()
        ip = match.group(2) if match.group(2) else None

        with db_conn() as conn:
            existing_target = conn.execute(
                "SELECT enabled FROM targets WHERE scope_root = ?",
                (domain,),
            ).fetchone()
            auto_status = "approved" if existing_target and existing_target["enabled"] == 1 else "pending"

            conn.execute(
                """
                INSERT INTO discovered_domains (company_id, domain, ip, source_asn, status)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(company_id, domain) DO UPDATE SET
                    ip = COALESCE(excluded.ip, discovered_domains.ip),
                    source_asn = COALESCE(excluded.source_asn, discovered_domains.source_asn)
                """,
                (company_id, domain, ip, asn, auto_status),
            )
            inserted += 1

    logger.info("Company %d ASN %s: processed %d discovered domain line(s)", company_id, asn, inserted)

    if not _company_has_remaining_asn_tasks(r, company_id, current_raw):
        _set_company_status(company_id, "done")
        logger.info("Company %d: all ASN discovery jobs completed", company_id)


def _mark_company_failed_if_possible(task: dict, exc: Exception) -> None:
    company_id = task.get("company_id")
    if company_id is None:
        return
    try:
        _set_company_status(int(company_id), "failed")
        logger.error("Company %s marked failed: %s", company_id, exc)
    except Exception:
        logger.exception("Could not mark company %s as failed", company_id)


def _worker_loop(queue: str, processing_queue: str, handler) -> None:
    r = wait_for_redis()
    recover_processing_queue(r, queue, processing_queue, max_retries=MAX_RETRIES)
    logger.info("%s listening on %s", WORKER_NAME, queue)

    while True:
        task = dequeue_blocking(r, queue, processing_queue, timeout=30.0)
        if task is None:
            continue
        try:
            handler(r, task)
            ack_task(r, processing_queue, task)
        except Exception as exc:
            logger.exception("Task failed on %s: %s", queue, exc)
            _mark_company_failed_if_possible(task, exc)
            nack_task(r, queue, processing_queue, task, max_retries=MAX_RETRIES)


def main() -> None:
    init_db()

    pass1 = threading.Thread(
        target=_worker_loop,
        args=(QUEUE_PASS1, PROCESSING_PASS1, handle_pass1),
        name="company-intel-pass1",
        daemon=True,
    )
    pass2 = threading.Thread(
        target=_worker_loop,
        args=(QUEUE_PASS2, PROCESSING_PASS2, handle_pass2),
        name="company-intel-pass2",
        daemon=True,
    )
    pass1.start()
    pass2.start()
    logger.info("%s started", WORKER_NAME)

    while True:
        if not pass1.is_alive():
            logger.critical("Pass1 thread stopped; restarting")
            pass1 = threading.Thread(
                target=_worker_loop,
                args=(QUEUE_PASS1, PROCESSING_PASS1, handle_pass1),
                name="company-intel-pass1",
                daemon=True,
            )
            pass1.start()

        if not pass2.is_alive():
            logger.critical("Pass2 thread stopped; restarting")
            pass2 = threading.Thread(
                target=_worker_loop,
                args=(QUEUE_PASS2, PROCESSING_PASS2, handle_pass2),
                name="company-intel-pass2",
                daemon=True,
            )
            pass2.start()
        time.sleep(10)


if __name__ == "__main__":
    main()
