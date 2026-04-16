"""
HTTP worker
===========
Consumes: probe_host   payload: {"hostname": "sub.example.com",
                                  "target_id": 1, "scope_root": "example.com"}
Produces: scan_http    payload: {"url": "https://sub.example.com",
                                  "endpoint_id": 42}
          notify_finding (new_endpoint)

Workflow
--------
1. Dequeue probe_host task.
2. TTL check — skip if probed recently.
3. Run httpx against hostname (both HTTP and HTTPS).
4. Parse JSONL output; upsert endpoints.
5. Enqueue scan_http for new or changed live endpoints.
6. Ack task.
"""

import hashlib
import json
import logging
import os
import subprocess
import sys
import tempfile
import time
from datetime import datetime

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

# ---------------------------------------------------------------------------
QUEUE       = "probe_host"
PROCESSING  = "probe_host:processing"
NEXT_QUEUE  = "scan_http"
WORKER_NAME = "worker-httpx"

MAX_RETRIES          = int(os.environ.get("MAX_RETRIES", 2))
HTTPX_INTERVAL_HOURS = float(os.environ.get("DEFAULT_HTTPX_INTERVAL_HOURS", 12))
MAX_CONCURRENCY      = int(os.environ.get("MAX_HTTPX_CONCURRENCY", 10))
OUTPUT_DIR           = os.environ.get("OUTPUT_DIR", "/data/output")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("/logs/worker-httpx.log"),
    ],
)
logger = logging.getLogger(WORKER_NAME)

# ---------------------------------------------------------------------------

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _content_hash(record: dict) -> str:
    """Stable fingerprint for an httpx result — changes = changed endpoint."""
    sig = f"{record.get('status-code')}|{record.get('title')}|{record.get('webserver')}"
    return hashlib.sha1(sig.encode()).hexdigest()[:12]


def run_httpx(hostname: str, output_file: str) -> list:
    """
    Run the httpx binary against a hostname and return parsed JSON records.
    httpx probes both http:// and https:// by default.
    """
    cmd = [
        "httpx",
        "-u", hostname,
        "-silent",
        "-json",
        "-o", output_file,
        "-status-code",
        "-title",
        "-tech-detect",
        "-follow-redirects",
        "-threads", str(MAX_CONCURRENCY),
        "-timeout", "10",
        "-retries", "1",
        "-no-color",
    ]

    logger.info("httpx: %s", hostname)
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        if proc.returncode not in (0, 1):
            logger.warning("httpx stderr for %s: %s", hostname, proc.stderr[:400])
    except subprocess.TimeoutExpired:
        logger.error("httpx timed out for %s", hostname)
        return []

    if not os.path.exists(output_file):
        return []

    results = []
    with open(output_file) as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                results.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return results


def process_task(r: redis_lib.Redis, task: dict) -> None:
    hostname  = task.get("hostname")
    target_id = task.get("target_id")
    if not hostname or not target_id:
        raise ValueError(f"Missing hostname or target_id: {task}")

    logger.info("Probing %s", hostname)

    # Resolve subdomain_id from DB (may have been inserted by recon worker)
    with db_conn() as conn:
        sub_row = conn.execute(
            "SELECT id FROM subdomains WHERE target_id = ? AND hostname = ?",
            (target_id, hostname),
        ).fetchone()

        if not sub_row:
            # Subdomain not yet in DB (edge case: task arrived before upsert committed)
            time.sleep(2)
            sub_row = conn.execute(
                "SELECT id FROM subdomains WHERE target_id = ? AND hostname = ?",
                (target_id, hostname),
            ).fetchone()
            if not sub_row:
                raise ValueError(f"Subdomain not found in DB: {hostname}")

        subdomain_id = sub_row["id"]

        # TTL check
        recent = conn.execute(
            """SELECT last_seen FROM endpoints
               WHERE subdomain_id = ?
                 AND last_seen > datetime('now', ? || ' hours')
               LIMIT 1""",
            (subdomain_id, f"-{HTTPX_INTERVAL_HOURS}"),
        ).fetchone()
        if recent:
            logger.info("Skipping %s — probed recently", hostname)
            return

    out_dir = os.path.join(OUTPUT_DIR, "httpx", hostname)
    os.makedirs(out_dir, exist_ok=True)
    ts = datetime.utcnow().strftime("%Y%m%dT%H%M%S")
    output_file = os.path.join(out_dir, f"httpx_{ts}.jsonl")

    records = run_httpx(hostname, output_file)
    logger.info("httpx: %d results for %s", len(records), hostname)

    with db_conn() as conn:
        for rec in records:
            url         = rec.get("url", "")
            status_code = rec.get("status-code")
            alive       = bool(url and status_code and 100 <= int(status_code) < 600)

            if not url:
                continue

            tech       = json.dumps(rec.get("tech") or rec.get("technologies") or [])
            title      = rec.get("title", "")
            scheme     = rec.get("scheme", "")
            port       = rec.get("port")
            chash      = _content_hash(rec)

            existing = conn.execute(
                "SELECT id, content_hash, alive FROM endpoints WHERE url = ?",
                (url,),
            ).fetchone()

            if existing:
                changed = (
                    existing["content_hash"] != chash
                    or existing["alive"] != int(alive)
                )
                conn.execute(
                    """UPDATE endpoints
                       SET last_seen = datetime('now'), alive = ?, status_code = ?,
                           title = ?, technologies = ?, content_hash = ?
                       WHERE id = ?""",
                    (int(alive), status_code, title, tech, chash, existing["id"]),
                )
                endpoint_id = existing["id"]
                # Only re-scan if something changed
                if alive and changed:
                    enqueue(r, NEXT_QUEUE, {"url": url, "endpoint_id": endpoint_id})
            else:
                endpoint_id = conn.execute(
                    """INSERT INTO endpoints
                       (subdomain_id, url, scheme, host, port, title,
                        technologies, status_code, content_hash, alive)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (subdomain_id, url, scheme, hostname, port,
                     title, tech, status_code, chash, int(alive)),
                ).lastrowid

                if alive:
                    enqueue(r, NEXT_QUEUE, {"url": url, "endpoint_id": endpoint_id})
                    enqueue(r, "notify_finding", {
                        "notification_type": "new_endpoint",
                        "endpoint_id": endpoint_id,
                        "url": url,
                    })

    logger.info("Probe complete for %s", hostname)


def record_failed_job(task: dict, reason: str) -> None:
    with db_conn() as conn:
        conn.execute(
            """INSERT INTO failed_jobs (type, target_ref, payload, failure_reason, retry_count)
               VALUES ('probe_host', ?, ?, ?, ?)""",
            (task.get("hostname"), json.dumps(task), reason, task.get("retry_count", 0)),
        )


def main():
    logger.info("HTTP worker starting")
    try:
        v = subprocess.run(["httpx", "-version"], capture_output=True, text=True, timeout=10)
        logger.info(v.stdout.strip() or v.stderr.strip())
    except Exception as exc:
        logger.warning("Could not get httpx version: %s", exc)

    r = wait_for_redis()
    init_db()
    recover_processing_queue(r, QUEUE, PROCESSING)

    logger.info("Listening on queue: %s", QUEUE)

    while True:
        try:
            task = dequeue_blocking(r, QUEUE, PROCESSING, timeout=30)
            if task is None:
                continue

            try:
                process_task(r, task)
                ack_task(r, PROCESSING, task)
            except Exception as exc:
                logger.error("Task failed: %s — %s", task.get("hostname"), exc, exc_info=True)
                re_enqueued = nack_task(r, QUEUE, PROCESSING, task, MAX_RETRIES)
                if not re_enqueued:
                    record_failed_job(task, str(exc))

        except redis_lib.ConnectionError as exc:
            logger.error("Redis connection lost: %s", exc)
            time.sleep(5)
            r = wait_for_redis()
        except Exception as exc:
            logger.error("Worker loop error: %s", exc, exc_info=True)
            time.sleep(5)


if __name__ == "__main__":
    main()
