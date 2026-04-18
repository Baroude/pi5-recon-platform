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
import threading
import time
from datetime import datetime
from urllib.parse import urlparse, urlunparse

import redis as redis_lib

sys.path.insert(0, "/app")
from common.cleanup import cleanup_old_outputs
from common.db import db_conn, init_db
from common.queue import (
    ack_task,
    dequeue_blocking,
    enqueue,
    nack_task,
    recover_processing_queue,
    wait_for_redis,
)
from common.scope import is_in_scope

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

_DEFAULT_PORTS = {"http": 80, "https": 443}


def _normalize_url(raw_url: str) -> str:
    """
    Canonicalize a URL so that the same logical endpoint always maps to one key:
    - lower-case the host
    - strip default ports (:80 for http, :443 for https)
    - strip a bare trailing slash from the path (but keep /path/)
    """
    try:
        p = urlparse(raw_url)
        host = p.hostname or ""
        port = p.port
        scheme = p.scheme.lower()
        if port and port == _DEFAULT_PORTS.get(scheme):
            netloc = host
        elif port:
            netloc = f"{host}:{port}"
        else:
            netloc = host
        path = p.path.rstrip("/") or "/"
        # strip the trailing slash only for the root path
        if path == "/":
            path = ""
        return urlunparse((scheme, netloc, path, p.params, p.query, ""))
    except Exception:
        return raw_url


def _content_hash(record: dict) -> str:
    """Stable fingerprint for an httpx result — changes = changed endpoint."""
    sig = f"{record.get('status_code')}|{record.get('title')}|{record.get('webserver')}"
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
        "-max-redirects", "1",
        "-threads", str(MAX_CONCURRENCY),
        "-timeout", "10",
        "-retries", "1",
        "-no-color",
    ]

    logger.info("httpx: %s", hostname)
    proc = None

    def _pump_output(stream) -> None:
        if stream is None:
            return
        for raw_line in iter(stream.readline, ""):
            line = raw_line.rstrip("\n")
            if not line.strip():
                continue
            logger.info("%s", line)

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        output_thread = threading.Thread(target=_pump_output, args=(proc.stdout,), daemon=True)
        output_thread.start()
        try:
            proc.wait(timeout=120)
        except subprocess.TimeoutExpired:
            logger.error("httpx timed out for %s", hostname)
            proc.kill()
            output_thread.join(timeout=5)
            return []
        output_thread.join(timeout=5)
    except FileNotFoundError:
        logger.error("httpx binary not found for %s", hostname)
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
    hostname   = task.get("hostname")
    target_id  = task.get("target_id")
    scope_root = task.get("scope_root", "")
    if not hostname or not target_id:
        raise ValueError(f"Missing hostname or target_id: {task}")

    cleanup_old_outputs(OUTPUT_DIR, "httpx_*.jsonl")
    logger.info("Probing %s", hostname)

    # Resolve subdomain_id from DB; insert if not yet committed by recon worker.
    with db_conn() as conn:
        sub_row = conn.execute(
            "SELECT id FROM subdomains WHERE target_id = ? AND hostname = ?",
            (target_id, hostname),
        ).fetchone()

        if not sub_row:
            # Recon worker hasn't committed yet — insert so this worker is self-sufficient.
            conn.execute(
                "INSERT OR IGNORE INTO subdomains (target_id, hostname, source) VALUES (?, ?, 'httpx')",
                (target_id, hostname),
            )
            sub_row = conn.execute(
                "SELECT id FROM subdomains WHERE target_id = ? AND hostname = ?",
                (target_id, hostname),
            ).fetchone()
            if not sub_row:
                raise ValueError(f"Subdomain not found in DB: {hostname}")

        subdomain_id = sub_row["id"]

    with db_conn() as conn:
        job_id = conn.execute(
            """INSERT INTO jobs (type, target_ref, status, started_at, worker_name)
               VALUES ('probe_host', ?, 'running', datetime('now'), ?)""",
            (hostname, WORKER_NAME),
        ).lastrowid

    out_dir = os.path.join(OUTPUT_DIR, "httpx", hostname)
    os.makedirs(out_dir, exist_ok=True)
    ts = datetime.utcnow().strftime("%Y%m%dT%H%M%S")
    output_file = os.path.join(out_dir, f"httpx_{ts}.jsonl")

    try:
        records = run_httpx(hostname, output_file)
        logger.info("httpx: %d results for %s", len(records), hostname)

    except Exception:
        with db_conn() as conn:
            conn.execute(
                "UPDATE jobs SET status = 'failed', finished_at = datetime('now') WHERE id = ?",
                (job_id,),
            )
        raise

    with db_conn() as conn:
        for rec in records:
            url         = _normalize_url(rec.get("url", ""))
            status_code = rec.get("status_code")
            alive       = bool(url and status_code and 100 <= int(status_code) < 600)

            if not url:
                continue

            # Scope guard: reject endpoints that redirected outside the authorised root.
            if scope_root:
                parsed_host = urlparse(url).hostname or ""
                if not is_in_scope(parsed_host, scope_root):
                    logger.warning(
                        "httpx: out-of-scope endpoint skipped — host=%s scope=%s",
                        parsed_host, scope_root,
                    )
                    continue

            tech       = json.dumps(rec.get("tech") or rec.get("technologies") or [])
            title      = rec.get("title", "")
            scheme     = rec.get("scheme", "")
            port       = rec.get("port")
            chash      = _content_hash(rec)

            existing = conn.execute(
                """SELECT id, content_hash, alive,
                          (last_seen > datetime('now', ? || ' hours')) AS fresh
                   FROM endpoints WHERE url = ?""",
                (f"-{HTTPX_INTERVAL_HOURS}", url),
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
                # Re-scan if content changed or TTL has expired for this specific URL
                if alive and (changed or not existing["fresh"]):
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

    with db_conn() as conn:
        conn.execute(
            """UPDATE jobs SET status = 'done', finished_at = datetime('now'),
               raw_output_path = ? WHERE id = ?""",
            (output_file, job_id),
        )

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
