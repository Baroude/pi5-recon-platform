"""
Nuclei worker
=============
Consumes: scan_http     payload: {"url": "https://sub.example.com",
                                   "endpoint_id": 42}
Produces: notify_finding payload: {"notification_type": "new_finding",
                                    "finding_id": 123}

Workflow
--------
1. Dequeue scan_http task.
2. TTL check — skip recently scanned URLs.
3. Run nuclei with curated severity filter and templates dir.
4. Stream JSONL output line-by-line; deduplicate and persist each finding
   immediately so notify_finding is enqueued as soon as nuclei fires.
5. Ack task.

A background thread re-runs `nuclei -update-templates` on the configured
interval so templates stay current without a container restart.
"""

import hashlib
import json
import logging
import os
import subprocess
import sys
import threading
import time
from datetime import datetime
from urllib.parse import urlparse

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
QUEUE        = "scan_http"
PROCESSING   = "scan_http:processing"
NOTIFY_QUEUE = "notify_finding"
WORKER_NAME  = "worker-nuclei"

MAX_RETRIES           = int(os.environ.get("MAX_RETRIES", 2))
NUCLEI_INTERVAL_HOURS = float(os.environ.get("DEFAULT_NUCLEI_INTERVAL_HOURS", 24))
TEMPLATES_DIR         = os.environ.get("NUCLEI_TEMPLATES_DIR", "/templates")
SEVERITY_MIN          = os.environ.get("NUCLEI_SEVERITY_MIN", "medium")
MAX_CONCURRENCY       = int(os.environ.get("MAX_NUCLEI_CONCURRENCY", 1))
OUTPUT_DIR            = os.environ.get("OUTPUT_DIR", "/data/output")
TEMPLATE_UPDATE_HOURS = float(os.environ.get("NUCLEI_TEMPLATES_UPDATE_INTERVAL_HOURS", 24))
NUCLEI_THROTTLE_SECS  = int(os.environ.get("NUCLEI_THROTTLE_SECS", 30))
NUCLEI_PROC_TIMEOUT   = int(os.environ.get("NUCLEI_PROC_TIMEOUT", 1800))

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("/logs/worker-nuclei.log"),
    ],
)
logger = logging.getLogger(WORKER_NAME)

# ---------------------------------------------------------------------------

def severity_meets_threshold(severity: str) -> bool:
    return SEVERITY_ORDER.get(severity.lower(), -1) >= SEVERITY_ORDER.get(SEVERITY_MIN.lower(), 2)


def _dedupe_key(template_id: str, url: str) -> str:
    raw = f"{template_id}|{url}"
    return hashlib.sha1(raw.encode()).hexdigest()


def _process_finding(r: redis_lib.Redis, finding: dict, endpoint_id: int, output_file: str) -> None:
    """Persist one nuclei finding and enqueue notify_finding if new and above threshold."""
    template_id = finding.get("template-id", "")
    info        = finding.get("info", {})
    severity    = info.get("severity", "info").lower()
    title       = info.get("name", template_id)
    matched_at  = finding.get("matched-at", "")
    dedupe_key  = _dedupe_key(template_id, matched_at or "")

    with db_conn() as conn:
        existing = conn.execute(
            "SELECT id FROM findings WHERE dedupe_key = ?",
            (dedupe_key,),
        ).fetchone()

        if existing:
            conn.execute(
                "UPDATE findings SET last_seen = datetime('now') WHERE id = ?",
                (existing["id"],),
            )
            return

        finding_id = conn.execute(
            """INSERT INTO findings
               (endpoint_id, template_id, severity, title, matched_at,
                raw_blob_path, dedupe_key)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (endpoint_id, template_id, severity, title, matched_at,
             output_file, dedupe_key),
        ).lastrowid

    if severity_meets_threshold(severity):
        enqueue(r, NOTIFY_QUEUE, {
            "notification_type": "new_finding",
            "finding_id": finding_id,
        })
        logger.info("Finding enqueued for notify: [%s] %s", severity.upper(), title)


def process_task(r: redis_lib.Redis, task: dict) -> None:
    url         = task.get("url")
    endpoint_id = task.get("endpoint_id")
    if not url or not endpoint_id:
        raise ValueError(f"Missing url or endpoint_id: {task}")

    cleanup_old_outputs(OUTPUT_DIR, "nuclei_*.jsonl")
    logger.info("Scanning %s", url)

    with db_conn() as conn:
        scope_row = conn.execute(
            """SELECT t.scope_root
               FROM endpoints e
               JOIN subdomains s ON s.id = e.subdomain_id
               JOIN targets   t ON t.id = s.target_id
               WHERE e.id = ?""",
            (endpoint_id,),
        ).fetchone()

    scope_root = scope_row["scope_root"] if scope_row else ""

    if scope_root:
        parsed_host = urlparse(url).hostname or ""
        if not is_in_scope(parsed_host, scope_root):
            logger.warning(
                "nuclei: out-of-scope endpoint skipped — host=%s scope=%s",
                parsed_host, scope_root,
            )
            return

    if scope_root and NUCLEI_THROTTLE_SECS > 0:
        throttle_key = f"throttle:nuclei:{scope_root}"
        ttl = r.ttl(throttle_key)
        if ttl > 0:
            logger.info(
                "nuclei throttle: waiting %ds before scanning %s (scope=%s)",
                ttl, url, scope_root,
            )
            time.sleep(ttl)

    with db_conn() as conn:
        recent = conn.execute(
            "SELECT last_scanned_at FROM endpoints WHERE id = ? AND last_scanned_at > datetime('now', ? || ' hours')",
            (endpoint_id, f"-{NUCLEI_INTERVAL_HOURS}"),
        ).fetchone()
        if recent:
            logger.info("Skipping %s — scanned recently", url)
            return

    with db_conn() as conn:
        job_id = conn.execute(
            """INSERT INTO jobs (type, target_ref, status, started_at, worker_name)
               VALUES ('scan_http', ?, 'running', datetime('now'), ?)""",
            (url, WORKER_NAME),
        ).lastrowid

    host = urlparse(url).hostname or url.split("//")[-1].split("/")[0]
    out_dir = os.path.join(OUTPUT_DIR, "nuclei", host)
    os.makedirs(out_dir, exist_ok=True)
    ts = datetime.utcnow().strftime("%Y%m%dT%H%M%S")
    output_file = os.path.join(out_dir, f"nuclei_{ts}.jsonl")

    sev_names = [k for k, v in SEVERITY_ORDER.items()
                 if v >= SEVERITY_ORDER.get(SEVERITY_MIN.lower(), 2)]
    severity_arg = ",".join(sev_names)

    cmd = [
        "nuclei",
        "-u", url,
        "-t", TEMPLATES_DIR,
        "-severity", severity_arg,
        "-jsonl",
        "-silent",
        "-no-color",
        "-rate-limit", "10",
        "-bulk-size", "25",
        "-c", str(MAX_CONCURRENCY),
        "-timeout", "15",
        "-retries", "1",
    ]

    findings_count = 0
    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        with open(output_file, "w") as fh:
            for line in proc.stdout:
                line = line.strip()
                if not line:
                    continue
                fh.write(line + "\n")
                try:
                    finding = json.loads(line)
                except json.JSONDecodeError:
                    logger.debug("Non-JSON stdout line from nuclei: %s", line[:120])
                    continue
                _process_finding(r, finding, endpoint_id, output_file)
                findings_count += 1

        try:
            proc.wait(timeout=NUCLEI_PROC_TIMEOUT)
        except subprocess.TimeoutExpired:
            proc.kill()
            logger.error("nuclei process timeout exceeded for %s — killed", url)

    except Exception:
        with db_conn() as conn:
            conn.execute(
                "UPDATE jobs SET status = 'failed', finished_at = datetime('now') WHERE id = ?",
                (job_id,),
            )
        raise

    logger.info("nuclei: %d finding(s) for %s", findings_count, url)

    with db_conn() as conn:
        conn.execute(
            "UPDATE endpoints SET last_scanned_at = datetime('now') WHERE id = ?",
            (endpoint_id,),
        )
        conn.execute(
            """UPDATE jobs SET status = 'done', finished_at = datetime('now'),
               raw_output_path = ? WHERE id = ?""",
            (output_file, job_id),
        )

    if scope_root and NUCLEI_THROTTLE_SECS > 0:
        r.set(f"throttle:nuclei:{scope_root}", "1", ex=NUCLEI_THROTTLE_SECS)

    logger.info("Scan complete for %s", url)


def record_failed_job(task: dict, reason: str) -> None:
    with db_conn() as conn:
        conn.execute(
            """INSERT INTO failed_jobs (type, target_ref, payload, failure_reason, retry_count)
               VALUES ('scan_http', ?, ?, ?, ?)""",
            (task.get("url"), json.dumps(task), reason, task.get("retry_count", 0)),
        )


def _template_updater_loop():
    """Background thread: refresh templates immediately, then on the configured interval."""
    interval_secs = TEMPLATE_UPDATE_HOURS * 3600
    while True:
        logger.info("Updating Nuclei templates...")
        try:
            subprocess.run(
                ["nuclei", "-update-templates", "-ud", TEMPLATES_DIR, "-silent"],
                timeout=300,
            )
            logger.info("Template update complete")
        except Exception as exc:
            logger.error("Template update failed: %s", exc)
        time.sleep(interval_secs)


def main():
    logger.info("Nuclei worker starting")
    try:
        v = subprocess.run(["nuclei", "-version"], capture_output=True, text=True, timeout=10)
        logger.info(v.stdout.strip() or v.stderr.strip())
    except Exception as exc:
        logger.warning("Could not get nuclei version: %s", exc)

    r = wait_for_redis()
    init_db()
    recover_processing_queue(r, QUEUE, PROCESSING)

    t = threading.Thread(target=_template_updater_loop, daemon=True)
    t.start()

    logger.info("Listening on queue: %s", NOTIFY_QUEUE)

    while True:
        try:
            task = dequeue_blocking(r, QUEUE, PROCESSING, timeout=30)
            if task is None:
                continue

            try:
                process_task(r, task)
                ack_task(r, PROCESSING, task)
            except Exception as exc:
                logger.error("Task failed: %s — %s", task.get("url"), exc, exc_info=True)
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
