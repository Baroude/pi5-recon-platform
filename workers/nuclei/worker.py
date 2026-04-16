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
4. Parse JSONL output; deduplicate findings on (template_id, matched_at).
5. Enqueue notify_finding for new findings that meet severity threshold.
6. Ack task.

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
QUEUE       = "scan_http"
PROCESSING  = "scan_http:processing"
NOTIFY_QUEUE = "notify_finding"
WORKER_NAME = "worker-nuclei"

MAX_RETRIES           = int(os.environ.get("MAX_RETRIES", 2))
NUCLEI_INTERVAL_HOURS = float(os.environ.get("DEFAULT_NUCLEI_INTERVAL_HOURS", 24))
TEMPLATES_DIR         = os.environ.get("NUCLEI_TEMPLATES_DIR", "/templates")
SEVERITY_MIN          = os.environ.get("NUCLEI_SEVERITY_MIN", "medium")
MAX_CONCURRENCY       = int(os.environ.get("MAX_NUCLEI_CONCURRENCY", 1))
OUTPUT_DIR            = os.environ.get("OUTPUT_DIR", "/data/output")
TEMPLATE_UPDATE_HOURS = float(os.environ.get("NUCLEI_TEMPLATES_UPDATE_INTERVAL_HOURS", 24))

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
    """Stable key: same template fired against the same canonical endpoint URL."""
    raw = f"{template_id}|{url}"
    return hashlib.sha1(raw.encode()).hexdigest()


def run_nuclei(url: str, output_file: str) -> list:
    """Run nuclei against a single URL; return list of parsed findings."""
    # Build severity list: include all severities >= threshold
    sev_names = [k for k, v in SEVERITY_ORDER.items()
                 if v >= SEVERITY_ORDER.get(SEVERITY_MIN.lower(), 2)]
    severity_arg = ",".join(sev_names)

    cmd = [
        "nuclei",
        "-u", url,
        "-t", TEMPLATES_DIR,
        "-severity", severity_arg,
        "-jsonl",
        "-o", output_file,
        "-silent",
        "-no-color",
        "-rate-limit", "10",
        "-bulk-size", "25",
        "-c", str(MAX_CONCURRENCY),
        "-timeout", "15",
        "-retries", "1",
    ]

    logger.info("nuclei: %s (severity>=%s)", url, SEVERITY_MIN)
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
        if proc.returncode not in (0, 1):
            logger.warning("nuclei stderr for %s: %s", url, proc.stderr[:500])
    except subprocess.TimeoutExpired:
        logger.error("nuclei timed out for %s", url)
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
    url         = task.get("url")
    endpoint_id = task.get("endpoint_id")
    if not url or not endpoint_id:
        raise ValueError(f"Missing url or endpoint_id: {task}")

    logger.info("Scanning %s", url)

    with db_conn() as conn:
        # TTL check — use last_scanned_at so clean endpoints aren't rescanned.
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

    host = url.split("//")[-1].split("/")[0]
    out_dir = os.path.join(OUTPUT_DIR, "nuclei", host)
    os.makedirs(out_dir, exist_ok=True)
    ts = datetime.utcnow().strftime("%Y%m%dT%H%M%S")
    output_file = os.path.join(out_dir, f"nuclei_{ts}.jsonl")

    try:
        findings = run_nuclei(url, output_file)
    except Exception:
        with db_conn() as conn:
            conn.execute(
                "UPDATE jobs SET status = 'failed', finished_at = datetime('now') WHERE id = ?",
                (job_id,),
            )
        raise

    logger.info("nuclei: %d finding(s) for %s", len(findings), url)

    with db_conn() as conn:
        for f in findings:
            template_id = f.get("template-id", "")
            info        = f.get("info", {})
            severity    = info.get("severity", "info").lower()
            title       = info.get("name", template_id)
            matched_at  = f.get("matched-at", url)
            # Dedupe on template + canonical endpoint URL (stable across runs).
            # matched_at is stored for reference but kept out of the key because
            # it can vary (query-string order, redirect targets, etc.).
            dedupe_key  = _dedupe_key(template_id, url)

            existing = conn.execute(
                "SELECT id FROM findings WHERE dedupe_key = ?",
                (dedupe_key,),
            ).fetchone()

            if existing:
                conn.execute(
                    "UPDATE findings SET last_seen = datetime('now') WHERE id = ?",
                    (existing["id"],),
                )
                continue

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

    logger.info("Scan complete for %s", url)


def record_failed_job(task: dict, reason: str) -> None:
    with db_conn() as conn:
        conn.execute(
            """INSERT INTO failed_jobs (type, target_ref, payload, failure_reason, retry_count)
               VALUES ('scan_http', ?, ?, ?, ?)""",
            (task.get("url"), json.dumps(task), reason, task.get("retry_count", 0)),
        )


def _template_updater_loop():
    """Background thread: refresh templates on the configured interval."""
    interval_secs = TEMPLATE_UPDATE_HOURS * 3600
    while True:
        time.sleep(interval_secs)
        logger.info("Updating Nuclei templates...")
        try:
            subprocess.run(
                ["nuclei", "-update-templates", "-ud", TEMPLATES_DIR, "-silent"],
                timeout=300,
            )
            logger.info("Template update complete")
        except Exception as exc:
            logger.error("Template update failed: %s", exc)


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

    # Start background template updater
    t = threading.Thread(target=_template_updater_loop, daemon=True)
    t.start()

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
