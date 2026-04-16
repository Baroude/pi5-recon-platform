"""
Recon worker
============
Consumes: recon_domain   payload: {"domain": "example.com"}
Produces: probe_host     payload: {"hostname": "sub.example.com",
                                   "target_id": 1, "scope_root": "example.com"}

Workflow
--------
1. Dequeue task (BLMOVE into processing list).
2. Validate target exists and is enabled.
3. TTL check — skip if already scanned within DEFAULT_RECON_INTERVAL_HOURS.
4. Run subfinder (passive, with optional provider keys).
5. Filter results against scope_root before touching the DB.
6. Upsert subdomains; enqueue probe_host for new ones.
7. Ack task.  On error: nack (retry ×2) or DLQ.
"""

import json
import logging
import os
import subprocess
import sys
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
QUEUE       = "recon_domain"
PROCESSING  = "recon_domain:processing"
NEXT_QUEUE  = "probe_host"
WORKER_NAME = "worker-recon"

MAX_RETRIES          = int(os.environ.get("MAX_RETRIES", 2))
RECON_INTERVAL_HOURS = float(os.environ.get("DEFAULT_RECON_INTERVAL_HOURS", 24))
MAX_CONCURRENCY      = int(os.environ.get("MAX_RECON_CONCURRENCY", 2))
OUTPUT_DIR           = os.environ.get("OUTPUT_DIR", "/data/output")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("/logs/worker-recon.log"),
    ],
)
logger = logging.getLogger(WORKER_NAME)

# ---------------------------------------------------------------------------

def is_in_scope(hostname: str, scope_root: str) -> bool:
    """True if hostname equals or is a subdomain of scope_root."""
    h = hostname.lower().strip()
    s = scope_root.lower().strip().lstrip("*.")
    return h == s or h.endswith(f".{s}")


def run_subfinder(domain: str, output_file: str) -> list:
    cmd = [
        "subfinder",
        "-d", domain,
        "-o", output_file,
        "-silent",
        "-all",
        "-t", str(MAX_CONCURRENCY),
        "-timeout", "30",
    ]
    logger.info("subfinder: %s", domain)
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        if proc.returncode not in (0, 1):   # 1 = no results, still ok
            logger.warning("subfinder stderr for %s: %s", domain, proc.stderr[:500])
    except subprocess.TimeoutExpired:
        logger.error("subfinder timed out for %s", domain)
        return []

    if not os.path.exists(output_file):
        return []

    with open(output_file) as fh:
        return [line.strip() for line in fh if line.strip()]


def run_amass_passive(domain: str, output_file: str) -> list:
    """Run amass in passive-only mode; return list of discovered hostnames."""
    cmd = [
        "amass",
        "enum",
        "-passive",
        "-d", domain,
        "-o", output_file,
        "-silent",
        "-timeout", "10",   # minutes
    ]
    logger.info("amass passive: %s", domain)
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=660)
        if proc.returncode not in (0, 1):
            logger.warning("amass stderr for %s: %s", domain, proc.stderr[:500])
    except subprocess.TimeoutExpired:
        logger.error("amass timed out for %s", domain)
        return []
    except FileNotFoundError:
        logger.warning("amass binary not found — skipping")
        return []

    if not os.path.exists(output_file):
        return []

    with open(output_file) as fh:
        return [line.strip() for line in fh if line.strip()]


def process_task(r: redis_lib.Redis, task: dict) -> None:
    domain = task.get("domain") or task.get("target")
    if not domain:
        raise ValueError(f"Missing domain in task: {task}")

    logger.info("Processing recon for %s", domain)

    with db_conn() as conn:
        row = conn.execute(
            "SELECT id, scope_root FROM targets WHERE scope_root = ? AND enabled = 1",
            (domain,),
        ).fetchone()
        if not row:
            raise ValueError(f"Target not found or disabled: {domain}")

        target_id  = row["id"]
        scope_root = row["scope_root"]

        # TTL check
        stale_threshold = f"-{RECON_INTERVAL_HOURS}"
        recent = conn.execute(
            """SELECT finished_at FROM jobs
               WHERE type = 'recon_domain' AND target_ref = ? AND status = 'done'
                 AND finished_at > datetime('now', ? || ' hours')
               ORDER BY finished_at DESC LIMIT 1""",
            (domain, stale_threshold),
        ).fetchone()
        if recent:
            logger.info("Skipping %s — scanned recently (%s)", domain, recent["finished_at"])
            return

        job_id = conn.execute(
            """INSERT INTO jobs (type, target_ref, status, started_at, worker_name)
               VALUES ('recon_domain', ?, 'running', datetime('now'), ?)""",
            (domain, WORKER_NAME),
        ).lastrowid

    out_dir = os.path.join(OUTPUT_DIR, "recon", domain)
    os.makedirs(out_dir, exist_ok=True)
    ts = datetime.utcnow().strftime("%Y%m%dT%H%M%S")
    output_file = os.path.join(out_dir, f"subfinder_{ts}.txt")
    amass_output_file = os.path.join(out_dir, f"amass_{ts}.txt")

    try:
        subfinder_found = run_subfinder(domain, output_file)
        amass_found     = run_amass_passive(domain, amass_output_file)
        found = list({h for h in subfinder_found + amass_found if h})
        logger.info(
            "recon found %d hosts for %s (subfinder=%d, amass=%d)",
            len(found), domain, len(subfinder_found), len(amass_found),
        )

        new_count = 0
        with db_conn() as conn:
            for hostname in found:
                if not is_in_scope(hostname, scope_root):
                    logger.debug("Out of scope, skipped: %s", hostname)
                    continue

                existing = conn.execute(
                    "SELECT id FROM subdomains WHERE target_id = ? AND hostname = ?",
                    (target_id, hostname),
                ).fetchone()

                if existing:
                    conn.execute(
                        "UPDATE subdomains SET last_seen = datetime('now') WHERE id = ?",
                        (existing["id"],),
                    )
                else:
                    conn.execute(
                        "INSERT INTO subdomains (target_id, hostname, source) VALUES (?, ?, 'subfinder')",
                        (target_id, hostname),
                    )
                    new_count += 1
                    enqueue(r, NEXT_QUEUE, {
                        "hostname":   hostname,
                        "target_id":  target_id,
                        "scope_root": scope_root,
                    })
                    # Notify on new subdomain discovery
                    enqueue(r, "notify_finding", {
                        "notification_type": "new_subdomain",
                        "hostname":   hostname,
                        "scope_root": scope_root,
                    })

            conn.execute(
                """UPDATE jobs
                   SET status = 'done', finished_at = datetime('now'), raw_output_path = ?
                   WHERE id = ?""",
                (output_file, job_id),
            )

        logger.info("Recon done for %s: %d new subdomains", domain, new_count)

    except Exception:
        with db_conn() as conn:
            conn.execute(
                "UPDATE jobs SET status = 'failed', finished_at = datetime('now') WHERE id = ?",
                (job_id,),
            )
        raise


def record_failed_job(task: dict, reason: str) -> None:
    with db_conn() as conn:
        conn.execute(
            """INSERT INTO failed_jobs (type, target_ref, payload, failure_reason, retry_count)
               VALUES ('recon_domain', ?, ?, ?, ?)""",
            (task.get("domain"), json.dumps(task), reason, task.get("retry_count", 0)),
        )


def main():
    logger.info("Recon worker starting")
    for tool in ("subfinder", "amass"):
        try:
            v = subprocess.run([tool, "-version"], capture_output=True, text=True, timeout=10)
            logger.info("%s: %s", tool, v.stdout.strip() or v.stderr.strip())
        except FileNotFoundError:
            logger.warning("%s binary not found", tool)
        except Exception as exc:
            logger.warning("Could not get %s version: %s", tool, exc)

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
                logger.error("Task failed: %s — %s", task.get("domain"), exc, exc_info=True)
                re_enqueued = nack_task(r, QUEUE, PROCESSING, task, MAX_RETRIES)
                if not re_enqueued:
                    record_failed_job(task, str(exc))

        except redis_lib.ConnectionError as exc:
            logger.error("Redis connection lost: %s — reconnecting", exc)
            time.sleep(5)
            r = wait_for_redis()
        except Exception as exc:
            logger.error("Worker loop error: %s", exc, exc_info=True)
            time.sleep(5)


if __name__ == "__main__":
    main()
