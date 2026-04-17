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
4. Run subfinder and amass concurrently, streaming stdout line-by-line.
5. Enqueue probe_host for each new in-scope hostname as it is discovered.
6. Ack task.  On error: nack (retry ×2) or DLQ.
"""

import json
import logging
import os
import queue as thread_queue
import select
import subprocess
import sys
import threading
import time
from datetime import datetime

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

# ---------------------------------------------------------------------------
QUEUE       = "recon_domain"
PROCESSING  = "recon_domain:processing"
NEXT_QUEUE  = "probe_host"
WORKER_NAME = "worker-recon"

MAX_RETRIES           = int(os.environ.get("MAX_RETRIES", 2))
RECON_INTERVAL_HOURS  = float(os.environ.get("DEFAULT_RECON_INTERVAL_HOURS", 24))
MAX_CONCURRENCY       = int(os.environ.get("MAX_RECON_CONCURRENCY", 2))
OUTPUT_DIR            = os.environ.get("OUTPUT_DIR", "/data/output")
AMASS_TIMEOUT_MINUTES = int(os.environ.get("AMASS_TIMEOUT_MINUTES", 20))
# Process-level kill timeout: tool's own timeout + 60 s grace period.
SUBFINDER_PROC_TIMEOUT = 660   # subfinder -timeout is in seconds; 10 min tool + 60 s
AMASS_PROC_TIMEOUT     = AMASS_TIMEOUT_MINUTES * 60 + 60

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


def _stream_into_queue(
    cmd: list,
    tool_name: str,
    output_file: str,
    out_q: thread_queue.Queue,
    proc_timeout: int,
) -> None:
    """
    Run cmd in a subprocess, push (hostname, tool_name) into out_q for every
    non-empty stdout line, then push (None, tool_name) as the done sentinel.
    Writes the same lines to output_file for raw storage.
    """
    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        started_monotonic = time.monotonic()
        timed_out = False

        with open(output_file, "w") as fh:
            while True:
                if proc.stdout is None:
                    break

                elapsed = time.monotonic() - started_monotonic
                if elapsed > proc_timeout:
                    timed_out = True
                    proc.kill()
                    logger.error("%s process timeout exceeded - killed", tool_name)
                    break

                ready, _, _ = select.select([proc.stdout], [], [], 1.0)
                if not ready:
                    if proc.poll() is not None:
                        break
                    continue

                line = proc.stdout.readline()
                if line == "":
                    if proc.poll() is not None:
                        break
                    continue

                hostname = line.strip()
                if hostname:
                    fh.write(hostname + "\n")
                    out_q.put((hostname, tool_name))

        if proc.poll() is None:
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()

        if not timed_out and proc.returncode not in (0, None):
            stderr_tail = (proc.stderr.read() if proc.stderr else "").strip()
            if stderr_tail:
                logger.warning(
                    "%s exited with code %s: %s",
                    tool_name,
                    proc.returncode,
                    stderr_tail[-500:],
                )
            else:
                logger.warning("%s exited with code %s", tool_name, proc.returncode)
    except FileNotFoundError:
        logger.warning("%s binary not found - skipping", tool_name)
    except Exception as exc:
        logger.error("%s unexpected error: %s", tool_name, exc)
    finally:
        out_q.put((None, tool_name))

def process_task(r: redis_lib.Redis, task: dict) -> None:
    domain = task.get("domain") or task.get("target")
    if not domain:
        raise ValueError(f"Missing domain in task: {task}")

    cleanup_old_outputs(OUTPUT_DIR, "subfinder_*.txt")
    cleanup_old_outputs(OUTPUT_DIR, "amass_*.txt")
    logger.info("Processing recon for %s", domain)

    with db_conn() as conn:
        row = conn.execute(
            "SELECT id, scope_root, active_recon, brute_wordlist FROM targets WHERE scope_root = ? AND enabled = 1",
            (domain,),
        ).fetchone()
        if not row:
            raise ValueError(f"Target not found or disabled: {domain}")

        target_id    = row["id"]
        scope_root   = row["scope_root"]
        active_recon = bool(row["active_recon"])
        brute_wordlist = row["brute_wordlist"] or "dns-small.txt"

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
    subfinder_file = os.path.join(out_dir, f"subfinder_{ts}.txt")
    amass_file     = os.path.join(out_dir, f"amass_{ts}.txt")

    subfinder_cmd = [
        "subfinder",
        "-d", domain,
        "-silent",
        "-all",
        "-t", str(MAX_CONCURRENCY),
        "-timeout", "30",
    ]
    amass_cmd = [
        "amass", "enum",
        "-passive",
        "-d", domain,
        "-silent",
        "-timeout", str(AMASS_TIMEOUT_MINUTES),
    ]

    out_q: thread_queue.Queue = thread_queue.Queue()
    threads = [
        threading.Thread(
            target=_stream_into_queue,
            args=(subfinder_cmd, "subfinder", subfinder_file, out_q, SUBFINDER_PROC_TIMEOUT),
            daemon=True,
        ),
        threading.Thread(
            target=_stream_into_queue,
            args=(amass_cmd, "amass", amass_file, out_q, AMASS_PROC_TIMEOUT),
            daemon=True,
        ),
    ]

    try:
        for t in threads:
            t.start()

        seen: set = set()
        new_count = 0
        subfinder_count = 0
        amass_count = 0
        tools_done = 0

        while tools_done < 2:
            hostname, tool_name = out_q.get()
            if hostname is None:
                tools_done += 1
                logger.info("%s finished for %s", tool_name, domain)
                continue

            if tool_name == "subfinder":
                subfinder_count += 1
            else:
                amass_count += 1

            if not is_in_scope(hostname, scope_root):
                logger.debug("Out of scope, skipped: %s", hostname)
                continue
            if hostname in seen:
                continue
            seen.add(hostname)

            with db_conn() as conn:
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
                        "INSERT INTO subdomains (target_id, hostname, source) VALUES (?, ?, ?)",
                        (target_id, hostname, tool_name),
                    )
                    new_count += 1
                    enqueue(r, NEXT_QUEUE, {
                        "hostname":   hostname,
                        "target_id":  target_id,
                        "scope_root": scope_root,
                    })
                    enqueue(r, "notify_finding", {
                        "notification_type": "new_subdomain",
                        "hostname":   hostname,
                        "scope_root": scope_root,
                    })

        for t in threads:
            t.join()

        logger.info(
            "Recon done for %s: %d new subdomains (subfinder=%d, amass=%d)",
            domain, new_count, subfinder_count, amass_count,
        )

        with db_conn() as conn:
            conn.execute(
                """UPDATE jobs
                   SET status = 'done', finished_at = datetime('now'), raw_output_path = ?
                   WHERE id = ?""",
                (subfinder_file, job_id),
            )

        if active_recon:
            enqueue(r, "brute_domain", {
                "target_id":  target_id,
                "domain":     domain,
                "scope_root": scope_root,
                "wordlist":   brute_wordlist,
            }, dedup_key=f"brute:{domain}", dedup_ttl_secs=int(RECON_INTERVAL_HOURS * 3600))
            logger.info("Enqueued brute_domain for %s (wordlist=%s)", domain, brute_wordlist)

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

