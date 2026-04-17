"""
Nuclei worker
=============
Consumes: scan_http     payload: {"url": "https://sub.example.com",
                                   "endpoint_id": 42}
Produces: notify_finding payload: {"notification_type": "new_finding",
                                    "finding_id": 123}

Workflow
--------
1. Dequeue up to NUCLEI_BATCH_SIZE scan_http tasks at once.
2. TTL check — skip recently scanned URLs.
3. Run nuclei with -list (batch of URLs) and curated severity filter.
4. Stream JSONL output line-by-line; map findings back to endpoint_id via
   matched-at URL; deduplicate and persist immediately.
5. Ack all tasks in the batch.

A background thread re-runs `nuclei -update-templates` on the configured
interval so templates stay current without a container restart.
"""

import hashlib
import json
import logging
import os
import select
import subprocess
import sys
import tempfile
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
MAX_CONCURRENCY       = int(os.environ.get("MAX_NUCLEI_CONCURRENCY", 25))
NUCLEI_BATCH_SIZE     = int(os.environ.get("NUCLEI_BATCH_SIZE", 1))
OUTPUT_DIR            = os.environ.get("OUTPUT_DIR", "/data/output")
TEMPLATE_UPDATE_HOURS = float(os.environ.get("NUCLEI_TEMPLATES_UPDATE_INTERVAL_HOURS", 24))
NUCLEI_PROC_TIMEOUT   = int(os.environ.get("NUCLEI_PROC_TIMEOUT", 1800))
NUCLEI_THROTTLE_SECS  = int(os.environ.get("NUCLEI_THROTTLE_SECS", 30))
NUCLEI_RATE_LIMIT     = int(os.environ.get("NUCLEI_RATE_LIMIT", 10))
NUCLEI_BULK_SIZE      = int(os.environ.get("NUCLEI_BULK_SIZE", 25))
NUCLEI_TIMEOUT_SECS   = int(os.environ.get("NUCLEI_TIMEOUT_SECS", 15))
NUCLEI_RETRIES        = int(os.environ.get("NUCLEI_RETRIES", 1))

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


def _find_endpoint_id(url_to_endpoint: dict, matched_at: str) -> int:
    """Map a nuclei matched-at URL back to the endpoint_id from the batch."""
    if matched_at in url_to_endpoint:
        return url_to_endpoint[matched_at]
    # matched-at may include a path; try base URL prefix match
    for base_url, endpoint_id in url_to_endpoint.items():
        if matched_at.startswith(base_url):
            return endpoint_id
    # fall back to hostname match
    matched_host = urlparse(matched_at).hostname or ""
    for base_url, endpoint_id in url_to_endpoint.items():
        if urlparse(base_url).hostname == matched_host:
            return endpoint_id
    return next(iter(url_to_endpoint.values()))


def _resolve_template_path(template_name: str) -> str:
    selected = (template_name or "all").strip().strip("/")
    if not selected or selected == "all":
        return TEMPLATES_DIR
    if ".." in selected.split("/"):
        logger.warning("Unsafe template path requested (%s) - using all templates", selected)
        return TEMPLATES_DIR
    candidate = os.path.join(TEMPLATES_DIR, selected)
    if not os.path.exists(candidate):
        logger.warning("Template path not found (%s) - using all templates", candidate)
        return TEMPLATES_DIR
    return candidate


def _wait_for_scope_throttle(r: redis_lib.Redis, scope_root: str) -> None:
    """
    Enforce a minimum delay between nuclei batch starts for the same scope_root.

    Uses Redis so the throttle applies across multiple worker replicas.
    """
    if NUCLEI_THROTTLE_SECS <= 0 or not scope_root:
        return

    throttle_key = f"throttle:nuclei:{scope_root}"
    while True:
        acquired = r.set(throttle_key, "1", nx=True, ex=NUCLEI_THROTTLE_SECS)
        if acquired:
            return

        ttl = r.ttl(throttle_key)
        wait_secs = ttl if ttl and ttl > 0 else 1
        logger.info(
            "Throttling nuclei for scope %s - waiting %ds before next batch",
            scope_root,
            wait_secs,
        )
        time.sleep(wait_secs)


def _scan_group(r: redis_lib.Redis, group: list, template_name: str) -> None:
    urls = [t["url"] for t in group]
    url_to_endpoint = {t["url"]: t["endpoint_id"] for t in group}
    scope_root = group[0].get("scope_root", "") if group else ""
    _wait_for_scope_throttle(r, scope_root)
    logger.info(
        "Scanning batch of %d URL(s) with template '%s': %s",
        len(urls),
        template_name,
        ", ".join(urls),
    )

    # one job record per URL for dashboard visibility
    job_ids = {}
    for t in group:
        with db_conn() as conn:
            job_ids[t["url"]] = conn.execute(
                """INSERT INTO jobs (type, target_ref, status, started_at, worker_name)
                   VALUES ('scan_http', ?, 'running', datetime('now'), ?)""",
                (t["url"], WORKER_NAME),
            ).lastrowid

    # write URL list to temp file
    url_list = tempfile.NamedTemporaryFile("w", suffix="_urls.txt", delete=False)
    url_list.writelines(u + "\n" for u in urls)
    url_list.close()

    out_dir = os.path.join(OUTPUT_DIR, "nuclei", "_batch")
    os.makedirs(out_dir, exist_ok=True)
    ts = datetime.utcnow().strftime("%Y%m%dT%H%M%S")
    template_slug = (template_name or "all").replace("/", "_")
    output_file = os.path.join(out_dir, f"nuclei_{template_slug}_{ts}.jsonl")

    sev_names = [k for k, v in SEVERITY_ORDER.items()
                 if v >= SEVERITY_ORDER.get(SEVERITY_MIN.lower(), 2)]
    severity_arg = ",".join(sev_names)
    template_path = _resolve_template_path(template_name)

    cmd = [
        "nuclei",
        "-list", url_list.name,
        "-t", template_path,
        "-severity", severity_arg,
        "-jsonl",
        "-silent",
        "-no-color",
        "-rate-limit", str(NUCLEI_RATE_LIMIT),
        "-bulk-size", str(NUCLEI_BULK_SIZE),
        "-c", str(MAX_CONCURRENCY),
        "-timeout", str(NUCLEI_TIMEOUT_SECS),
        "-retries", str(NUCLEI_RETRIES),
    ]

    findings_count = 0
    proc = None
    timed_out = False
    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        started_monotonic = time.monotonic()

        with open(output_file, "w") as fh:
            while True:
                if proc.stdout is None:
                    break
                if time.monotonic() - started_monotonic > NUCLEI_PROC_TIMEOUT:
                    timed_out = True
                    proc.kill()
                    logger.error("nuclei batch timeout exceeded - killed")
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

                line = line.strip()
                if not line:
                    continue
                fh.write(line + "\n")
                try:
                    finding = json.loads(line)
                except json.JSONDecodeError:
                    logger.debug("Non-JSON nuclei output: %s", line[:120])
                    continue

                matched_at = finding.get("matched-at", "")
                endpoint_id = _find_endpoint_id(url_to_endpoint, matched_at)
                _process_finding(r, finding, endpoint_id, output_file)
                findings_count += 1

        if proc.poll() is None:
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()

        if not timed_out and proc.returncode not in (0, None):
            stderr_tail = (proc.stderr.read() if proc.stderr else "").strip()
            if stderr_tail:
                logger.warning("nuclei exited %s: %s", proc.returncode, stderr_tail[-500:])

    except Exception:
        if proc and proc.poll() is None:
            proc.kill()
        with db_conn() as conn:
            for job_id in job_ids.values():
                conn.execute(
                    "UPDATE jobs SET status = 'failed', finished_at = datetime('now') WHERE id = ?",
                    (job_id,),
                )
        raise
    finally:
        try:
            os.unlink(url_list.name)
        except OSError:
            pass

    logger.info(
        "nuclei batch (%s): %d finding(s) across %d URL(s)",
        template_name,
        findings_count,
        len(urls),
    )

    with db_conn() as conn:
        for t in group:
            conn.execute(
                "UPDATE endpoints SET last_scanned_at = datetime('now') WHERE id = ?",
                (t["endpoint_id"],),
            )
        for url, job_id in job_ids.items():
            conn.execute(
                """UPDATE jobs SET status = 'done', finished_at = datetime('now'),
                   raw_output_path = ? WHERE id = ?""",
                (output_file, job_id),
            )


def process_batch(r: redis_lib.Redis, tasks: list) -> None:
    if not tasks:
        return

    valid = []
    for task in tasks:
        url = task.get("url")
        endpoint_id = task.get("endpoint_id")
        if not url or not endpoint_id:
            logger.warning("Skipping malformed task: %s", task)
            continue

        with db_conn() as conn:
            scope_row = conn.execute(
                """SELECT t.scope_root, COALESCE(t.nuclei_template, 'all') AS nuclei_template
                   FROM endpoints e
                   JOIN subdomains s ON s.id = e.subdomain_id
                   JOIN targets   t ON t.id = s.target_id
                   WHERE e.id = ?""",
                (endpoint_id,),
            ).fetchone()
            recent = conn.execute(
                "SELECT last_scanned_at FROM endpoints WHERE id = ? AND last_scanned_at > datetime('now', ? || ' hours')",
                (endpoint_id, f"-{NUCLEI_INTERVAL_HOURS}"),
            ).fetchone()

        scope_root = scope_row["scope_root"] if scope_row else ""
        nuclei_template = scope_row["nuclei_template"] if scope_row else "all"

        if scope_root:
            parsed_host = urlparse(url).hostname or ""
            if not is_in_scope(parsed_host, scope_root):
                logger.warning("Out-of-scope skipped: %s (scope=%s)", url, scope_root)
                continue
        if recent:
            logger.info("Skipping %s - scanned recently", url)
            continue

        valid.append({**task, "scope_root": scope_root, "nuclei_template": nuclei_template})

    if not valid:
        return

    cleanup_old_outputs(OUTPUT_DIR, "nuclei_*.jsonl")

    grouped = {}
    for task in valid:
        scope_root = task.get("scope_root") or ""
        template_name = (task.get("nuclei_template") or "all").strip().strip("/") or "all"
        grouped.setdefault((scope_root, template_name), []).append(task)

    for (_, template_name), group in grouped.items():
        _scan_group(r, group, template_name)


def record_failed_job(tasks: list, reason: str) -> None:
    with db_conn() as conn:
        for task in tasks:
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

    logger.info("Listening on queue: %s (batch_size=%d)", QUEUE, NUCLEI_BATCH_SIZE)

    while True:
        try:
            first = dequeue_blocking(r, QUEUE, PROCESSING, timeout=30)
            if first is None:
                continue

            tasks = [first]
            while len(tasks) < NUCLEI_BATCH_SIZE:
                raw = r.lmove(QUEUE, PROCESSING, "LEFT", "RIGHT")
                if raw is None:
                    break
                task = json.loads(raw)
                task["__raw__"] = raw
                tasks.append(task)

            try:
                process_batch(r, tasks)
                for task in tasks:
                    ack_task(r, PROCESSING, task)
            except Exception as exc:
                urls = [t.get("url") for t in tasks]
                logger.error("Batch failed %s — %s", urls, exc, exc_info=True)
                failed = []
                for task in tasks:
                    re_enqueued = nack_task(r, QUEUE, PROCESSING, task, MAX_RETRIES)
                    if not re_enqueued:
                        failed.append(task)
                if failed:
                    record_failed_job(failed, str(exc))

        except redis_lib.ConnectionError as exc:
            logger.error("Redis connection lost: %s", exc)
            time.sleep(5)
            r = wait_for_redis()
        except Exception as exc:
            logger.error("Worker loop error: %s", exc, exc_info=True)
            time.sleep(5)


if __name__ == "__main__":
    main()

