"""
DNS brute-force worker
======================
Consumes: brute_domain   payload: {"target_id": 1, "domain": "example.com",
                                    "scope_root": "example.com", "wordlist": "dns-small.txt"}
Produces: probe_host     payload: {"hostname": "...", "target_id": 1, "scope_root": "..."}

Workflow
--------
1. Wildcard detection — abort if apex resolves wildcard.
2. DNS brute-force via shuffledns with internal Unbound resolver.
3. Permutation via alterx + dnsx on existing subdomains from DB.
4. Merge, deduplicate, scope-filter results.
5. INSERT new subdomains, enqueue probe_host for each.
6. Cleanup old output files.
"""

import json
import logging
import os
import random
import shutil
import socket
import string
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone

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
QUEUE       = "brute_domain"
PROCESSING  = "brute_domain:processing"
NEXT_QUEUE  = "probe_host"
WORKER_NAME = "worker-dns-brute"

MAX_RETRIES                = int(os.environ.get("MAX_RETRIES", 2))
DNS_BRUTE_THREADS          = int(os.environ.get("DNS_BRUTE_THREADS", 20))
DNS_BRUTE_RETRIES          = int(os.environ.get("DNS_BRUTE_RETRIES", 3))
MAX_PERMUTATION_CANDIDATES = int(os.environ.get("MAX_PERMUTATION_CANDIDATES", 50000))
DNS_TIMEOUT_SECS           = int(os.environ.get("DNS_TIMEOUT_SECS", 900))
PERM_TIMEOUT_SECS          = int(os.environ.get("PERM_TIMEOUT_SECS", 600))
OUTPUT_DIR                 = os.environ.get("OUTPUT_DIR", "/data/output")
WORDLISTS_DIR              = "/wordlists"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("/logs/worker-dns-brute.log"),
    ],
)
logger = logging.getLogger(WORKER_NAME)

# Resolver file path — written once at startup, shared across tasks.
_resolver_file: str = ""


def _build_resolver_file() -> str:
    """Resolve the Unbound container hostname and write a resolver file."""
    try:
        ip = socket.getaddrinfo("resolver", 53)[0][4][0]
    except socket.gaierror:
        # Fallback to env override for local testing.
        ip = os.environ.get("RESOLVER_IP", "127.0.0.1")
    f = tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False)
    f.write(f"{ip}:53\n")
    f.close()
    logger.info("Resolver file: %s → %s:53", f.name, ip)
    return f.name


def _random_label(length: int = 12) -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=length))


def _detect_wildcard(domain: str) -> bool:
    """Return True if apex zone resolves wildcard DNS (3/3 random labels resolve)."""
    hits = 0
    for _ in range(3):
        label = _random_label()
        host = f"{label}.{domain}"
        try:
            result = subprocess.run(
                ["dnsx", "-d", host, "-r", _resolver_file, "-silent", "-a", "-resp"],
                capture_output=True, text=True, timeout=30,
            )
            if result.stdout.strip():
                hits += 1
        except Exception as exc:
            logger.warning("Wildcard probe error for %s: %s", host, exc)
    return hits == 3


def _run_shuffledns(domain: str, wordlist_path: str, out_file: str) -> list:
    """Run shuffledns brute-force; return list of discovered hostnames."""
    if shutil.which("massdns") is None:
        raise FileNotFoundError("massdns binary not found (required by shuffledns)")
    if shutil.which("shuffledns") is None:
        raise FileNotFoundError("shuffledns binary not found")

    cmd = [
        "shuffledns",
        "-mode", "bruteforce",
        "-d", domain,
        "-w", wordlist_path,
        "-r", _resolver_file,
        "-t", str(DNS_BRUTE_THREADS),
        "-retries", str(DNS_BRUTE_RETRIES),
        "-silent",
        "-o", out_file,
    ]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=DNS_TIMEOUT_SECS,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        stderr_tail = (exc.stderr or "").strip()
        detail = f" (stderr: {stderr_tail[-300:]})" if stderr_tail else ""
        raise RuntimeError(f"shuffledns timed out for {domain}{detail}")

    if proc.returncode != 0:
        stderr_tail = (proc.stderr or proc.stdout or "").strip()
        detail = f" (stderr: {stderr_tail[-500:]})" if stderr_tail else ""
        raise RuntimeError(
            f"shuffledns failed for {domain} with exit code {proc.returncode}{detail}"
        )

    results = []
    if os.path.exists(out_file):
        with open(out_file) as fh:
            for line in fh:
                h = line.strip()
                if h:
                    results.append(h)
    return results


def _run_permutation(existing_hosts: list) -> list:
    """Run alterx + dnsx permutation; return list of resolved hostnames."""
    if not existing_hosts:
        return []

    with tempfile.NamedTemporaryFile("w", suffix="_alterx_in.txt", delete=False) as f:
        f.writelines(h + "\n" for h in existing_hosts)
        in_file = f.name

    with tempfile.NamedTemporaryFile("w", suffix="_alterx_out.txt", delete=False) as f:
        candidates_file = f.name

    try:
        result = subprocess.run(
            ["alterx", "-l", in_file, "-silent"],
            capture_output=True, text=True, timeout=120,
        )
        candidates = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
        logger.warning("alterx error: %s", exc)
        return []
    finally:
        os.unlink(in_file)

    if not candidates:
        return []

    candidates = candidates[:MAX_PERMUTATION_CANDIDATES]
    with open(candidates_file, "w") as fh:
        fh.writelines(h + "\n" for h in candidates)

    resolved = []
    try:
        result = subprocess.run(
            ["dnsx", "-l", candidates_file, "-r", _resolver_file, "-silent", "-a"],
            capture_output=True, text=True, timeout=PERM_TIMEOUT_SECS,
        )
        for line in result.stdout.splitlines():
            h = line.strip()
            if h:
                resolved.append(h)
    except subprocess.TimeoutExpired:
        logger.warning("dnsx permutation timed out")
    except FileNotFoundError:
        logger.error("dnsx binary not found")
    finally:
        os.unlink(candidates_file)

    return resolved


def process_task(r: redis_lib.Redis, task: dict) -> None:
    domain     = task["domain"]
    scope_root = task["scope_root"]
    target_id  = task["target_id"]
    wordlist   = task.get("wordlist", "dns-small.txt")

    wordlist_path = os.path.join(WORDLISTS_DIR, wordlist)
    if not os.path.exists(wordlist_path):
        raise FileNotFoundError(
            f"Wordlist not found: {wordlist_path}. "
            f"Run init-dirs.sh or download manually."
        )

    cleanup_old_outputs(OUTPUT_DIR, "brute_*.txt")
    cleanup_old_outputs(OUTPUT_DIR, "perm_*.txt")
    logger.info("brute_domain starting for %s (wordlist=%s)", domain, wordlist)

    with db_conn() as conn:
        job_id = conn.execute(
            """INSERT INTO jobs (type, target_ref, status, started_at, worker_name)
               VALUES ('brute_domain', ?, 'running', datetime('now'), ?)""",
            (domain, WORKER_NAME),
        ).lastrowid

    try:
        # 1. WILDCARD DETECTION
        if _detect_wildcard(domain):
            logger.warning("Wildcard DNS detected on %s — skipping brute-force", domain)
            with db_conn() as conn:
                conn.execute(
                    "UPDATE jobs SET status = 'done', finished_at = datetime('now') WHERE id = ?",
                    (job_id,),
                )
            return

        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
        out_dir = os.path.join(OUTPUT_DIR, "recon", domain)
        os.makedirs(out_dir, exist_ok=True)
        brute_file = os.path.join(out_dir, f"brute_{domain}_{ts}.txt")

        # 2. DNS BRUTE-FORCE
        brute_results = _run_shuffledns(domain, wordlist_path, brute_file)
        logger.info("shuffledns found %d hosts for %s", len(brute_results), domain)

        # 3. PERMUTATION
        with db_conn() as conn:
            existing = conn.execute(
                "SELECT hostname FROM subdomains WHERE target_id = ?", (target_id,)
            ).fetchall()
        existing_hosts = [row["hostname"] for row in existing]
        perm_results = _run_permutation(existing_hosts)
        logger.info("permutation resolved %d hosts for %s", len(perm_results), domain)

        # 4. MERGE
        brute_set = {h.lower() for h in brute_results}
        perm_set   = {h.lower() for h in perm_results}

        all_hosts = {}
        for h in brute_set:
            all_hosts[h] = "shuffledns"
        for h in perm_set:
            if h not in all_hosts:
                all_hosts[h] = "alterx"

        filtered = {
            h: src for h, src in all_hosts.items()
            if is_in_scope(h, scope_root)
            and not h.startswith("_")
        }

        # 5. INSERT NEW SUBDOMAINS
        new_count = 0
        for hostname, source in filtered.items():
            with db_conn() as conn:
                existing_row = conn.execute(
                    "SELECT id FROM subdomains WHERE target_id = ? AND hostname = ?",
                    (target_id, hostname),
                ).fetchone()

                if existing_row:
                    conn.execute(
                        "UPDATE subdomains SET last_seen = datetime('now') WHERE id = ?",
                        (existing_row["id"],),
                    )
                else:
                    conn.execute(
                        "INSERT INTO subdomains (target_id, hostname, source) VALUES (?, ?, ?)",
                        (target_id, hostname, source),
                    )
                    new_count += 1
                    enqueue(r, NEXT_QUEUE, {
                        "hostname":   hostname,
                        "target_id":  target_id,
                        "scope_root": scope_root,
                    }, dedup_key=f"probe:{hostname}")
                    enqueue(r, "notify_finding", {
                        "notification_type": "new_subdomain",
                        "hostname":   hostname,
                        "scope_root": scope_root,
                    })

        logger.info(
            "brute_domain done for %s: %d new subdomains (brute=%d, perm=%d)",
            domain, new_count, len(brute_set), len(perm_set),
        )

        with db_conn() as conn:
            conn.execute(
                """UPDATE jobs SET status = 'done', finished_at = datetime('now'),
                   raw_output_path = ? WHERE id = ?""",
                (brute_file, job_id),
            )

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
               VALUES ('brute_domain', ?, ?, ?, ?)""",
            (task.get("domain"), json.dumps(task), reason, task.get("retry_count", 0)),
        )


def main():
    global _resolver_file
    logger.info("DNS brute-force worker starting")

    for tool in ("dnsx", "shuffledns", "alterx", "massdns"):
        try:
            if tool == "massdns":
                path = shutil.which("massdns")
                if path:
                    logger.info("massdns: %s", path)
                else:
                    logger.warning("massdns binary not found")
                continue
            v = subprocess.run([tool, "-version"], capture_output=True, text=True, timeout=10)
            logger.info("%s: %s", tool, (v.stdout.strip() or v.stderr.strip())[:80])
        except FileNotFoundError:
            logger.warning("%s binary not found", tool)
        except Exception as exc:
            logger.warning("Could not get %s version: %s", tool, exc)

    r = wait_for_redis()
    init_db()
    recover_processing_queue(r, QUEUE, PROCESSING)

    _resolver_file = _build_resolver_file()

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
