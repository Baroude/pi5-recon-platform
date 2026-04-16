"""
Notify worker
=============
Consumes: notify_finding  payload variants:
  {"notification_type": "new_finding",   "finding_id": 123}
  {"notification_type": "new_subdomain", "hostname": "...", "scope_root": "..."}
  {"notification_type": "new_endpoint",  "endpoint_id": 42, "url": "..."}

Dispatches alerts to Telegram and/or Discord depending on which env vars are set.
At least one of TELEGRAM_BOT_TOKEN+TELEGRAM_CHAT_ID or DISCORD_WEBHOOK_URL must be
configured, otherwise notifications are logged and discarded without error.
"""

import json
import logging
import os
import sys
import time

import requests
import redis as redis_lib

sys.path.insert(0, "/app")
from common.db import db_conn, init_db
from common.queue import (
    ack_task,
    dequeue_blocking,
    nack_task,
    recover_processing_queue,
    wait_for_redis,
)

# ---------------------------------------------------------------------------
QUEUE      = "notify_finding"
PROCESSING = "notify_finding:processing"
WORKER_NAME = "worker-notify"

MAX_RETRIES = int(os.environ.get("MAX_RETRIES", 2))

TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID   = os.environ.get("TELEGRAM_CHAT_ID", "")
DISCORD_WEBHOOK_URL = os.environ.get("DISCORD_WEBHOOK_URL", "")
SEVERITY_MIN        = os.environ.get("NUCLEI_SEVERITY_MIN", "medium")

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("/logs/worker-notify.log"),
    ],
)
logger = logging.getLogger(WORKER_NAME)

# ---------------------------------------------------------------------------


def severity_meets_threshold(severity: str) -> bool:
    return SEVERITY_ORDER.get(severity.lower(), -1) >= SEVERITY_ORDER.get(SEVERITY_MIN.lower(), 2)


def _send_telegram(text: str) -> None:
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        return
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    resp = requests.post(
        url,
        json={"chat_id": TELEGRAM_CHAT_ID, "text": text, "parse_mode": "Markdown"},
        timeout=10,
    )
    resp.raise_for_status()


def _send_discord(text: str) -> None:
    if not DISCORD_WEBHOOK_URL:
        return
    resp = requests.post(
        DISCORD_WEBHOOK_URL,
        json={"content": text},
        timeout=10,
    )
    resp.raise_for_status()


def _dispatch(text: str) -> None:
    """Send to all configured channels; log if none configured."""
    if not TELEGRAM_BOT_TOKEN and not DISCORD_WEBHOOK_URL:
        logger.info("No notification channel configured — message: %s", text)
        return
    if TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID:
        _send_telegram(text)
    if DISCORD_WEBHOOK_URL:
        _send_discord(text)


def _record_notification(finding_id: int | None, channel: str) -> None:
    with db_conn() as conn:
        conn.execute(
            "INSERT INTO notifications (finding_id, channel) VALUES (?, ?)",
            (finding_id, channel),
        )


def process_task(task: dict) -> None:
    notification_type = task.get("notification_type")

    if notification_type == "new_finding":
        finding_id = task.get("finding_id")
        if not finding_id:
            raise ValueError(f"Missing finding_id: {task}")

        with db_conn() as conn:
            row = conn.execute(
                """SELECT f.template_id, f.severity, f.title, f.matched_at, e.url
                   FROM findings f
                   JOIN endpoints e ON e.id = f.endpoint_id
                   WHERE f.id = ?""",
                (finding_id,),
            ).fetchone()

        if not row:
            logger.warning("Finding %d not found in DB — skipping", finding_id)
            return

        if not severity_meets_threshold(row["severity"]):
            return

        sev = row["severity"].upper()
        text = (
            f"*[{sev}] New Finding*\n"
            f"Template: `{row['template_id']}`\n"
            f"Title: {row['title']}\n"
            f"URL: {row['url']}\n"
            f"Matched at: {row['matched_at']}"
        )
        _dispatch(text)
        channel = "telegram" if TELEGRAM_BOT_TOKEN else "discord"
        _record_notification(finding_id, channel)
        logger.info("Notified: finding %d (%s)", finding_id, sev)

    elif notification_type == "new_subdomain":
        hostname   = task.get("hostname", "")
        scope_root = task.get("scope_root", "")
        text = f"*New Subdomain*\n`{hostname}` (scope: `{scope_root}`)"
        _dispatch(text)
        logger.info("Notified: new subdomain %s", hostname)

    elif notification_type == "new_endpoint":
        url = task.get("url", "")
        text = f"*New Live Endpoint*\n{url}"
        _dispatch(text)
        logger.info("Notified: new endpoint %s", url)

    else:
        logger.warning("Unknown notification_type '%s' — discarding", notification_type)


def record_failed_job(task: dict, reason: str) -> None:
    with db_conn() as conn:
        conn.execute(
            """INSERT INTO failed_jobs (type, target_ref, payload, failure_reason, retry_count)
               VALUES ('notify_finding', ?, ?, ?, ?)""",
            (
                task.get("hostname") or task.get("url"),
                json.dumps(task),
                reason,
                task.get("retry_count", 0),
            ),
        )


def main():
    logger.info("Notify worker starting")
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
                process_task(task)
                ack_task(r, PROCESSING, task)
            except Exception as exc:
                logger.error("Task failed: %s — %s", task, exc, exc_info=True)
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
