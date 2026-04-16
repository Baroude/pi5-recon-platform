"""
Redis queue helpers used by all workers.

Task lifecycle
--------------
  enqueue()              → LPUSH task onto queue list
  dequeue_blocking()     → BLMOVE task → processing list (atomic)
  ack_task()             → LREM task from processing list (success)
  nack_task()            → retry (RPUSH back) or DLQ (LPUSH dlq:<queue>)
  recover_processing_queue() → on startup, move stuck tasks back to queue

The raw JSON string is stashed under task["__raw__"] so that ack/nack can
remove the exact bytes from the processing list without re-serialising and
risking key-order mismatches.
"""

import json
import logging
import os
import time
from typing import Any, Dict, Optional

import redis

logger = logging.getLogger(__name__)


def get_redis() -> redis.Redis:
    url = os.environ.get("REDIS_URL", "redis://redis:6379")
    return redis.from_url(url, decode_responses=True)


def wait_for_redis(max_attempts: int = 30, delay: float = 2.0) -> redis.Redis:
    for attempt in range(max_attempts):
        try:
            r = get_redis()
            r.ping()
            logger.info("Redis connected")
            return r
        except Exception as exc:
            logger.warning("Redis not ready (%d/%d): %s", attempt + 1, max_attempts, exc)
            time.sleep(delay)
    raise RuntimeError("Could not connect to Redis after %d attempts" % max_attempts)


def enqueue(r: redis.Redis, queue: str, payload: Dict[str, Any]) -> None:
    """Push a new task to the left of the named queue list."""
    if "retry_count" not in payload:
        payload["retry_count"] = 0
    r.lpush(queue, json.dumps(payload))


def dequeue_blocking(
    r: redis.Redis,
    queue: str,
    processing_queue: str,
    timeout: float = 30.0,
) -> Optional[Dict[str, Any]]:
    """
    Atomically move one item from *queue* to *processing_queue* (BLMOVE LEFT→RIGHT).
    Returns the parsed task dict (with __raw__ attached) or None on timeout.
    Requires Redis ≥ 6.2.
    """
    raw = r.blmove(queue, processing_queue, timeout, src="LEFT", dest="RIGHT")
    if raw is None:
        return None
    task = json.loads(raw)
    task["__raw__"] = raw   # kept for ack/nack; never written back to Redis
    return task


def ack_task(r: redis.Redis, processing_queue: str, task: Dict[str, Any]) -> None:
    """Remove a successfully processed task from the processing queue."""
    raw = task.get("__raw__")
    if raw:
        r.lrem(processing_queue, 1, raw)


def nack_task(
    r: redis.Redis,
    queue: str,
    processing_queue: str,
    task: Dict[str, Any],
    max_retries: int = 2,
    dlq_prefix: str = "dlq",
) -> bool:
    """
    Handle a failed task.
    - If retry_count < max_retries: increment and re-enqueue (RPUSH → tail).
    - Otherwise: move to dead-letter queue and return False.
    Mutates *task* in-place (increments retry_count, removes __raw__).
    Returns True if re-enqueued, False if moved to DLQ.
    """
    raw = task.pop("__raw__", None)
    retry_count = task.get("retry_count", 0)

    if raw:
        r.lrem(processing_queue, 1, raw)

    if retry_count < max_retries:
        task["retry_count"] = retry_count + 1
        r.rpush(queue, json.dumps(task))
        logger.warning("Re-enqueued task on %s (retry %d/%d)", queue, retry_count + 1, max_retries)
        return True

    dlq_key = f"{dlq_prefix}:{queue}"
    r.lpush(dlq_key, json.dumps(task))
    logger.error("Task sent to DLQ %s after %d retries", dlq_key, retry_count)
    return False


def recover_processing_queue(r: redis.Redis, queue: str, processing_queue: str) -> int:
    """
    On worker startup, move any items stuck in the processing queue back to
    the main queue so they are retried.  Tasks that repeatedly crash will
    eventually exhaust retries and reach the DLQ through the normal nack path.
    """
    count = 0
    while True:
        item = r.rpoplpush(processing_queue, queue)
        if item is None:
            break
        count += 1
    if count:
        logger.info("Recovered %d stuck tasks: %s → %s", count, processing_queue, queue)
    return count
