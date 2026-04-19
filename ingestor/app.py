"""
Ingestor — FastAPI service for target submission and periodic refresh scheduling.

Endpoints
---------
  GET  /admin/meta           Dashboard control metadata (limits/defaults/options).
  GET  /admin/progress       Consolidated progress snapshot for UI rendering.
  GET  /admin/failed-jobs    Recent failed jobs for Ops UI.
  GET  /admin/dlq            DLQ depths plus recent raw payloads.
  POST /admin/dlq/{queue}/requeue  Requeue one DLQ item by exact raw payload.
  POST /admin/dlq/{queue}/dismiss  Remove one DLQ item by exact raw payload.
  POST /targets              Add a new scope root; enqueues first recon job.
  GET  /targets              List all targets with last-seen job status.
  PATCH /targets/{id}        Update target scan configuration.
  POST /targets/{id}/run     Trigger an immediate recon enqueue for a target.
  DELETE /targets/{id}       Disable a target (sets enabled=0).
  POST /targets/{id}/stop    Stop a target (disable + drain queues).
  GET  /targets/{id}/jobs    Recent jobs for a target.
  GET  /findings             Recent findings (supports severity/status/target/window filters).
  GET  /findings/{id}        Full finding details with best-effort raw nuclei event.
  PATCH /findings/{id}       Update finding triage status.
  GET  /health               Liveness probe.
"""

import asyncio
import glob as _glob
import json
import logging
import os
import re
import sys
import threading
import time
from collections import deque
from datetime import datetime, timezone
from typing import Any, Optional

import redis as redis_lib
from fastapi import FastAPI, HTTPException, Query, Request, Response
from fastapi.responses import RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, field_validator

sys.path.insert(0, "/app")
from common.db import db_conn, init_db
from common.queue import enqueue, wait_for_redis

# ---------------------------------------------------------------------------
LOG_DIR = os.environ.get("LOG_DIR", "/logs")
if not os.path.isdir(LOG_DIR):
    LOG_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "logs"))
os.makedirs(LOG_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOG_DIR, "ingestor.log")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(LOG_FILE),
    ],
)
logger = logging.getLogger("ingestor")

RECON_INTERVAL_HOURS = float(os.environ.get("DEFAULT_RECON_INTERVAL_HOURS", 24))
DEFAULT_WINDOW_HOURS = int(os.environ.get("DASHBOARD_DEFAULT_WINDOW_HOURS", 24))
DEFAULT_TARGET_LIMIT = int(os.environ.get("DASHBOARD_DEFAULT_TARGET_LIMIT", 200))
DEFAULT_RECENT_JOB_LIMIT = int(os.environ.get("DASHBOARD_DEFAULT_RECENT_JOB_LIMIT", 60))
DEFAULT_REFRESH_INTERVAL_SECS = int(os.environ.get("DASHBOARD_DEFAULT_REFRESH_INTERVAL_SECS", 5))
RUN_NOW_DEDUP_SECS = int(os.environ.get("RUN_NOW_DEDUP_SECS", 60))
WINDOW_HOURS_BOUNDS = (1, 168)
TARGET_LIMIT_BOUNDS = (1, 500)
RECENT_JOB_LIMIT_BOUNDS = (5, 200)
REFRESH_INTERVAL_BOUNDS = (2, 60)

app = FastAPI(title="Recon Platform Ingestor", version="1.0")

_redis: Optional[redis_lib.Redis] = None
_refresh_thread: Optional[threading.Thread] = None

_DLQ_QUEUES = [
    "recon_domain",
    "brute_domain",
    "probe_host",
    "scan_http",
    "notify_finding",
    "company_intel",
    "company_intel_crt",
    "company_intel_pivot",
    "company_intel_ripestat",
]
_ALL_QUEUES = _DLQ_QUEUES
_ALLOWED_FINDING_STATUSES = {"open", "triaged", "false_positive", "fixed"}
_ALLOWED_FINDING_SEVERITIES = {"critical", "high", "medium", "low", "info"}
_LOG_WORKER_RE = re.compile(r"^[\w-]+$")

_ALLOWED_WORDLISTS = {"dns-small.txt", "dns-medium.txt", "dns-large.txt"}
_DEFAULT_ALLOWED_NUCLEI_TEMPLATES = {
    "all",
    "http",
    "network",
    "dns",
    "ssl",
    "exposures",
    "takeovers",
    "default-logins",
    "misconfiguration",
}
_OUTPUT_DIR = os.path.abspath(os.environ.get("OUTPUT_DIR", "/data/output"))
_STATIC_DIR = "/app/static" if os.path.isdir("/app/static") else os.path.join(os.path.dirname(__file__), "static")


def _parse_allowed_nuclei_templates() -> set[str]:
    raw = os.environ.get("ALLOWED_NUCLEI_TEMPLATES", "")
    parsed = set()
    for item in raw.split(","):
        cleaned = item.strip().strip("/")
        if cleaned:
            parsed.add(cleaned)
    if not parsed:
        return set(_DEFAULT_ALLOWED_NUCLEI_TEMPLATES)
    parsed.add("all")
    return parsed


_ALLOWED_NUCLEI_TEMPLATES = _parse_allowed_nuclei_templates()


def _is_path_within_base(candidate_path: str, base_dir: str) -> bool:
    candidate_abs = os.path.abspath(candidate_path)
    base_abs = os.path.abspath(base_dir)
    try:
        return os.path.commonpath([candidate_abs, base_abs]) == base_abs
    except ValueError:
        return False


def _load_raw_event_for_finding(row: dict) -> tuple[Optional[dict], Optional[str]]:
    raw_blob_path = row.get("raw_blob_path")
    template_id = row.get("template_id")
    matched_at = row.get("matched_at")
    if not raw_blob_path:
        return None, "No raw blob path is associated with this finding."

    if not _is_path_within_base(raw_blob_path, _OUTPUT_DIR):
        return None, f"Raw blob path is outside allowed output directory ({_OUTPUT_DIR})."

    if not os.path.isfile(raw_blob_path):
        return None, f"Raw blob file not found: {raw_blob_path}"

    fallback_event = None
    try:
        with open(raw_blob_path, "r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                payload = line.strip()
                if not payload:
                    continue
                try:
                    event = json.loads(payload)
                except Exception:
                    continue

                if event.get("template-id") != template_id:
                    continue

                if event.get("matched-at") == matched_at:
                    return event, None

                if fallback_event is None:
                    fallback_event = event
    except Exception as exc:
        return None, f"Failed reading raw blob: {exc}"

    if fallback_event is not None:
        return fallback_event, "Exact event match not found; showing first event with the same template-id."

    return None, "No matching event found in raw blob."


def _redis_value_to_text(value: Any) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def _decode_json_payload(raw: Any) -> Any:
    try:
        return json.loads(_redis_value_to_text(raw))
    except Exception:
        return None


def _decode_json_text(raw_text: Optional[str]) -> Any:
    if raw_text is None:
        return None
    try:
        return json.loads(raw_text)
    except Exception:
        return None


def _normalize_optional_text(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    normalized = value.strip()
    return normalized or None


def _parse_technology_csv(raw_value: Optional[str]) -> list[str]:
    if not raw_value:
        return []
    return sorted({item.strip().lower() for item in raw_value.split(",") if item and item.strip()})


def _drain_target_queues(r: redis_lib.Redis, scope_root: str) -> int:
    """Remove all pending/processing queue entries for scope_root. Returns count removed."""
    drained = 0
    queue_lists = _ALL_QUEUES + [f"{q}:processing" for q in _ALL_QUEUES]
    for queue in queue_lists:
        items = r.lrange(queue, 0, -1)
        for raw in items:
            try:
                payload = json.loads(raw if isinstance(raw, str) else raw.decode())
                if payload.get("domain") == scope_root or payload.get("scope_root") == scope_root:
                    drained += r.lrem(queue, 1, raw)
            except Exception:
                continue
    inflight_keys = [
        f"inflight:recon_domain:{scope_root}",
        f"inflight:recon_domain:manual:{scope_root}",
        f"inflight:brute_domain:brute:{scope_root}",
    ]
    r.delete(*inflight_keys)
    return drained


_COMPANY_QUEUES = [
    "company_intel",
    "company_intel_crt",
    "company_intel_pivot",
    "company_intel_ripestat",
]


def _drain_company_queues(r: redis_lib.Redis, company_id: int) -> int:
    """Remove all pending/processing queue entries for a company. Returns count removed."""
    drained = 0
    queue_lists = _COMPANY_QUEUES + [f"{q}:processing" for q in _COMPANY_QUEUES]
    for queue in queue_lists:
        items = r.lrange(queue, 0, -1)
        for raw in items:
            try:
                payload = json.loads(raw if isinstance(raw, str) else raw.decode())
                if payload.get("company_id") == company_id:
                    drained += r.lrem(queue, 1, raw)
            except Exception:
                continue
    r.delete(f"company:{company_id}:pending_jobs")
    return drained


def _collect_target_file_paths(target_id: int, scope_root: str) -> set[str]:
    """Read file paths to delete for a target. Does not delete anything."""
    paths: set[str] = set()
    with db_conn() as conn:
        rows = conn.execute(
            """
            SELECT f.raw_blob_path FROM findings f
            JOIN endpoints e ON e.id = f.endpoint_id
            JOIN subdomains s ON s.id = e.subdomain_id
            WHERE s.target_id = ?
            """,
            (target_id,),
        ).fetchall()
    for row in rows:
        path = row["raw_blob_path"]
        if path and _is_path_within_base(path, _OUTPUT_DIR):
            paths.add(path)
    pattern = os.path.join(_OUTPUT_DIR, "**", f"*{scope_root}*")
    for path in _glob.glob(pattern, recursive=True):
        if _is_path_within_base(path, _OUTPUT_DIR):
            paths.add(path)
    return paths


def _delete_file_paths(paths: set[str]) -> int:
    """Delete the given file paths. Returns count deleted."""
    deleted = 0
    for path in paths:
        try:
            if os.path.isfile(path):
                os.remove(path)
                deleted += 1
        except OSError as exc:
            logger.warning("Purge: could not remove %s: %s", path, exc)
    return deleted


def _validate_queue_name(queue: str) -> str:
    if queue not in _DLQ_QUEUES:
        raise HTTPException(status_code=404, detail="Unknown queue")
    return queue


def _parse_csv_values(raw_value: Optional[str], *, allowed: Optional[set[str]] = None, field_name: str) -> list[str]:
    if not raw_value:
        return []

    values = [item.strip().lower() for item in raw_value.split(",") if item.strip()]
    if not values:
        return []

    invalid = sorted({value for value in values if allowed is not None and value not in allowed})
    if invalid:
        raise HTTPException(status_code=400, detail=f"Invalid {field_name}: {', '.join(invalid)}")
    return values


def _append_in_clause(base_name: str, values: list[str], params: dict[str, Any]) -> str:
    placeholders = []
    for idx, value in enumerate(values):
        key = f"{base_name}_{idx}"
        params[key] = value
        placeholders.append(f":{key}")
    return ", ".join(placeholders)


def _serialize_dlq_entry(raw_item: Any) -> dict[str, Any]:
    raw_text = _redis_value_to_text(raw_item)
    return {"raw": raw_text, "payload": _decode_json_text(raw_text)}


def _validate_log_worker(worker: str) -> str:
    if not _LOG_WORKER_RE.fullmatch(worker):
        raise HTTPException(status_code=400, detail="Invalid worker")
    if not worker.startswith("worker-"):
        raise HTTPException(status_code=400, detail="Invalid worker")
    return worker


def _log_path_for_worker(worker: str) -> str:
    return os.path.join(LOG_DIR, f"{worker}.log")


def _read_log_lines(path: str, *, lines: int) -> tuple[list[str], int]:
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        if lines == 0:
            output = handle.read().splitlines()
        else:
            tail: deque[str] = deque(maxlen=lines)
            for raw in handle:
                tail.append(raw.rstrip("\n"))
            output = list(tail)
        end_offset = handle.tell()
    return output, end_offset


def get_r() -> redis_lib.Redis:
    global _redis
    if _redis is None:
        _redis = wait_for_redis()
    try:
        _redis.ping()
    except Exception:
        _redis = wait_for_redis()
    return _redis


# ---------------------------------------------------------------------------
# Startup / shutdown
# ---------------------------------------------------------------------------

@app.on_event("startup")
def on_startup():
    global _refresh_thread
    if os.environ.get("INGESTOR_DISABLE_STARTUP", "0") == "1":
        logger.info("Startup IO disabled via INGESTOR_DISABLE_STARTUP=1")
        return
    init_db()
    get_r()
    _refresh_thread = threading.Thread(target=_refresh_loop, daemon=True, name="refresh")
    _refresh_thread.start()
    logger.info("Ingestor ready")


@app.get("/", include_in_schema=False)
def root():
    return RedirectResponse(url="/ui/index.html")


@app.get("/logs")
def list_logs():
    workers = []
    for path in _glob.glob(os.path.join(LOG_DIR, "*.log")):
        if os.path.isfile(path):
            worker = os.path.splitext(os.path.basename(path))[0]
            if worker.startswith("worker-"):
                workers.append(worker)
    return {"workers": sorted(workers)}


@app.get("/logs/{worker}")
def get_log_lines(
    worker: str,
    response: Response,
    lines: int = Query(default=500, ge=0, le=10000),
):
    worker_name = _validate_log_worker(worker)
    path = _log_path_for_worker(worker_name)
    if not os.path.isfile(path):
        raise HTTPException(status_code=404, detail="Log file not found")

    selected_lines, end_offset = _read_log_lines(path, lines=lines)
    response.headers["X-Log-Offset"] = str(end_offset)
    return {"lines": selected_lines}


@app.get("/logs/{worker}/stream")
async def stream_log(
    worker: str,
    request: Request,
    offset: int | None = Query(default=None, ge=0),
):
    worker_name = _validate_log_worker(worker)
    path = _log_path_for_worker(worker_name)
    if not os.path.isfile(path):
        raise HTTPException(status_code=404, detail="Log file not found")

    async def event_stream():
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            handle.seek(0, os.SEEK_END)
            file_end = handle.tell()
            start_offset = file_end if offset is None else min(offset, file_end)
            handle.seek(start_offset)
            while True:
                if await request.is_disconnected():
                    break
                line = handle.readline()
                if line:
                    cursor = handle.tell()
                    yield f"id: {cursor}\ndata: {line.rstrip('\r\n')}\n\n"
                    continue
                await asyncio.sleep(0.2)

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


# ---------------------------------------------------------------------------
# Periodic refresh
# ---------------------------------------------------------------------------

def _refresh_stale_targets() -> int:
    """Enqueue recon jobs for targets whose last successful scan is stale."""
    enqueued = 0
    with db_conn() as conn:
        rows = conn.execute(
            """
            SELECT t.scope_root FROM targets t
            WHERE t.enabled = 1
              AND NOT EXISTS (
                  SELECT 1 FROM jobs j
                  WHERE j.type      = 'recon_domain'
                    AND j.target_ref = t.scope_root
                    AND j.status     = 'done'
                    AND j.finished_at > datetime('now', :hours || ' hours')
              )
            """,
            {"hours": f"-{int(RECON_INTERVAL_HOURS)}"},
        ).fetchall()

    r = get_r()
    ttl = int(RECON_INTERVAL_HOURS * 3600)
    for row in rows:
        pushed = enqueue(
            r, "recon_domain", {"domain": row["scope_root"]},
            dedup_key=row["scope_root"],
            dedup_ttl_secs=ttl,
        )
        if pushed:
            enqueued += 1
            logger.info("Refresh enqueued for %s", row["scope_root"])
    return enqueued


def _refresh_loop():
    """Background thread: check for stale targets every hour, log DLQ depths."""
    while True:
        try:
            n = _refresh_stale_targets()
            if n:
                logger.info("Refresh cycle: enqueued %d target(s)", n)
        except Exception as exc:
            logger.error("Refresh cycle error: %s", exc)

        # Log DLQ depths so operators can spot queue buildup in the logs.
        try:
            r = get_r()
            for q in _DLQ_QUEUES:
                depth = r.llen(f"dlq:{q}")
                if depth:
                    logger.warning("DLQ depth dlq:%s = %d", q, depth)
        except Exception as exc:
            logger.error("DLQ depth check failed: %s", exc)

        time.sleep(3600)


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

# Matches a valid public domain: dot-separated labels of [a-z0-9-], no
# consecutive dots, no leading/trailing dots, at least two labels (TLD present).
# Bare IPs and single-label hostnames (e.g. "localhost") are rejected.
_DOMAIN_RE = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)"
    r"+[a-z]{2,}$"
)


class TargetIn(BaseModel):
    scope_root: str
    notes: Optional[str] = None
    active_recon: bool = False
    brute_wordlist: str = "dns-small.txt"
    nuclei_template: str = "all"

    @field_validator("scope_root")
    @classmethod
    def normalise(cls, v: str) -> str:
        v = v.strip().lower().lstrip("*.")
        if not v:
            raise ValueError("scope_root must not be empty")
        if not _DOMAIN_RE.match(v):
            raise ValueError(
                "scope_root must be a valid public domain (e.g. example.com). "
                "Bare IPs, single-label names, and malformed hostnames are not accepted."
            )
        return v

    @field_validator("brute_wordlist")
    @classmethod
    def validate_wordlist(cls, v: str) -> str:
        if v not in _ALLOWED_WORDLISTS:
            raise ValueError(f"brute_wordlist must be one of: {sorted(_ALLOWED_WORDLISTS)}")
        return v

    @field_validator("nuclei_template")
    @classmethod
    def validate_nuclei_template(cls, v: str) -> str:
        if v not in _ALLOWED_NUCLEI_TEMPLATES:
            raise ValueError(f"nuclei_template must be one of: {sorted(_ALLOWED_NUCLEI_TEMPLATES)}")
        return v


class TargetUpdate(BaseModel):
    scope_root: Optional[str] = None
    notes: Optional[str] = None
    active_recon: Optional[bool] = None
    brute_wordlist: Optional[str] = None
    nuclei_template: Optional[str] = None

    @field_validator("scope_root")
    @classmethod
    def normalise_scope_root(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        cleaned = v.strip().lower().lstrip("*.")
        if not cleaned:
            raise ValueError("scope_root must not be empty")
        if not _DOMAIN_RE.match(cleaned):
            raise ValueError(
                "scope_root must be a valid public domain (e.g. example.com). "
                "Bare IPs, single-label names, and malformed hostnames are not accepted."
            )
        return cleaned

    @field_validator("brute_wordlist")
    @classmethod
    def validate_wordlist(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and v not in _ALLOWED_WORDLISTS:
            raise ValueError(f"brute_wordlist must be one of: {sorted(_ALLOWED_WORDLISTS)}")
        return v

    @field_validator("nuclei_template")
    @classmethod
    def validate_nuclei_template(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and v not in _ALLOWED_NUCLEI_TEMPLATES:
            raise ValueError(f"nuclei_template must be one of: {sorted(_ALLOWED_NUCLEI_TEMPLATES)}")
        return v


class DlqActionRequest(BaseModel):
    raw: str

    @field_validator("raw")
    @classmethod
    def validate_raw(cls, v: str) -> str:
        value = v.strip()
        if not value:
            raise ValueError("raw must not be empty")
        return value


class CompanyIn(BaseModel):
    name: str
    seed_domain: Optional[str] = None

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        value = v.strip()
        if not value:
            raise ValueError("name must not be empty")
        if len(value) > 200:
            raise ValueError("name must be 200 characters or fewer")
        return value

    @field_validator("seed_domain")
    @classmethod
    def validate_seed_domain(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        v = v.strip().lower()
        if not v:
            return None
        if not re.match(r"^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?)+$", v):
            raise ValueError("seed_domain must be a valid domain name (e.g. kering.com)")
        return v


class DomainActionRequest(BaseModel):
    domain_ids: Optional[list[int]] = None
    all: bool = False
    min_trust: Optional[int] = None

    @field_validator("domain_ids")
    @classmethod
    def validate_ids(cls, v: Optional[list[int]]) -> Optional[list[int]]:
        if v is not None and len(v) == 0:
            raise ValueError("domain_ids must not be empty when provided")
        return v

    @field_validator("min_trust")
    @classmethod
    def validate_min_trust(cls, v: Optional[int]) -> Optional[int]:
        if v is not None and v not in (1, 2, 3):
            raise ValueError("min_trust must be 1, 2, or 3")
        return v


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/health")
def health():
    issues = []
    try:
        get_r().ping()
    except Exception as exc:
        issues.append(f"redis: {exc}")
    try:
        with db_conn() as conn:
            conn.execute("SELECT 1")
    except Exception as exc:
        issues.append(f"sqlite: {exc}")
    if _refresh_thread is not None and not _refresh_thread.is_alive():
        issues.append("refresh thread is not alive")
    if issues:
        raise HTTPException(
            status_code=503,
            detail={"status": "unhealthy", "issues": issues},
        )
    return {"status": "ok"}


@app.get("/admin/queues")
def queue_status():
    """Return live depth for all work queues and their DLQs."""
    r = get_r()
    result = {}
    for q in _DLQ_QUEUES:
        result[q] = {
            "pending": r.llen(q),
            "processing": r.llen(f"{q}:processing"),
            "dlq": r.llen(f"dlq:{q}"),
        }
    return result


@app.get("/admin/dlq")
def dlq_status():
    """Return DLQ depths and the 10 most recent items for every known queue."""
    r = get_r()
    result = {}
    for q in _DLQ_QUEUES:
        key = f"dlq:{q}"
        depth = r.llen(key)
        raw_items = r.lrange(key, 0, 9)
        result[q] = {"depth": depth, "recent": [_serialize_dlq_entry(raw) for raw in raw_items]}
    return result


@app.post("/admin/dlq/{queue}/requeue")
def requeue_dlq_item(queue: str, body: DlqActionRequest):
    queue_name = _validate_queue_name(queue)
    r = get_r()
    removed = r.lrem(f"dlq:{queue_name}", 1, body.raw)
    if not removed:
        raise HTTPException(status_code=404, detail="DLQ entry not found")
    r.rpush(queue_name, body.raw)
    return {"requeued": True, "queue": queue_name}


@app.post("/admin/dlq/{queue}/dismiss")
def dismiss_dlq_item(queue: str, body: DlqActionRequest):
    queue_name = _validate_queue_name(queue)
    removed = get_r().lrem(f"dlq:{queue_name}", 1, body.raw)
    if not removed:
        raise HTTPException(status_code=404, detail="DLQ entry not found")
    return {"dismissed": True}


@app.get("/admin/failed-jobs")
def list_failed_jobs(limit: int = Query(default=100, ge=1, le=500)):
    with db_conn() as conn:
        rows = conn.execute(
            """
            SELECT id, type, target_ref, payload, failure_reason, retry_count, failed_at
            FROM failed_jobs
            ORDER BY failed_at DESC, id DESC
            LIMIT :lim
            """,
            {"lim": limit},
        ).fetchall()

    result = []
    for row in rows:
        item = dict(row)
        item["payload"] = _decode_json_text(item.get("payload"))
        result.append(item)
    return result


@app.get("/admin/meta")
def admin_meta():
    return {
        "allowed_wordlists": sorted(_ALLOWED_WORDLISTS),
        "allowed_nuclei_templates": sorted(_ALLOWED_NUCLEI_TEMPLATES),
        "recon_interval_hours": RECON_INTERVAL_HOURS,
        "defaults": {
            "window_hours": DEFAULT_WINDOW_HOURS,
            "target_limit": DEFAULT_TARGET_LIMIT,
            "recent_job_limit": DEFAULT_RECENT_JOB_LIMIT,
            "refresh_interval_secs": DEFAULT_REFRESH_INTERVAL_SECS,
        },
        "bounds": {
            "window_hours": {"min": WINDOW_HOURS_BOUNDS[0], "max": WINDOW_HOURS_BOUNDS[1]},
            "target_limit": {"min": TARGET_LIMIT_BOUNDS[0], "max": TARGET_LIMIT_BOUNDS[1]},
            "recent_job_limit": {"min": RECENT_JOB_LIMIT_BOUNDS[0], "max": RECENT_JOB_LIMIT_BOUNDS[1]},
            "refresh_interval_secs": {"min": REFRESH_INTERVAL_BOUNDS[0], "max": REFRESH_INTERVAL_BOUNDS[1]},
        },
    }


@app.get("/admin/progress")
def progress_snapshot(
    target_limit: int = Query(
        default=DEFAULT_TARGET_LIMIT,
        ge=TARGET_LIMIT_BOUNDS[0],
        le=TARGET_LIMIT_BOUNDS[1],
    ),
    recent_job_limit: int = Query(
        default=DEFAULT_RECENT_JOB_LIMIT,
        ge=RECENT_JOB_LIMIT_BOUNDS[0],
        le=RECENT_JOB_LIMIT_BOUNDS[1],
    ),
    window_hours: int = Query(
        default=DEFAULT_WINDOW_HOURS,
        ge=WINDOW_HOURS_BOUNDS[0],
        le=WINDOW_HOURS_BOUNDS[1],
    ),
):
    """
    Consolidated operational snapshot for dashboard rendering.
    Includes queue pressure, job outcomes, recent activity, and per-target metrics.
    """
    r = get_r()
    queues = {}
    for q in _DLQ_QUEUES:
        queues[q] = {
            "pending": r.llen(q),
            "processing": r.llen(f"{q}:processing"),
            "dlq": r.llen(f"dlq:{q}"),
        }

    with db_conn() as conn:
        overview = dict(
            conn.execute(
                """
                SELECT
                  (SELECT COUNT(*) FROM targets) AS targets_total,
                  (SELECT COUNT(*) FROM targets WHERE enabled = 1) AS targets_enabled,
                  (SELECT COUNT(*) FROM subdomains) AS subdomains_total,
                  (SELECT COUNT(*) FROM endpoints) AS endpoints_total,
                  (SELECT COUNT(*) FROM endpoints WHERE alive = 1) AS endpoints_live,
                  (SELECT COUNT(*) FROM findings) AS findings_total,
                  (SELECT COUNT(*) FROM findings WHERE status = 'open') AS findings_open_total,
                  (SELECT COUNT(*) FROM findings
                   WHERE first_seen > datetime('now', :window || ' hours')) AS findings_window,
                  (SELECT COUNT(*) FROM findings
                   WHERE status = 'open'
                     AND first_seen > datetime('now', :window || ' hours')) AS findings_open_window,
                  (SELECT COUNT(*) FROM jobs WHERE status = 'running') AS jobs_running,
                  (SELECT MIN(started_at)
                   FROM jobs
                   WHERE status = 'running' AND started_at IS NOT NULL) AS oldest_running_started_at,
                  (SELECT MAX(finished_at)
                   FROM jobs
                   WHERE finished_at IS NOT NULL) AS last_job_finished_at
                """,
                {"window": f"-{window_hours}"},
            ).fetchone()
        )

        all_time_rows = conn.execute(
            """
            SELECT type, status, COUNT(*) AS count
            FROM jobs
            WHERE type IN ('recon_domain', 'brute_domain', 'probe_host', 'scan_http', 'notify_finding')
            GROUP BY type, status
            """
        ).fetchall()
        window_rows = conn.execute(
            """
            SELECT type, status, COUNT(*) AS count
            FROM jobs
            WHERE type IN ('recon_domain', 'brute_domain', 'probe_host', 'scan_http', 'notify_finding')
              AND created_at > datetime('now', :window || ' hours')
            GROUP BY type, status
            """,
            {"window": f"-{window_hours}"},
        ).fetchall()
        timestamp_rows = conn.execute(
            """
            SELECT
              type,
              MAX(CASE WHEN status = 'done' THEN finished_at END) AS last_done_at,
              MAX(CASE WHEN status = 'failed' THEN finished_at END) AS last_failed_at
            FROM jobs
            WHERE type IN ('recon_domain', 'brute_domain', 'probe_host', 'scan_http', 'notify_finding')
            GROUP BY type
            """
        ).fetchall()
        recent_jobs = conn.execute(
            """
            SELECT id, type, target_ref, status, created_at, started_at, finished_at,
                   retry_count, worker_name
            FROM jobs
            ORDER BY COALESCE(finished_at, started_at, created_at) DESC, id DESC
            LIMIT :lim
            """,
            {"lim": recent_job_limit},
        ).fetchall()
        targets = conn.execute(
            """
            WITH target_enriched AS (
              SELECT
                t.id, t.scope_root, t.enabled, t.created_at, t.notes,
                t.active_recon, t.brute_wordlist, t.nuclei_template,
                COALESCE(sd.subdomain_count, 0) AS subdomain_count,
                COALESCE(ep.live_endpoint_count, 0) AS live_endpoint_count,
                COALESCE(fd.finding_count, 0) AS finding_count,
                COALESCE(fd.finding_open_count, 0) AS finding_open_count,
                (
                  SELECT MAX(j.finished_at)
                  FROM jobs j
                  WHERE j.type = 'recon_domain'
                    AND j.target_ref = t.scope_root
                    AND j.status = 'done'
                ) AS last_recon,
                (
                  SELECT COUNT(*)
                  FROM jobs j
                  WHERE j.type = 'recon_domain'
                    AND j.target_ref = t.scope_root
                    AND j.status = 'done'
                    AND j.finished_at > datetime('now', :window || ' hours')
                ) AS recon_done_window,
                NULLIF(
                  MAX(
                    COALESCE(
                      (
                        SELECT MAX(j.finished_at)
                        FROM jobs j
                        WHERE j.target_ref = t.scope_root
                      ),
                      '1970-01-01 00:00:00'
                    ),
                    COALESCE(sd.last_subdomain_seen, '1970-01-01 00:00:00')
                  ),
                  '1970-01-01 00:00:00'
                ) AS last_activity
              FROM targets t
              LEFT JOIN (
                SELECT target_id, COUNT(*) AS subdomain_count, MAX(last_seen) AS last_subdomain_seen
                FROM subdomains
                GROUP BY target_id
              ) sd ON sd.target_id = t.id
              LEFT JOIN (
                SELECT s.target_id, COUNT(*) AS live_endpoint_count
                FROM endpoints e
                JOIN subdomains s ON s.id = e.subdomain_id
                WHERE e.alive = 1
                GROUP BY s.target_id
              ) ep ON ep.target_id = t.id
              LEFT JOIN (
                SELECT
                  s.target_id,
                  COUNT(*) AS finding_count,
                  SUM(CASE WHEN f.status = 'open' THEN 1 ELSE 0 END) AS finding_open_count
                FROM findings f
                JOIN endpoints e ON e.id = f.endpoint_id
                JOIN subdomains s ON s.id = e.subdomain_id
                GROUP BY s.target_id
              ) fd ON fd.target_id = t.id
            )
            SELECT
              te.*,
              datetime(COALESCE(te.last_recon, te.created_at), :recon_interval || ' hours') AS next_recon_due_at,
              CAST(
                unixepoch(datetime(COALESCE(te.last_recon, te.created_at), :recon_interval || ' hours')) - unixepoch('now')
                AS INTEGER
              ) AS next_recon_in_secs,
              CASE
                WHEN unixepoch(datetime(COALESCE(te.last_recon, te.created_at), :recon_interval || ' hours')) < unixepoch('now')
                THEN 1 ELSE 0
              END AS is_recon_overdue
            FROM target_enriched te
            ORDER BY te.enabled DESC, te.last_activity DESC, te.created_at DESC
            LIMIT :target_limit
            """,
            {
                "window": f"-{window_hours}",
                "target_limit": target_limit,
                "recon_interval": str(RECON_INTERVAL_HOURS),
            },
        ).fetchall()

    pipeline = {
        q: {
            "queue": queues[q],
            "all_time": {"pending": 0, "running": 0, "done": 0, "failed": 0},
            "window": {"pending": 0, "running": 0, "done": 0, "failed": 0},
            "last_done_at": None,
            "last_failed_at": None,
            "done_per_hour_window": 0.0,
        }
        for q in _DLQ_QUEUES
    }

    for row in all_time_rows:
        q, status, count = row["type"], row["status"], row["count"]
        if q in pipeline and status in pipeline[q]["all_time"]:
            pipeline[q]["all_time"][status] = count
    for row in window_rows:
        q, status, count = row["type"], row["status"], row["count"]
        if q in pipeline and status in pipeline[q]["window"]:
            pipeline[q]["window"][status] = count
    for row in timestamp_rows:
        q = row["type"]
        if q in pipeline:
            pipeline[q]["last_done_at"] = row["last_done_at"]
            pipeline[q]["last_failed_at"] = row["last_failed_at"]
    for q in _DLQ_QUEUES:
        pipeline[q]["done_per_hour_window"] = pipeline[q]["window"]["done"] / float(window_hours)

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "window_hours": window_hours,
        "overview": overview,
        "pipeline": pipeline,
        "recent_jobs": [dict(r) for r in recent_jobs],
        "targets": [dict(r) for r in targets],
    }


@app.post("/targets", status_code=201)
def add_target(body: TargetIn):
    with db_conn() as conn:
        existing = conn.execute(
            "SELECT id, enabled FROM targets WHERE scope_root = ?",
            (body.scope_root,),
        ).fetchone()

        if existing:
            if not existing["enabled"]:
                conn.execute(
                    "UPDATE targets SET enabled = 1, notes = ?, active_recon = ?, brute_wordlist = ?, nuclei_template = ? WHERE id = ?",
                    (body.notes, body.active_recon, body.brute_wordlist, body.nuclei_template, existing["id"]),
                )
                target_id = existing["id"]
                logger.info("Re-enabled target %s", body.scope_root)
            else:
                raise HTTPException(status_code=409, detail="Target already exists")
        else:
            target_id = conn.execute(
                "INSERT INTO targets (scope_root, notes, active_recon, brute_wordlist, nuclei_template) VALUES (?, ?, ?, ?, ?)",
                (body.scope_root, body.notes, body.active_recon, body.brute_wordlist, body.nuclei_template),
            ).lastrowid
            logger.info("Added target %s (id=%d)", body.scope_root, target_id)

    enqueue(get_r(), "recon_domain", {"domain": body.scope_root})
    return {"id": target_id, "scope_root": body.scope_root, "queued": True,
            "active_recon": body.active_recon, "brute_wordlist": body.brute_wordlist,
            "nuclei_template": body.nuclei_template}


@app.get("/targets")
def list_targets():
    with db_conn() as conn:
        rows = conn.execute(
            """
            SELECT t.id, t.scope_root, t.created_at, t.enabled, t.notes,
                   t.active_recon, t.brute_wordlist, t.nuclei_template,
                   (SELECT COUNT(*) FROM subdomains s WHERE s.target_id = t.id) AS subdomain_count,
                   (SELECT COUNT(*)
                    FROM findings f
                    JOIN endpoints e ON e.id = f.endpoint_id
                    JOIN subdomains s ON s.id = e.subdomain_id
                    WHERE s.target_id = t.id AND f.status = 'open') AS finding_open_count,
                   (SELECT COUNT(*)
                    FROM endpoints e
                    JOIN subdomains s ON s.id = e.subdomain_id
                    WHERE s.target_id = t.id AND e.alive = 1) AS live_endpoint_count,
                   (SELECT MAX(j.finished_at) FROM jobs j
                    WHERE j.target_ref = t.scope_root AND j.status = 'done') AS last_recon
            FROM targets t
            ORDER BY t.created_at DESC
            """
        ).fetchall()
    return [dict(r) for r in rows]


@app.patch("/targets/{target_id}", status_code=200)
def update_target(target_id: int, body: TargetUpdate):
    with db_conn() as conn:
        row = conn.execute(
            "SELECT id, scope_root FROM targets WHERE id = ?",
            (target_id,),
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Target not found")

        updates = {}
        if body.scope_root is not None:
            existing = conn.execute(
                "SELECT id FROM targets WHERE scope_root = ? AND id != ?",
                (body.scope_root, target_id),
            ).fetchone()
            if existing:
                raise HTTPException(status_code=409, detail="Target already exists")
            updates["scope_root"] = body.scope_root
        if body.notes is not None:
            updates["notes"] = body.notes
        if body.active_recon is not None:
            updates["active_recon"] = body.active_recon
        if body.brute_wordlist is not None:
            updates["brute_wordlist"] = body.brute_wordlist
        if body.nuclei_template is not None:
            updates["nuclei_template"] = body.nuclei_template

        if not updates:
            raise HTTPException(status_code=422, detail="No fields to update")

        set_clause = ", ".join(f"{k} = ?" for k in updates)
        values = list(updates.values()) + [target_id]
        conn.execute(f"UPDATE targets SET {set_clause} WHERE id = ?", values)
        if "scope_root" in updates:
            old_scope_root = row["scope_root"]
            new_scope_root = updates["scope_root"]
            conn.execute(
                "UPDATE jobs SET target_ref = ? WHERE target_ref = ?",
                (new_scope_root, old_scope_root),
            )
            conn.execute(
                "UPDATE failed_jobs SET target_ref = ? WHERE target_ref = ?",
                (new_scope_root, old_scope_root),
            )
        logger.info("Updated target %d: %s", target_id, updates)

        updated = conn.execute(
            "SELECT id, scope_root, notes, active_recon, brute_wordlist, nuclei_template, enabled FROM targets WHERE id = ?",
            (target_id,),
        ).fetchone()
    return dict(updated)


@app.post("/targets/{target_id}/run", status_code=200)
def run_target_now(target_id: int):
    with db_conn() as conn:
        row = conn.execute(
            "SELECT id, scope_root, enabled FROM targets WHERE id = ?",
            (target_id,),
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Target not found")
        if not row["enabled"]:
            raise HTTPException(status_code=409, detail="Target is disabled")

    queued = enqueue(
        get_r(),
        "recon_domain",
        {"domain": row["scope_root"]},
        dedup_key=f"manual:{row['scope_root']}",
        dedup_ttl_secs=RUN_NOW_DEDUP_SECS,
    )
    return {
        "target_id": row["id"],
        "scope_root": row["scope_root"],
        "queued": queued,
        "dedup_suppressed": not queued,
    }


@app.delete("/targets/{target_id}", status_code=200)
def disable_target(target_id: int):
    with db_conn() as conn:
        row = conn.execute("SELECT scope_root FROM targets WHERE id = ?", (target_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Target not found")
        conn.execute("UPDATE targets SET enabled = 0 WHERE id = ?", (target_id,))
    return {"disabled": target_id}


@app.post("/targets/{target_id}/stop", status_code=200)
def stop_target(target_id: int):
    with db_conn() as conn:
        row = conn.execute("SELECT scope_root FROM targets WHERE id = ?", (target_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Target not found")
        conn.execute("UPDATE targets SET enabled = 0 WHERE id = ?", (target_id,))
    scope_root = row["scope_root"]
    drained = _drain_target_queues(get_r(), scope_root)
    logger.info("Stopped target %s — drained %d task(s)", scope_root, drained)
    return {"stopped": True, "scope_root": scope_root, "tasks_drained": drained}


@app.post("/targets/{target_id}/purge", status_code=200)
def purge_target(target_id: int):
    with db_conn() as conn:
        row = conn.execute("SELECT scope_root FROM targets WHERE id = ?", (target_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Target not found")

    scope_root = row["scope_root"]
    paths_to_delete = _collect_target_file_paths(target_id, scope_root)

    with db_conn() as conn:
        subdomain_ids = [r["id"] for r in conn.execute(
            "SELECT id FROM subdomains WHERE target_id = ?", (target_id,)
        ).fetchall()]

        if subdomain_ids:
            ph = ",".join("?" * len(subdomain_ids))
            endpoint_ids = [r["id"] for r in conn.execute(
                f"SELECT id FROM endpoints WHERE subdomain_id IN ({ph})", subdomain_ids
            ).fetchall()]

            if endpoint_ids:
                ep_ph = ",".join("?" * len(endpoint_ids))
                finding_ids = [r["id"] for r in conn.execute(
                    f"SELECT id FROM findings WHERE endpoint_id IN ({ep_ph})", endpoint_ids
                ).fetchall()]

                if finding_ids:
                    fi_ph = ",".join("?" * len(finding_ids))
                    conn.execute(f"DELETE FROM notifications WHERE finding_id IN ({fi_ph})", finding_ids)
                    conn.execute(f"DELETE FROM findings WHERE id IN ({fi_ph})", finding_ids)

                conn.execute(f"DELETE FROM endpoints WHERE id IN ({ep_ph})", endpoint_ids)

            conn.execute(f"DELETE FROM subdomains WHERE id IN ({ph})", subdomain_ids)

        conn.execute("DELETE FROM jobs WHERE target_ref = ?", (scope_root,))
        conn.execute("DELETE FROM failed_jobs WHERE target_ref = ?", (scope_root,))
        conn.execute("DELETE FROM targets WHERE id = ?", (target_id,))

    _drain_target_queues(get_r(), scope_root)
    files_deleted = _delete_file_paths(paths_to_delete)

    logger.info("Purged target %s (id=%d) — %d file(s) deleted", scope_root, target_id, files_deleted)
    return {"purged": True, "scope_root": scope_root, "files_deleted": files_deleted}


@app.get("/targets/{target_id}/jobs")
def target_jobs(target_id: int, limit: int = Query(default=20, le=100)):
    with db_conn() as conn:
        target = conn.execute("SELECT scope_root FROM targets WHERE id = ?", (target_id,)).fetchone()
        if not target:
            raise HTTPException(status_code=404, detail="Target not found")
        rows = conn.execute(
            """
            SELECT id, type, status, created_at, started_at, finished_at, retry_count
            FROM jobs WHERE target_ref = ?
            ORDER BY created_at DESC LIMIT ?
            """,
            (target["scope_root"], limit),
        ).fetchall()
    return [dict(r) for r in rows]


@app.get("/findings")
def list_findings(
    severity: Optional[str] = None,
    status: Optional[str] = None,
    target_id: Optional[int] = None,
    window_hours: Optional[int] = Query(default=None, ge=WINDOW_HOURS_BOUNDS[0], le=WINDOW_HOURS_BOUNDS[1]),
    limit: int = Query(default=50, le=500),
):
    params: dict[str, Any] = {
        "tid": target_id,
        "window": f"-{window_hours}" if window_hours else None,
        "lim": limit,
    }

    severity_values = _parse_csv_values(
        severity,
        allowed=_ALLOWED_FINDING_SEVERITIES,
        field_name="severity",
    )
    status_values = _parse_csv_values(
        status,
        allowed=_ALLOWED_FINDING_STATUSES,
        field_name="status",
    )

    severity_filter = ""
    if severity_values:
        severity_filter = f"AND f.severity IN ({_append_in_clause('severity', severity_values, params)})"

    status_filter = ""
    if status_values:
        status_filter = f"AND f.status IN ({_append_in_clause('status', status_values, params)})"

    target_filter = "AND t.id = :tid" if target_id else ""
    window_filter = "AND f.first_seen > datetime('now', :window || ' hours')" if window_hours else ""
    with db_conn() as conn:
        rows = conn.execute(
            f"""
            SELECT f.id, f.template_id, f.severity, f.status, f.title, f.matched_at,
                   f.first_seen, e.url, e.host, t.id AS target_id, t.scope_root
            FROM findings f
            JOIN endpoints e ON e.id = f.endpoint_id
            JOIN subdomains s ON s.id = e.subdomain_id
            JOIN targets t ON t.id = s.target_id
            WHERE 1=1 {severity_filter} {status_filter} {target_filter} {window_filter}
            ORDER BY f.first_seen DESC LIMIT :lim
            """,
            params,
        ).fetchall()
    return [dict(r) for r in rows]


@app.get("/findings/{finding_id}")
def get_finding_detail(finding_id: int):
    with db_conn() as conn:
        row = conn.execute(
            """
            SELECT f.id, f.endpoint_id, f.scanner, f.template_id, f.severity, f.status, f.title, f.matched_at,
                   f.first_seen, f.last_seen, f.raw_blob_path, f.dedupe_key,
                   e.url, e.host, e.scheme, e.port, e.status_code, e.technologies,
                   s.hostname,
                   t.id AS target_id, t.scope_root
            FROM findings f
            LEFT JOIN endpoints e ON e.id = f.endpoint_id
            LEFT JOIN subdomains s ON s.id = e.subdomain_id
            LEFT JOIN targets t ON t.id = s.target_id
            WHERE f.id = ?
            """,
            (finding_id,),
        ).fetchone()

    if not row:
        raise HTTPException(status_code=404, detail="Finding not found")

    detail = dict(row)
    raw_event, raw_event_error = _load_raw_event_for_finding(detail)
    detail["raw_event"] = raw_event
    detail["raw_event_error"] = raw_event_error
    return detail


@app.patch("/findings/{finding_id}")
def update_finding_status(finding_id: int, body: dict[str, str]):
    status = str(body.get("status", "")).strip().lower()
    if status not in _ALLOWED_FINDING_STATUSES:
        raise HTTPException(
            status_code=400,
            detail=f"status must be one of: {sorted(_ALLOWED_FINDING_STATUSES)}",
        )

    with db_conn() as conn:
        existing = conn.execute("SELECT id FROM findings WHERE id = ?", (finding_id,)).fetchone()
        if not existing:
            raise HTTPException(status_code=404, detail="Finding not found")
        conn.execute(
            "UPDATE findings SET status = ? WHERE id = ?",
            (status, finding_id),
        )
    return get_finding_detail(finding_id)


@app.get("/subdomains")
def list_subdomains(
    target_id: Optional[int] = None,
    status: Optional[str] = None,
    technology: Optional[str] = None,
    search: Optional[str] = None,
    sort_by: str = "last_seen",
    sort_dir: str = "desc",
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=100, le=1000),
):
    normalized_status = _normalize_optional_text(status)
    normalized_technology = _normalize_optional_text(technology)
    normalized_search = _normalize_optional_text(search)
    normalized_sort_by = (_normalize_optional_text(sort_by) or "last_seen").lower()
    normalized_sort_dir = (_normalize_optional_text(sort_dir) or "desc").lower()

    allowed_statuses = {"online", "offline"}
    allowed_sort_fields = {"hostname", "last_seen", "status", "scope_root"}
    allowed_sort_dirs = {"asc", "desc"}

    if normalized_status and normalized_status.lower() not in allowed_statuses:
        raise HTTPException(status_code=400, detail=f"status must be one of: {sorted(allowed_statuses)}")
    if normalized_sort_by not in allowed_sort_fields:
        raise HTTPException(status_code=400, detail=f"sort_by must be one of: {sorted(allowed_sort_fields)}")
    if normalized_sort_dir not in allowed_sort_dirs:
        raise HTTPException(status_code=400, detail=f"sort_dir must be one of: {sorted(allowed_sort_dirs)}")

    params: dict[str, Any] = {
        "limit": limit,
        "offset": offset,
    }
    inner_conditions = []
    outer_conditions = []

    if target_id is not None:
        inner_conditions.append("s.target_id = :target_id")
        params["target_id"] = target_id
    if normalized_search:
        outer_conditions.append("LOWER(sr.hostname) LIKE :search")
        params["search"] = f"%{normalized_search.lower()}%"
    if normalized_status:
        outer_conditions.append("sr.status = :status")
        params["status"] = normalized_status.lower()
    if normalized_technology:
        outer_conditions.append(
            """
            EXISTS (
                SELECT 1
                FROM endpoint_technologies etf
                WHERE etf.subdomain_id = sr.id
                  AND etf.technology = :technology
            )
            """
        )
        params["technology"] = normalized_technology.lower()

    sort_columns = {
        "hostname": "LOWER(sr.hostname)",
        "last_seen": "sr.last_seen",
        "status": "CASE sr.status WHEN 'online' THEN 1 ELSE 0 END",
        "scope_root": "LOWER(sr.scope_root)",
    }
    sort_clause = (
        f"{sort_columns[normalized_sort_by]} {normalized_sort_dir.upper()}, "
        "LOWER(sr.scope_root) ASC, LOWER(sr.hostname) ASC, sr.id ASC"
    )
    inner_where = f"WHERE {' AND '.join(inner_conditions)}" if inner_conditions else ""
    outer_where = f"WHERE {' AND '.join(outer_conditions)}" if outer_conditions else ""

    with db_conn() as conn:
        rows = conn.execute(
            f"""
            WITH endpoint_technologies AS (
                SELECT
                    e.subdomain_id,
                    LOWER(TRIM(CAST(je.value AS TEXT))) AS technology
                FROM endpoints e
                JOIN json_each(CASE WHEN json_valid(e.technologies) THEN e.technologies ELSE '[]' END) je
                WHERE TRIM(CAST(je.value AS TEXT)) <> ''
            ),
            technology_rollups AS (
                SELECT
                    subdomain_id,
                    GROUP_CONCAT(DISTINCT technology) AS technology_csv
                FROM endpoint_technologies
                GROUP BY subdomain_id
            ),
            subdomain_rollups AS (
                SELECT
                    s.id,
                    s.target_id,
                    s.hostname,
                    s.source,
                    s.first_seen,
                    COALESCE(MAX(e.last_seen), s.last_seen) AS last_seen,
                    t.scope_root,
                    COUNT(e.id) AS endpoint_count,
                    SUM(CASE WHEN e.alive = 1 THEN 1 ELSE 0 END) AS alive_endpoint_count,
                    CASE
                        WHEN SUM(CASE WHEN e.alive = 1 THEN 1 ELSE 0 END) > 0 THEN 'online'
                        ELSE 'offline'
                    END AS status
                FROM subdomains s
                JOIN targets t ON t.id = s.target_id
                LEFT JOIN endpoints e ON e.subdomain_id = s.id
                {inner_where}
                GROUP BY s.id, s.target_id, s.hostname, s.source, s.first_seen, s.last_seen, t.scope_root
            )
            SELECT
                sr.id,
                sr.target_id,
                sr.hostname,
                sr.source,
                sr.first_seen,
                sr.last_seen,
                sr.scope_root,
                sr.status,
                sr.endpoint_count,
                COALESCE(sr.alive_endpoint_count, 0) AS alive_endpoint_count,
                COALESCE(tr.technology_csv, '') AS technology_csv
            FROM subdomain_rollups sr
            LEFT JOIN technology_rollups tr ON tr.subdomain_id = sr.id
            {outer_where}
            ORDER BY {sort_clause}
            LIMIT :limit OFFSET :offset
            """,
            params,
        ).fetchall()

    serialized_rows = []
    for row in rows:
        item = dict(row)
        item["technology_tags"] = _parse_technology_csv(item.pop("technology_csv", None))
        serialized_rows.append(item)
    return serialized_rows


@app.get("/subdomains/options")
def list_subdomain_options():
    with db_conn() as conn:
        rows = conn.execute(
            """
            WITH endpoint_technologies AS (
                SELECT DISTINCT
                    LOWER(TRIM(CAST(je.value AS TEXT))) AS technology
                FROM endpoints e
                JOIN json_each(CASE WHEN json_valid(e.technologies) THEN e.technologies ELSE '[]' END) je
                WHERE TRIM(CAST(je.value AS TEXT)) <> ''
            )
            SELECT technology
            FROM endpoint_technologies
            ORDER BY technology ASC
            """
        ).fetchall()

    return {"technologies": [row["technology"] for row in rows]}


# ---------------------------------------------------------------------------
# Companies
# ---------------------------------------------------------------------------

@app.post("/companies")
def create_company(body: CompanyIn):
    r = get_r()
    with db_conn() as conn:
        existing = conn.execute(
            "SELECT id, status FROM companies WHERE name = ?",
            (body.name,),
        ).fetchone()
        if existing:
            if existing["status"] == "running":
                raise HTTPException(status_code=409, detail="Discovery already running for this company")
            conn.execute(
                "UPDATE companies SET status = 'running', last_run_at = datetime('now'), seed_domain = ? WHERE id = ?",
                (body.seed_domain, existing["id"]),
            )
            company_id = existing["id"]
        else:
            company_id = conn.execute(
                "INSERT INTO companies (name, seed_domain, status, last_run_at) VALUES (?, ?, 'running', datetime('now'))",
                (body.name, body.seed_domain),
            ).lastrowid

    r.incr(f"company:{company_id}:pending_jobs")
    enqueue(r, "company_intel", {
        "company_id": company_id,
        "name": body.name,
        "seed_domain": body.seed_domain,
    })
    with db_conn() as conn:
        row = conn.execute("SELECT * FROM companies WHERE id = ?", (company_id,)).fetchone()
    return dict(row)


@app.get("/companies")
def list_companies():
    with db_conn() as conn:
        rows = conn.execute(
            """
            SELECT c.id, c.name, c.status, c.created_at, c.last_run_at,
                   COUNT(CASE WHEN d.status = 'pending' THEN 1 END) AS pending_count
            FROM companies c
            LEFT JOIN discovered_domains d ON d.company_id = c.id
            GROUP BY c.id
            ORDER BY c.created_at DESC, c.id DESC
            """
        ).fetchall()
    return [dict(row) for row in rows]


@app.get("/companies/{company_id}")
def get_company(company_id: int):
    with db_conn() as conn:
        company = conn.execute(
            "SELECT * FROM companies WHERE id = ?",
            (company_id,),
        ).fetchone()
        if not company:
            raise HTTPException(status_code=404, detail="Company not found")

        asns = conn.execute(
            """
            SELECT id, asn, description, cidr_ranges, created_at
            FROM discovered_asns
            WHERE company_id = ?
            ORDER BY asn
            """,
            (company_id,),
        ).fetchall()

        counts = conn.execute(
            """
            SELECT status, COUNT(*) AS cnt
            FROM discovered_domains
            WHERE company_id = ?
            GROUP BY status
            """,
            (company_id,),
        ).fetchall()

        trust_counts = conn.execute(
            """
            SELECT trust_score, COUNT(*) AS cnt
            FROM discovered_domains
            WHERE company_id = ? AND status = 'pending'
            GROUP BY trust_score
            """,
            (company_id,),
        ).fetchall()

    domain_counts = {"pending": 0, "approved": 0, "rejected": 0}
    for row in counts:
        domain_counts[row["status"]] = row["cnt"]

    pending_by_trust = {"high": 0, "medium": 0, "low": 0}
    _trust_labels = {3: "high", 2: "medium", 1: "low"}
    for row in trust_counts:
        label = _trust_labels.get(row["trust_score"], "low")
        pending_by_trust[label] = row["cnt"]
    domain_counts["pending_by_trust"] = pending_by_trust

    asn_rows = []
    for asn in asns:
        item = dict(asn)
        item["cidr_ranges"] = _decode_json_text(item.get("cidr_ranges")) or []
        asn_rows.append(item)

    return {**dict(company), "asns": asn_rows, "domain_counts": domain_counts}


@app.post("/companies/{company_id}/discover")
def rediscover_company(company_id: int):
    with db_conn() as conn:
        company = conn.execute("SELECT * FROM companies WHERE id = ?", (company_id,)).fetchone()
        if not company:
            raise HTTPException(status_code=404, detail="Company not found")
        if company["status"] == "running":
            raise HTTPException(status_code=409, detail="Discovery already running")
        conn.execute(
            "UPDATE companies SET status = 'running', last_run_at = datetime('now') WHERE id = ?",
            (company_id,),
        )

    r = get_r()
    r.incr(f"company:{company_id}:pending_jobs")
    enqueue(r, "company_intel", {
        "company_id": company_id,
        "name": company["name"],
        "seed_domain": company["seed_domain"] if "seed_domain" in company.keys() else None,
    })
    return {"status": "running", "company_id": company_id}


@app.post("/companies/{company_id}/stop", status_code=200)
def stop_company(company_id: int):
    with db_conn() as conn:
        company = conn.execute("SELECT name FROM companies WHERE id = ?", (company_id,)).fetchone()
        if not company:
            raise HTTPException(status_code=404, detail="Company not found")
        conn.execute("UPDATE companies SET status = 'idle' WHERE id = ?", (company_id,))
    drained = _drain_company_queues(get_r(), company_id)
    logger.info("Stopped company %s (id=%d) — drained %d task(s)", company["name"], company_id, drained)
    return {"stopped": True, "company_id": company_id, "tasks_drained": drained}


@app.post("/companies/{company_id}/purge", status_code=200)
def purge_company(company_id: int):
    with db_conn() as conn:
        company = conn.execute("SELECT name FROM companies WHERE id = ?", (company_id,)).fetchone()
        if not company:
            raise HTTPException(status_code=404, detail="Company not found")
        conn.execute("DELETE FROM discovered_emails WHERE company_id = ?", (company_id,))
        conn.execute("DELETE FROM discovered_asns WHERE company_id = ?", (company_id,))
        conn.execute("DELETE FROM discovered_domains WHERE company_id = ?", (company_id,))
        conn.execute("DELETE FROM companies WHERE id = ?", (company_id,))
    _drain_company_queues(get_r(), company_id)
    logger.info("Purged company %s (id=%d)", company["name"], company_id)
    return {"purged": True, "company_id": company_id}


@app.get("/companies/{company_id}/pending")
def list_pending_domains(
    company_id: int,
    limit: int = Query(default=200, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    trust: Optional[int] = Query(default=None, ge=1, le=3),
):
    with db_conn() as conn:
        company = conn.execute("SELECT id FROM companies WHERE id = ?", (company_id,)).fetchone()
        if not company:
            raise HTTPException(status_code=404, detail="Company not found")
        if trust is not None:
            rows = conn.execute(
                """
                SELECT id, domain, ip, source_asn, source, trust_score, trust_signals, status, created_at
                FROM discovered_domains
                WHERE company_id = ? AND status = 'pending' AND trust_score = ?
                ORDER BY domain
                LIMIT ? OFFSET ?
                """,
                (company_id, trust, limit, offset),
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT id, domain, ip, source_asn, source, trust_score, trust_signals, status, created_at
                FROM discovered_domains
                WHERE company_id = ? AND status = 'pending'
                ORDER BY trust_score DESC, domain
                LIMIT ? OFFSET ?
                """,
                (company_id, limit, offset),
            ).fetchall()
    return [dict(r) for r in rows]


def _resolve_domain_ids(conn, company_id: int, body: DomainActionRequest) -> list[int]:
    if body.min_trust is not None:
        rows = conn.execute(
            "SELECT id FROM discovered_domains WHERE company_id = ? AND status = 'pending' AND trust_score >= ?",
            (company_id, body.min_trust),
        ).fetchall()
        return [r["id"] for r in rows]
    if body.all:
        rows = conn.execute(
            "SELECT id FROM discovered_domains WHERE company_id = ? AND status = 'pending'",
            (company_id,),
        ).fetchall()
        return [row["id"] for row in rows]
    if body.domain_ids:
        return body.domain_ids
    raise HTTPException(status_code=400, detail="Provide domain_ids, all=true, or min_trust")


@app.post("/companies/{company_id}/approve")
def approve_domains(company_id: int, body: DomainActionRequest):
    with db_conn() as conn:
        company = conn.execute("SELECT id FROM companies WHERE id = ?", (company_id,)).fetchone()
        if not company:
            raise HTTPException(status_code=404, detail="Company not found")

        ids = _resolve_domain_ids(conn, company_id, body)
        if not ids:
            return {"approved": 0}

        placeholders = ",".join("?" * len(ids))
        rows = conn.execute(
            f"""
            SELECT id, domain
            FROM discovered_domains
            WHERE company_id = ? AND status = 'pending' AND id IN ({placeholders})
            """,
            (company_id, *ids),
        ).fetchall()

    approved = 0
    redis_client = get_r()
    for row in rows:
        domain = row["domain"].strip().lower()
        if not _DOMAIN_RE.match(domain):
            raise HTTPException(status_code=400, detail=f"Invalid discovered domain: {domain}")

        with db_conn() as conn:
            existing = conn.execute(
                "SELECT id, enabled FROM targets WHERE scope_root = ?",
                (domain,),
            ).fetchone()
            if existing and existing["enabled"] == 1:
                pass
            elif existing:
                conn.execute("UPDATE targets SET enabled = 1 WHERE id = ?", (existing["id"],))
            else:
                conn.execute("INSERT INTO targets (scope_root) VALUES (?)", (domain,))

            conn.execute(
                "UPDATE discovered_domains SET status = 'approved' WHERE id = ?",
                (row["id"],),
            )

        enqueue(redis_client, "recon_domain", {"domain": domain}, dedup_key=domain, dedup_ttl_secs=3600)
        approved += 1

    return {"approved": approved}


@app.post("/companies/{company_id}/reject")
def reject_domains(company_id: int, body: DomainActionRequest):
    with db_conn() as conn:
        company = conn.execute("SELECT id FROM companies WHERE id = ?", (company_id,)).fetchone()
        if not company:
            raise HTTPException(status_code=404, detail="Company not found")

        ids = _resolve_domain_ids(conn, company_id, body)
        if not ids:
            return {"rejected": 0}

        placeholders = ",".join("?" * len(ids))
        conn.execute(
            f"""
            UPDATE discovered_domains
            SET status = 'rejected'
            WHERE company_id = ? AND status = 'pending' AND id IN ({placeholders})
            """,
            (company_id, *ids),
        )

    return {"rejected": len(ids)}


app.mount("/ui", StaticFiles(directory=_STATIC_DIR, html=True), name="ui")
