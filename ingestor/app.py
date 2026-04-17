"""
Ingestor — FastAPI service for target submission and periodic refresh scheduling.

Endpoints
---------
  GET  /admin/meta           Dashboard control metadata (limits/defaults/options).
  GET  /admin/progress       Consolidated progress snapshot for UI rendering.
  POST /targets              Add a new scope root; enqueues first recon job.
  GET  /targets              List all targets with last-seen job status.
  PATCH /targets/{id}        Update target scan configuration.
  POST /targets/{id}/run     Trigger an immediate recon enqueue for a target.
  DELETE /targets/{id}       Disable a target (sets enabled=0).
  GET  /targets/{id}/jobs    Recent jobs for a target.
  GET  /findings             Recent findings (supports severity/target/window filters).
  GET  /health               Liveness probe.
"""

import json
import logging
import os
import re
import sys
import threading
import time
from datetime import datetime, timezone
from typing import Optional

import redis as redis_lib
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import RedirectResponse
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

_DLQ_QUEUES = ["recon_domain", "brute_domain", "probe_host", "scan_http", "notify_finding"]

_ALLOWED_WORDLISTS = {"dns-small.txt", "dns-medium.txt", "dns-large.txt"}
_STATIC_DIR = "/app/static" if os.path.isdir("/app/static") else os.path.join(os.path.dirname(__file__), "static")


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


class TargetUpdate(BaseModel):
    active_recon: Optional[bool] = None
    brute_wordlist: Optional[str] = None

    @field_validator("brute_wordlist")
    @classmethod
    def validate_wordlist(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and v not in _ALLOWED_WORDLISTS:
            raise ValueError(f"brute_wordlist must be one of: {sorted(_ALLOWED_WORDLISTS)}")
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
        parsed = []
        for raw in raw_items:
            try:
                parsed.append(json.loads(raw))
            except Exception:
                parsed.append({"raw": raw})
        result[q] = {"depth": depth, "recent": parsed}
    return result


@app.get("/admin/meta")
def admin_meta():
    return {
        "allowed_wordlists": sorted(_ALLOWED_WORDLISTS),
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
                  (SELECT COUNT(*) FROM findings
                   WHERE first_seen > datetime('now', :window || ' hours')) AS findings_window,
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
                t.active_recon, t.brute_wordlist,
                COALESCE(sd.subdomain_count, 0) AS subdomain_count,
                COALESCE(ep.live_endpoint_count, 0) AS live_endpoint_count,
                COALESCE(fd.finding_count, 0) AS finding_count,
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
                SELECT s.target_id, COUNT(*) AS finding_count
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
                    "UPDATE targets SET enabled = 1, notes = ?, active_recon = ?, brute_wordlist = ? WHERE id = ?",
                    (body.notes, body.active_recon, body.brute_wordlist, existing["id"]),
                )
                target_id = existing["id"]
                logger.info("Re-enabled target %s", body.scope_root)
            else:
                raise HTTPException(status_code=409, detail="Target already exists")
        else:
            target_id = conn.execute(
                "INSERT INTO targets (scope_root, notes, active_recon, brute_wordlist) VALUES (?, ?, ?, ?)",
                (body.scope_root, body.notes, body.active_recon, body.brute_wordlist),
            ).lastrowid
            logger.info("Added target %s (id=%d)", body.scope_root, target_id)

    enqueue(get_r(), "recon_domain", {"domain": body.scope_root})
    return {"id": target_id, "scope_root": body.scope_root, "queued": True,
            "active_recon": body.active_recon, "brute_wordlist": body.brute_wordlist}


@app.get("/targets")
def list_targets():
    with db_conn() as conn:
        rows = conn.execute(
            """
            SELECT t.id, t.scope_root, t.created_at, t.enabled, t.notes,
                   t.active_recon, t.brute_wordlist,
                   (SELECT COUNT(*) FROM subdomains s WHERE s.target_id = t.id) AS subdomain_count,
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
        row = conn.execute("SELECT id FROM targets WHERE id = ?", (target_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Target not found")

        updates = {}
        if body.active_recon is not None:
            updates["active_recon"] = body.active_recon
        if body.brute_wordlist is not None:
            updates["brute_wordlist"] = body.brute_wordlist

        if not updates:
            raise HTTPException(status_code=422, detail="No fields to update")

        set_clause = ", ".join(f"{k} = ?" for k in updates)
        values = list(updates.values()) + [target_id]
        conn.execute(f"UPDATE targets SET {set_clause} WHERE id = ?", values)
        logger.info("Updated target %d: %s", target_id, updates)

        updated = conn.execute(
            "SELECT id, scope_root, active_recon, brute_wordlist, enabled FROM targets WHERE id = ?",
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
    target_id: Optional[int] = None,
    window_hours: Optional[int] = Query(default=None, ge=WINDOW_HOURS_BOUNDS[0], le=WINDOW_HOURS_BOUNDS[1]),
    limit: int = Query(default=50, le=500),
):
    severity_filter = "AND f.severity = :sev" if severity else ""
    target_filter = "AND t.id = :tid" if target_id else ""
    window_filter = "AND f.first_seen > datetime('now', :window || ' hours')" if window_hours else ""
    with db_conn() as conn:
        rows = conn.execute(
            f"""
            SELECT f.id, f.template_id, f.severity, f.title, f.matched_at,
                   f.first_seen, e.url, e.host, t.scope_root
            FROM findings f
            JOIN endpoints e ON e.id = f.endpoint_id
            JOIN subdomains s ON s.id = e.subdomain_id
            JOIN targets t ON t.id = s.target_id
            WHERE 1=1 {severity_filter} {target_filter} {window_filter}
            ORDER BY f.first_seen DESC LIMIT :lim
            """,
            {
                "sev": severity,
                "tid": target_id,
                "window": f"-{window_hours}" if window_hours else None,
                "lim": limit,
            },
        ).fetchall()
    return [dict(r) for r in rows]


@app.get("/subdomains")
def list_subdomains(
    target_id: Optional[int] = None,
    limit: int = Query(default=100, le=1000),
):
    where = "WHERE s.target_id = :tid" if target_id else ""
    with db_conn() as conn:
        rows = conn.execute(
            f"""
            SELECT s.id, s.hostname, s.source, s.first_seen, s.last_seen,
                   t.scope_root
            FROM subdomains s
            JOIN targets t ON t.id = s.target_id
            {where}
            ORDER BY s.first_seen DESC LIMIT :lim
            """,
            {"tid": target_id, "lim": limit},
        ).fetchall()
    return [dict(r) for r in rows]


app.mount("/ui", StaticFiles(directory=_STATIC_DIR, html=True), name="ui")
