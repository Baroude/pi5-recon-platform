"""
Ingestor — FastAPI service for target submission and periodic refresh scheduling.

Endpoints
---------
  POST /targets              Add a new scope root; enqueues first recon job.
  GET  /targets              List all targets with last-seen job status.
  DELETE /targets/{id}       Disable a target (sets enabled=0).
  GET  /targets/{id}/jobs    Recent jobs for a target.
  GET  /findings             Recent findings (optional ?severity= filter).
  GET  /health               Liveness probe.
"""

import json
import logging
import os
import re
import sys
import threading
import time
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
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("/logs/ingestor.log"),
    ],
)
logger = logging.getLogger("ingestor")

RECON_INTERVAL_HOURS = float(os.environ.get("DEFAULT_RECON_INTERVAL_HOURS", 24))

app = FastAPI(title="Recon Platform Ingestor", version="1.0")

_redis: Optional[redis_lib.Redis] = None
_refresh_thread: Optional[threading.Thread] = None

_DLQ_QUEUES = ["recon_domain", "probe_host", "scan_http", "notify_finding"]


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
            "processing": r.llen(f"processing:{q}"),
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
                    "UPDATE targets SET enabled = 1, notes = ? WHERE id = ?",
                    (body.notes, existing["id"]),
                )
                target_id = existing["id"]
                logger.info("Re-enabled target %s", body.scope_root)
            else:
                raise HTTPException(status_code=409, detail="Target already exists")
        else:
            target_id = conn.execute(
                "INSERT INTO targets (scope_root, notes) VALUES (?, ?)",
                (body.scope_root, body.notes),
            ).lastrowid
            logger.info("Added target %s (id=%d)", body.scope_root, target_id)

    enqueue(get_r(), "recon_domain", {"domain": body.scope_root})
    return {"id": target_id, "scope_root": body.scope_root, "queued": True}


@app.get("/targets")
def list_targets():
    with db_conn() as conn:
        rows = conn.execute(
            """
            SELECT t.id, t.scope_root, t.created_at, t.enabled, t.notes,
                   (SELECT COUNT(*) FROM subdomains s WHERE s.target_id = t.id) AS subdomain_count,
                   (SELECT MAX(j.finished_at) FROM jobs j
                    WHERE j.target_ref = t.scope_root AND j.status = 'done') AS last_recon
            FROM targets t
            ORDER BY t.created_at DESC
            """
        ).fetchall()
    return [dict(r) for r in rows]


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
    limit: int = Query(default=50, le=500),
):
    severity_filter = "AND f.severity = :sev" if severity else ""
    with db_conn() as conn:
        rows = conn.execute(
            f"""
            SELECT f.id, f.template_id, f.severity, f.title, f.matched_at,
                   f.first_seen, e.url, e.host
            FROM findings f
            JOIN endpoints e ON e.id = f.endpoint_id
            WHERE 1=1 {severity_filter}
            ORDER BY f.first_seen DESC LIMIT :lim
            """,
            {"sev": severity, "lim": limit},
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


app.mount("/ui", StaticFiles(directory="/app/static", html=True), name="ui")
