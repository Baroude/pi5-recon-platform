"""
Shared SQLite helpers used by all workers and the ingestor.

WAL mode is set on every connection so multiple workers can write concurrently
without SQLITE_BUSY errors. Connections are short-lived (open → work → close)
to keep lock windows small.
"""

import logging
import os
import sqlite3
from contextlib import contextmanager

logger = logging.getLogger(__name__)

SCHEMA_SQL = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS targets (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scope_root  TEXT    NOT NULL UNIQUE,
    created_at  TEXT    NOT NULL DEFAULT (datetime('now')),
    enabled     INTEGER NOT NULL DEFAULT 1,
    notes       TEXT
);

CREATE TABLE IF NOT EXISTS jobs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    type            TEXT    NOT NULL,
    target_ref      TEXT,
    status          TEXT    NOT NULL DEFAULT 'pending',
    created_at      TEXT    NOT NULL DEFAULT (datetime('now')),
    started_at      TEXT,
    finished_at     TEXT,
    retry_count     INTEGER NOT NULL DEFAULT 0,
    worker_name     TEXT,
    raw_output_path TEXT
);

CREATE TABLE IF NOT EXISTS subdomains (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id  INTEGER NOT NULL REFERENCES targets(id),
    hostname   TEXT    NOT NULL,
    source     TEXT,
    first_seen TEXT    NOT NULL DEFAULT (datetime('now')),
    last_seen  TEXT    NOT NULL DEFAULT (datetime('now')),
    status     TEXT    NOT NULL DEFAULT 'active',
    UNIQUE(target_id, hostname)
);

CREATE TABLE IF NOT EXISTS endpoints (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    subdomain_id INTEGER NOT NULL REFERENCES subdomains(id),
    url          TEXT    NOT NULL UNIQUE,
    scheme       TEXT,
    host         TEXT,
    port         INTEGER,
    title        TEXT,
    technologies TEXT,
    status_code  INTEGER,
    content_hash TEXT,
    first_seen   TEXT    NOT NULL DEFAULT (datetime('now')),
    last_seen    TEXT    NOT NULL DEFAULT (datetime('now')),
    alive        INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS findings (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    endpoint_id   INTEGER REFERENCES endpoints(id),
    scanner       TEXT    NOT NULL DEFAULT 'nuclei',
    template_id   TEXT,
    severity      TEXT,
    title         TEXT,
    matched_at    TEXT,
    first_seen    TEXT    NOT NULL DEFAULT (datetime('now')),
    last_seen     TEXT    NOT NULL DEFAULT (datetime('now')),
    raw_blob_path TEXT,
    dedupe_key    TEXT    UNIQUE
);

CREATE TABLE IF NOT EXISTS failed_jobs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    original_job_id INTEGER,
    type            TEXT    NOT NULL,
    target_ref      TEXT,
    payload         TEXT,
    failure_reason  TEXT,
    retry_count     INTEGER NOT NULL DEFAULT 0,
    failed_at       TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS notifications (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id      INTEGER REFERENCES findings(id),
    channel         TEXT    NOT NULL,
    sent_at         TEXT    NOT NULL DEFAULT (datetime('now')),
    delivery_status TEXT    NOT NULL DEFAULT 'sent'
);
"""


def _db_path() -> str:
    return os.environ.get("SQLITE_PATH", "/data/db/recon.db")


def init_db(path: str = None) -> None:
    p = path or _db_path()
    os.makedirs(os.path.dirname(os.path.abspath(p)), exist_ok=True)
    conn = sqlite3.connect(p)
    conn.executescript(SCHEMA_SQL)
    # Add last_scanned_at to endpoints for nuclei TTL tracking (idempotent migration).
    try:
        conn.execute(
            "ALTER TABLE endpoints ADD COLUMN last_scanned_at DATETIME"
        )
        conn.commit()
    except sqlite3.OperationalError:
        pass  # Column already exists
    conn.commit()
    conn.close()
    logger.info("DB ready: %s", p)


@contextmanager
def db_conn(path: str = None):
    """Context manager: yields a WAL-mode connection, commits on exit."""
    p = path or _db_path()
    conn = sqlite3.connect(p, timeout=15, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=FULL")
    conn.execute("PRAGMA wal_autocheckpoint=100")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=10000")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
