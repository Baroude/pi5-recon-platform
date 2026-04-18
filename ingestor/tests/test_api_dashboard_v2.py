import importlib
import json
import re
import sys
import types
from pathlib import Path

import pytest
from fastapi.testclient import TestClient


ROOT = Path(__file__).resolve().parents[2]
INGESTOR_DIR = ROOT / "ingestor"
WORKERS_DIR = ROOT / "workers"

if str(WORKERS_DIR) not in sys.path:
    sys.path.insert(0, str(WORKERS_DIR))
if str(INGESTOR_DIR) not in sys.path:
    sys.path.insert(0, str(INGESTOR_DIR))

try:
    import redis  # noqa: F401
except ModuleNotFoundError:
    redis_stub = types.ModuleType("redis")

    class _Redis:  # pragma: no cover - shim for environments without redis package
        pass

    def _from_url(*_args, **_kwargs):
        return _Redis()

    redis_stub.Redis = _Redis
    redis_stub.from_url = _from_url
    redis_stub.ConnectionError = Exception
    sys.modules["redis"] = redis_stub


class FakeRedis:
    def __init__(self):
        self.lists = {}

    def ping(self):
        return True

    def llen(self, key):
        return len(self.lists.get(key, []))

    def lrange(self, key, start, end):
        values = self.lists.get(key, [])
        if end < 0:
            end = len(values) - 1
        return values[start:end + 1]

    def rpush(self, key, *values):
        bucket = self.lists.setdefault(key, [])
        bucket.extend(values)
        return len(bucket)

    def lrem(self, key, count, value):
        values = list(self.lists.get(key, []))
        removed = 0
        remaining = []

        if count == 0:
            for item in values:
                if item == value:
                    removed += 1
                else:
                    remaining.append(item)
        elif count > 0:
            for item in values:
                if item == value and removed < count:
                    removed += 1
                    continue
                remaining.append(item)
        else:
            to_remove = abs(count)
            reversed_remaining = []
            for item in reversed(values):
                if item == value and removed < to_remove:
                    removed += 1
                    continue
                reversed_remaining.append(item)
            remaining = list(reversed(reversed_remaining))

        self.lists[key] = remaining
        return removed

    def lpush(self, key, *values):
        bucket = self.lists.setdefault(key, [])
        for v in reversed(values):
            bucket.insert(0, v)
        return len(bucket)

    def delete(self, *keys):
        deleted = 0
        for key in keys:
            if key in self.lists:
                del self.lists[key]
                deleted += 1
        return deleted


@pytest.fixture
def app_ctx(tmp_path, monkeypatch):
    monkeypatch.setenv("INGESTOR_DISABLE_STARTUP", "1")
    monkeypatch.setenv("SQLITE_PATH", str(tmp_path / "recon.db"))
    monkeypatch.setenv("DEFAULT_RECON_INTERVAL_HOURS", "24")

    if "app" in sys.modules:
        del sys.modules["app"]
    ingestor_app = importlib.import_module("app")
    ingestor_app = importlib.reload(ingestor_app)
    ingestor_app.init_db()

    fake_redis = FakeRedis()
    monkeypatch.setattr(ingestor_app, "get_r", lambda: fake_redis)

    enqueued = []

    def fake_enqueue(r, queue, payload, dedup_key=None, dedup_ttl_secs=0):
        enqueued.append(
            {
                "queue": queue,
                "payload": payload,
                "dedup_key": dedup_key,
                "dedup_ttl_secs": dedup_ttl_secs,
            }
        )
        return True

    monkeypatch.setattr(ingestor_app, "enqueue", fake_enqueue)
    return ingestor_app, fake_redis, enqueued


@pytest.fixture
def client(app_ctx):
    ingestor_app, fake_redis, enqueued = app_ctx
    with TestClient(ingestor_app.app) as test_client:
        yield test_client, ingestor_app, fake_redis, enqueued


def _insert_target(
    ingestor_app,
    scope_root="example.com",
    enabled=1,
    active_recon=0,
    wordlist="dns-small.txt",
    nuclei_template="all",
):
    with ingestor_app.db_conn() as conn:
        return conn.execute(
            """
            INSERT INTO targets (scope_root, enabled, notes, active_recon, brute_wordlist, nuclei_template)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (scope_root, enabled, "note", active_recon, wordlist, nuclei_template),
        ).lastrowid


def _insert_endpoint(ingestor_app, target_id, hostname):
    with ingestor_app.db_conn() as conn:
        subdomain_id = conn.execute(
            "INSERT INTO subdomains (target_id, hostname, source) VALUES (?, ?, ?)",
            (target_id, hostname, "seed"),
        ).lastrowid
        endpoint_id = conn.execute(
            "INSERT INTO endpoints (subdomain_id, url, host, alive) VALUES (?, ?, ?, 1)",
            (subdomain_id, f"https://{hostname}", hostname),
        ).lastrowid
    return endpoint_id


def _insert_finding(ingestor_app, endpoint_id, template_id="test-tpl", raw_blob_path=None):
    with ingestor_app.db_conn() as conn:
        return conn.execute(
            "INSERT INTO findings (endpoint_id, template_id, severity, matched_at, raw_blob_path, dedupe_key) VALUES (?, ?, ?, ?, ?, ?)",
            (endpoint_id, template_id, "high", "https://example.com", raw_blob_path, f"key-{template_id}-{endpoint_id}"),
        ).lastrowid


def _insert_notification(ingestor_app, finding_id):
    with ingestor_app.db_conn() as conn:
        return conn.execute(
            "INSERT INTO notifications (finding_id, channel, delivery_status) VALUES (?, ?, ?)",
            (finding_id, "telegram", "sent"),
        ).lastrowid


def test_run_target_now_enqueues_for_enabled_target(client):
    test_client, ingestor_app, _, enqueued = client
    target_id = _insert_target(ingestor_app, scope_root="enabled.example.com", enabled=1)

    res = test_client.post(f"/targets/{target_id}/run")
    assert res.status_code == 200
    body = res.json()
    assert body["target_id"] == target_id
    assert body["scope_root"] == "enabled.example.com"
    assert body["queued"] is True
    assert body["dedup_suppressed"] is False

    assert len(enqueued) == 1
    assert enqueued[0]["queue"] == "recon_domain"
    assert enqueued[0]["payload"] == {"domain": "enabled.example.com"}
    assert enqueued[0]["dedup_key"] == "manual:enabled.example.com"


def test_run_target_now_404_for_unknown_target(client):
    test_client, _, _, _ = client
    res = test_client.post("/targets/9999/run")
    assert res.status_code == 404


def test_run_target_now_409_for_disabled_target(client):
    test_client, ingestor_app, _, _ = client
    target_id = _insert_target(ingestor_app, scope_root="disabled.example.com", enabled=0)
    res = test_client.post(f"/targets/{target_id}/run")
    assert res.status_code == 409


def test_admin_meta_returns_expected_keys(client):
    test_client, _, _, _ = client
    res = test_client.get("/admin/meta")
    assert res.status_code == 200
    body = res.json()

    assert "allowed_wordlists" in body
    assert set(body["allowed_wordlists"]) == {"dns-small.txt", "dns-medium.txt", "dns-large.txt"}
    assert "allowed_nuclei_templates" in body
    assert set(body["allowed_nuclei_templates"]) == {"all", "dns", "http", "network", "ssl"}
    assert "defaults" in body
    assert "bounds" in body
    assert "recon_interval_hours" in body

    for key in ("window_hours", "target_limit", "recent_job_limit", "refresh_interval_secs"):
        assert key in body["defaults"]
        assert key in body["bounds"]
        assert "min" in body["bounds"][key]
        assert "max" in body["bounds"][key]


def test_progress_contains_target_schedule_and_throughput_fields(client):
    test_client, ingestor_app, _, _ = client
    _insert_target(
        ingestor_app,
        scope_root="sched.example.com",
        enabled=1,
        active_recon=1,
        wordlist="dns-medium.txt",
        nuclei_template="http",
    )

    with ingestor_app.db_conn() as conn:
        conn.execute(
            """
            INSERT INTO jobs (type, target_ref, status, created_at, started_at, finished_at, worker_name)
            VALUES ('recon_domain', 'sched.example.com', 'done',
                    datetime('now', '-1 hour'), datetime('now', '-59 minutes'),
                    datetime('now', '-55 minutes'), 'worker-recon')
            """
        )
        conn.execute(
            """
            INSERT INTO jobs (type, target_ref, status, created_at, started_at, worker_name)
            VALUES ('scan_http', 'sched.example.com', 'running',
                    datetime('now', '-10 minutes'), datetime('now', '-8 minutes'), 'worker-nuclei')
            """
        )

    res = test_client.get("/admin/progress?window_hours=24&target_limit=200&recent_job_limit=60")
    assert res.status_code == 200
    body = res.json()

    assert "overview" in body
    assert "oldest_running_started_at" in body["overview"]
    assert "last_job_finished_at" in body["overview"]
    assert "findings_open_total" in body["overview"]
    assert "findings_open_window" in body["overview"]

    recon_stage = body["pipeline"]["recon_domain"]
    assert isinstance(recon_stage["done_per_hour_window"], float)
    assert recon_stage["done_per_hour_window"] > 0

    target = next(t for t in body["targets"] if t["scope_root"] == "sched.example.com")
    assert target["active_recon"] == 1
    assert target["brute_wordlist"] == "dns-medium.txt"
    assert target["nuclei_template"] == "http"
    assert "next_recon_due_at" in target
    assert "next_recon_in_secs" in target
    assert "is_recon_overdue" in target
    assert "finding_open_count" in target
    assert isinstance(target["next_recon_in_secs"], int)


def test_target_create_update_and_list_include_nuclei_template(client):
    test_client, _, _, enqueued = client

    create_res = test_client.post(
        "/targets",
        json={
            "scope_root": "templated.example.com",
            "active_recon": True,
            "brute_wordlist": "dns-large.txt",
            "nuclei_template": "ssl",
        },
    )
    assert create_res.status_code == 201
    created = create_res.json()
    assert created["nuclei_template"] == "ssl"
    assert enqueued[-1]["queue"] == "recon_domain"
    assert enqueued[-1]["payload"] == {"domain": "templated.example.com"}

    target_id = created["id"]
    patch_res = test_client.patch(
        f"/targets/{target_id}",
        json={
            "scope_root": "renamed.example.com",
            "notes": "Updated note",
            "nuclei_template": "dns",
        },
    )
    assert patch_res.status_code == 200
    assert patch_res.json()["nuclei_template"] == "dns"
    assert patch_res.json()["scope_root"] == "renamed.example.com"
    assert patch_res.json()["notes"] == "Updated note"

    list_res = test_client.get("/targets")
    assert list_res.status_code == 200
    row = next(t for t in list_res.json() if t["id"] == target_id)
    assert row["nuclei_template"] == "dns"
    assert row["scope_root"] == "renamed.example.com"
    assert row["notes"] == "Updated note"


def test_findings_support_csv_severity_status_target_and_window_filters(client):
    test_client, ingestor_app, _, _ = client
    t1 = _insert_target(ingestor_app, scope_root="alpha.example.com")
    t2 = _insert_target(ingestor_app, scope_root="beta.example.com")
    e1 = _insert_endpoint(ingestor_app, t1, "api.alpha.example.com")
    e2 = _insert_endpoint(ingestor_app, t2, "api.beta.example.com")

    with ingestor_app.db_conn() as conn:
        conn.execute(
            """
            INSERT INTO findings (endpoint_id, severity, status, title, first_seen, matched_at, dedupe_key)
            VALUES (?, 'high', 'open', 'alpha finding', datetime('now', '-2 hours'), 'https://api.alpha.example.com', 'k1')
            """,
            (e1,),
        )
        conn.execute(
            """
            INSERT INTO findings (endpoint_id, severity, status, title, first_seen, matched_at, dedupe_key)
            VALUES (?, 'high', 'false_positive', 'old beta finding', datetime('now', '-48 hours'), 'https://api.beta.example.com', 'k2')
            """,
            (e2,),
        )
        conn.execute(
            """
            INSERT INTO findings (endpoint_id, severity, status, title, first_seen, matched_at, dedupe_key)
            VALUES (?, 'low', 'triaged', 'alpha low finding', datetime('now', '-1 hours'), 'https://api.alpha.example.com', 'k3')
            """,
            (e1,),
        )

    res = test_client.get(
        f"/findings?severity=high,critical&status=open,triaged&target_id={t1}&window_hours=24&limit=50"
    )
    assert res.status_code == 200
    rows = res.json()
    assert len(rows) == 1
    assert rows[0]["title"] == "alpha finding"
    assert rows[0]["severity"] == "high"
    assert rows[0]["status"] == "open"
    assert rows[0]["scope_root"] == "alpha.example.com"


def test_get_finding_detail_and_patch_include_status(client):
    test_client, ingestor_app, _, _ = client
    target_id = _insert_target(ingestor_app, scope_root="detail.example.com")
    endpoint_id = _insert_endpoint(ingestor_app, target_id, "app.detail.example.com")

    with ingestor_app.db_conn() as conn:
        finding_id = conn.execute(
            """
            INSERT INTO findings (endpoint_id, severity, status, title, matched_at, dedupe_key)
            VALUES (?, 'medium', 'open', 'detail finding', 'https://app.detail.example.com', 'detail-key')
            """,
            (endpoint_id,),
        ).lastrowid

    detail_res = test_client.get(f"/findings/{finding_id}")
    assert detail_res.status_code == 200
    assert detail_res.json()["status"] == "open"

    patch_res = test_client.patch(f"/findings/{finding_id}", json={"status": "fixed"})
    assert patch_res.status_code == 200
    assert patch_res.json()["status"] == "fixed"

    confirm_res = test_client.get(f"/findings/{finding_id}")
    assert confirm_res.status_code == 200
    assert confirm_res.json()["status"] == "fixed"


def test_patch_finding_rejects_invalid_status(client):
    test_client, ingestor_app, _, _ = client
    target_id = _insert_target(ingestor_app, scope_root="invalid-status.example.com")
    endpoint_id = _insert_endpoint(ingestor_app, target_id, "api.invalid-status.example.com")

    with ingestor_app.db_conn() as conn:
        finding_id = conn.execute(
            """
            INSERT INTO findings (endpoint_id, severity, status, title, matched_at, dedupe_key)
            VALUES (?, 'low', 'open', 'invalid status finding', 'https://api.invalid-status.example.com', 'invalid-status-key')
            """,
            (endpoint_id,),
        ).lastrowid

    patch_res = test_client.patch(f"/findings/{finding_id}", json={"status": "ignored"})
    assert patch_res.status_code == 400


def test_admin_dlq_returns_raw_and_payload_and_supports_requeue(client):
    test_client, _, fake_redis, _ = client
    raw = '{"hostname":"sub.example.com","retry_count":2}'
    fake_redis.rpush("dlq:recon_domain", raw)

    status_res = test_client.get("/admin/dlq")
    assert status_res.status_code == 200
    recent = status_res.json()["recon_domain"]["recent"]
    assert recent == [{"raw": raw, "payload": {"hostname": "sub.example.com", "retry_count": 2}}]

    requeue_res = test_client.post("/admin/dlq/recon_domain/requeue", json={"raw": raw})
    assert requeue_res.status_code == 200
    assert requeue_res.json() == {"requeued": True, "queue": "recon_domain"}
    assert fake_redis.lists["dlq:recon_domain"] == []
    assert fake_redis.lists["recon_domain"] == [raw]


def test_admin_dlq_dismiss_404s_when_entry_missing(client):
    test_client, _, fake_redis, _ = client
    fake_redis.rpush("dlq:scan_http", '{"url":"https://stale.example.com"}')

    dismiss_res = test_client.post(
        "/admin/dlq/scan_http/dismiss",
        json={"raw": '{"url":"https://missing.example.com"}'},
    )
    assert dismiss_res.status_code == 404
    assert fake_redis.lists["dlq:scan_http"] == ['{"url":"https://stale.example.com"}']


def test_admin_failed_jobs_returns_parsed_payload(client):
    test_client, ingestor_app, _, _ = client

    with ingestor_app.db_conn() as conn:
        conn.execute(
            """
            INSERT INTO failed_jobs (type, target_ref, payload, failure_reason, retry_count, failed_at)
            VALUES ('scan_http', 'corp.example.com', '{"url":"https://corp.example.com","attempt":3}', 'timeout', 2, datetime('now', '-5 minutes'))
            """
        )

    res = test_client.get("/admin/failed-jobs?limit=100")
    assert res.status_code == 200
    rows = res.json()
    assert len(rows) == 1
    assert rows[0]["type"] == "scan_http"
    assert rows[0]["failure_reason"] == "timeout"
    assert rows[0]["payload"] == {"url": "https://corp.example.com", "attempt": 3}


def test_progress_counts_only_open_findings(client):
    test_client, ingestor_app, _, _ = client
    target_id = _insert_target(ingestor_app, scope_root="open-counts.example.com")
    endpoint_id = _insert_endpoint(ingestor_app, target_id, "api.open-counts.example.com")

    with ingestor_app.db_conn() as conn:
        conn.execute(
            """
            INSERT INTO findings (endpoint_id, severity, status, title, first_seen, matched_at, dedupe_key)
            VALUES (?, 'high', 'open', 'fresh open', datetime('now', '-2 hours'), 'https://api.open-counts.example.com/a', 'open-a')
            """,
            (endpoint_id,),
        )
        conn.execute(
            """
            INSERT INTO findings (endpoint_id, severity, status, title, first_seen, matched_at, dedupe_key)
            VALUES (?, 'medium', 'open', 'old open', datetime('now', '-72 hours'), 'https://api.open-counts.example.com/b', 'open-b')
            """,
            (endpoint_id,),
        )
        conn.execute(
            """
            INSERT INTO findings (endpoint_id, severity, status, title, first_seen, matched_at, dedupe_key)
            VALUES (?, 'low', 'fixed', 'fixed finding', datetime('now', '-1 hour'), 'https://api.open-counts.example.com/c', 'fixed-c')
            """,
            (endpoint_id,),
        )

    res = test_client.get("/admin/progress?window_hours=24&target_limit=200&recent_job_limit=60")
    assert res.status_code == 200
    body = res.json()

    assert body["overview"]["findings_open_total"] == 2
    assert body["overview"]["findings_open_window"] == 1
    target = next(t for t in body["targets"] if t["id"] == target_id)
    assert target["finding_open_count"] == 2


def test_stop_target_disables_and_drains(client):
    test_client, ingestor_app, fake_redis, _ = client
    target_id = _insert_target(ingestor_app, scope_root="stop.example.com", enabled=1)

    # Pre-populate queues with tasks for this target and a different target
    fake_redis.lpush("recon_domain", json.dumps({"domain": "stop.example.com"}))
    fake_redis.lpush("recon_domain", json.dumps({"domain": "other.example.com"}))
    fake_redis.lpush("probe_host", json.dumps({"hostname": "sub.stop.example.com", "scope_root": "stop.example.com"}))
    fake_redis.lpush("probe_host:processing", json.dumps({"hostname": "sub2.stop.example.com", "scope_root": "stop.example.com"}))

    res = test_client.post(f"/targets/{target_id}/stop")
    assert res.status_code == 200
    body = res.json()
    assert body["stopped"] is True
    assert body["scope_root"] == "stop.example.com"
    assert body["tasks_drained"] == 3  # recon + probe + probe:processing

    # Target should be disabled in DB
    with ingestor_app.db_conn() as conn:
        row = conn.execute("SELECT enabled FROM targets WHERE id = ?", (target_id,)).fetchone()
    assert row["enabled"] == 0

    # Unrelated task should survive
    assert fake_redis.llen("recon_domain") == 1
    remaining = json.loads(fake_redis.lrange("recon_domain", 0, 0)[0])
    assert remaining["domain"] == "other.example.com"


def test_stop_target_404(client):
    test_client, _, _, _ = client
    res = test_client.post("/targets/9999/stop")
    assert res.status_code == 404


def test_stop_target_already_disabled_is_idempotent(client):
    test_client, ingestor_app, _, _ = client
    target_id = _insert_target(ingestor_app, scope_root="disabled.example.com", enabled=0)
    res = test_client.post(f"/targets/{target_id}/stop")
    assert res.status_code == 200
    assert res.json()["stopped"] is True
    with ingestor_app.db_conn() as conn:
        row = conn.execute("SELECT enabled FROM targets WHERE id = ?", (target_id,)).fetchone()
    assert row["enabled"] == 0


def test_purge_target_removes_all_data(client, tmp_path, monkeypatch):
    test_client, ingestor_app, fake_redis, _ = client

    # Point OUTPUT_DIR to tmp_path so file deletion is testable
    monkeypatch.setattr(ingestor_app, "_OUTPUT_DIR", str(tmp_path))

    target_id = _insert_target(ingestor_app, scope_root="purge.example.com", enabled=1)
    endpoint_id = _insert_endpoint(ingestor_app, target_id, "sub.purge.example.com")

    # Create a real file that should be deleted
    raw_blob = tmp_path / "purge.example.com_nuclei.jsonl"
    raw_blob.write_text('{"template-id": "test"}\n')
    finding_id = _insert_finding(ingestor_app, endpoint_id, raw_blob_path=str(raw_blob))
    notification_id = _insert_notification(ingestor_app, finding_id)

    # Add a queue task for this target
    fake_redis.lpush("recon_domain", json.dumps({"domain": "purge.example.com"}))

    res = test_client.post(f"/targets/{target_id}/purge")
    assert res.status_code == 200
    body = res.json()
    assert body["purged"] is True
    assert body["scope_root"] == "purge.example.com"
    assert body["files_deleted"] == 1

    # DB records gone
    with ingestor_app.db_conn() as conn:
        assert conn.execute("SELECT id FROM notifications WHERE finding_id = ?", (finding_id,)).fetchone() is None
        assert conn.execute("SELECT id FROM targets WHERE id = ?", (target_id,)).fetchone() is None
        assert conn.execute("SELECT id FROM subdomains WHERE target_id = ?", (target_id,)).fetchone() is None
        assert conn.execute("SELECT id FROM endpoints WHERE id = ?", (endpoint_id,)).fetchone() is None
        assert conn.execute("SELECT id FROM findings WHERE endpoint_id = ?", (endpoint_id,)).fetchone() is None

    # File deleted
    assert not raw_blob.exists()

    # Queue drained
    assert fake_redis.llen("recon_domain") == 0


def test_purge_target_404(client):
    test_client, _, _, _ = client
    res = test_client.post("/targets/9999/purge")
    assert res.status_code == 404


def test_purge_target_no_data(client):
    """Purge a target with no subdomains/findings — should succeed cleanly."""
    test_client, ingestor_app, _, _ = client
    target_id = _insert_target(ingestor_app, scope_root="bare.example.com", enabled=1)
    res = test_client.post(f"/targets/{target_id}/purge")
    assert res.status_code == 200
    body = res.json()
    assert body["purged"] is True
    assert body["files_deleted"] == 0
    with ingestor_app.db_conn() as conn:
        assert conn.execute("SELECT id FROM targets WHERE id = ?", (target_id,)).fetchone() is None


@pytest.mark.parametrize(
    ("path", "data_page"),
    [
        ("/ui/index.html", "dashboard"),
        ("/ui/findings.html", "findings"),
        ("/ui/targets.html", "targets"),
        ("/ui/ops.html", "ops"),
    ],
)
def test_shared_refresh_shell(client, path, data_page):
    test_client, _, _, _ = client
    res = test_client.get(path)
    assert res.status_code == 200

    html = res.text
    nav_match = re.search(r'<nav class="nav-links" aria-label="Primary">(.*?)</nav>', html, re.S)
    assert nav_match is not None

    nav_html = nav_match.group(1)
    anchors = list(re.finditer(r'<a\b([^>]*)>(.*?)</a>', nav_html, re.S))
    current_links = []
    for anchor in anchors:
        attrs = anchor.group(1)
        href_match = re.search(r'href="([^"]+)"', attrs)
        assert href_match is not None
        if 'aria-current="page"' in attrs:
            current_links.append(href_match.group(1))

    expected_current_href = {
        "/ui/index.html": "/ui/index.html",
        "/ui/findings.html": "/ui/findings.html",
        "/ui/targets.html": "/ui/targets.html",
        "/ui/ops.html": "/ui/ops.html",
    }[path]

    assert f'<body data-page="{data_page}"' in html
    assert '/ui/app.css' in html
    assert '/ui/app.js' in html
    assert 'class="topbar"' in html
    assert 'class="page-header panel"' in html
    assert 'class="page-header-copy"' in html
    assert 'class="page-header-actions"' in html
    assert len(current_links) == 1
    assert current_links[0] == expected_current_href


def test_refresh_tokens_and_layout_hooks(client):
    test_client, _, _, _ = client
    res = test_client.get("/ui/app.css")
    assert res.status_code == 200

    css = res.text
    for marker in [
        "--app-bg:",
        "--app-surface-muted:",
        "--app-accent-soft:",
        ".page-header {",
        ".page-header-copy {",
        ".page-header-actions {",
        ".page-section {",
        ".table-actions.compact {",
        ".inspector-panel {",
    ]:
        assert marker in css
