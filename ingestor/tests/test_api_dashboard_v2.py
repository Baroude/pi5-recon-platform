import importlib
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
        json={"nuclei_template": "dns"},
    )
    assert patch_res.status_code == 200
    assert patch_res.json()["nuclei_template"] == "dns"

    list_res = test_client.get("/targets")
    assert list_res.status_code == 200
    row = next(t for t in list_res.json() if t["id"] == target_id)
    assert row["nuclei_template"] == "dns"


def test_findings_supports_severity_target_and_window_filters(client):
    test_client, ingestor_app, _, _ = client
    t1 = _insert_target(ingestor_app, scope_root="alpha.example.com")
    t2 = _insert_target(ingestor_app, scope_root="beta.example.com")

    with ingestor_app.db_conn() as conn:
        s1 = conn.execute(
            "INSERT INTO subdomains (target_id, hostname, source) VALUES (?, ?, ?)",
            (t1, "api.alpha.example.com", "seed"),
        ).lastrowid
        s2 = conn.execute(
            "INSERT INTO subdomains (target_id, hostname, source) VALUES (?, ?, ?)",
            (t2, "api.beta.example.com", "seed"),
        ).lastrowid

        e1 = conn.execute(
            "INSERT INTO endpoints (subdomain_id, url, host, alive) VALUES (?, ?, ?, 1)",
            (s1, "https://api.alpha.example.com", "api.alpha.example.com"),
        ).lastrowid
        e2 = conn.execute(
            "INSERT INTO endpoints (subdomain_id, url, host, alive) VALUES (?, ?, ?, 1)",
            (s2, "https://api.beta.example.com", "api.beta.example.com"),
        ).lastrowid

        conn.execute(
            """
            INSERT INTO findings (endpoint_id, severity, title, first_seen, matched_at, dedupe_key)
            VALUES (?, 'high', 'alpha finding', datetime('now', '-2 hours'), 'https://api.alpha.example.com', 'k1')
            """,
            (e1,),
        )
        conn.execute(
            """
            INSERT INTO findings (endpoint_id, severity, title, first_seen, matched_at, dedupe_key)
            VALUES (?, 'high', 'old beta finding', datetime('now', '-48 hours'), 'https://api.beta.example.com', 'k2')
            """,
            (e2,),
        )
        conn.execute(
            """
            INSERT INTO findings (endpoint_id, severity, title, first_seen, matched_at, dedupe_key)
            VALUES (?, 'low', 'alpha low finding', datetime('now', '-1 hours'), 'https://api.alpha.example.com', 'k3')
            """,
            (e1,),
        )

    res = test_client.get(f"/findings?severity=high&target_id={t1}&window_hours=24&limit=50")
    assert res.status_code == 200
    rows = res.json()
    assert len(rows) == 1
    assert rows[0]["title"] == "alpha finding"
    assert rows[0]["severity"] == "high"
    assert rows[0]["scope_root"] == "alpha.example.com"
