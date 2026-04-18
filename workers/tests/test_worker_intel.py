import io
import logging
import sys
import types
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
WORKERS_DIR = ROOT / "workers"

if str(WORKERS_DIR) not in sys.path:
    sys.path.insert(0, str(WORKERS_DIR))

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


from intel import worker as intel_worker


class FakePopen:
    def __init__(self, *_args, **_kwargs):
        self.stdout = io.StringIO("first line\n\nsecond line\n")
        self.stderr = io.StringIO("")
        self.returncode = 0
        self.killed = False

    def wait(self, timeout=None):
        return self.returncode

    def poll(self):
        return self.returncode

    def kill(self):
        self.killed = True
        self.returncode = -9


def test_run_amass_logs_and_returns_each_line(monkeypatch, caplog):
    monkeypatch.setattr(intel_worker.subprocess, "Popen", FakePopen)
    caplog.set_level(logging.INFO, logger=intel_worker.logger.name)

    result = intel_worker._run_amass(["amass", "intel", "-org", "example"])

    assert result == ["first line", "second line"]
    logged = [record.message for record in caplog.records if record.levelno == logging.INFO]
    assert "first line" in logged
    assert "second line" in logged


def test_run_amass_missing_binary_returns_empty_list_and_logs_error(monkeypatch, caplog):
    def _missing_binary(*_args, **_kwargs):
        raise FileNotFoundError

    monkeypatch.setattr(intel_worker.subprocess, "Popen", _missing_binary)
    caplog.set_level(logging.INFO, logger=intel_worker.logger.name)

    result = intel_worker._run_amass(["amass", "intel", "-org", "example"])

    assert result == []
    assert any(
        record.levelno == logging.ERROR and "amass binary not found" in record.message
        for record in caplog.records
    )
