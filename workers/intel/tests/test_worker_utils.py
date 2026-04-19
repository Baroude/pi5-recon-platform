"""
Unit tests for pure utility functions in worker-intel.
Stubs redis and requests at module level so worker.py can be imported
without a running Redis or network.
"""

import os
import sys
import types
from pathlib import Path

# ── Path + env setup (must happen before importing worker) ────────────────────
_PROJ_ROOT = Path(__file__).resolve().parents[3]
os.environ.setdefault("LOG_DIR", str(_PROJ_ROOT / "logs"))
os.environ.setdefault("SQLITE_PATH", str(_PROJ_ROOT / "tests" / "test_utils.db"))

sys.path.insert(0, str(_PROJ_ROOT / "workers"))
sys.path.insert(0, str(_PROJ_ROOT / "workers" / "intel"))

# Stub redis
if "redis" not in sys.modules:
    _r = types.ModuleType("redis")
    class _FakeR:
        def incr(self, *a): pass
        def decr(self, *a): return 1
        def delete(self, *a): pass
    _r.Redis = _FakeR
    _r.from_url = lambda *a, **kw: _FakeR()
    _r.ConnectionError = Exception
    sys.modules["redis"] = _r

# Stub requests
if "requests" not in sys.modules:
    _req = types.ModuleType("requests")
    _req.get = lambda *a, **kw: None
    _req.post = lambda *a, **kw: None
    sys.modules["requests"] = _req

import pytest
import worker
from worker import _compute_trust, _extract_root_domain, _resolve_lei


# ---------------------------------------------------------------------------
# _extract_root_domain
# ---------------------------------------------------------------------------

def test_extract_strips_wildcard():
    assert _extract_root_domain("*.kering.com") == "kering.com"

def test_extract_keeps_apex():
    assert _extract_root_domain("kering.com") == "kering.com"

def test_extract_strips_subdomain():
    assert _extract_root_domain("api.gucci.com") == "gucci.com"

def test_extract_handles_deep_subdomain():
    assert _extract_root_domain("a.b.c.kering.com") == "kering.com"

def test_extract_lowercases():
    assert _extract_root_domain("KERING.COM") == "kering.com"

def test_extract_rejects_legal_entity_suffix():
    assert _extract_root_domain("Kering S.A.") == ""

def test_extract_rejects_invalid_trailing_dot_root():
    assert _extract_root_domain("a.") == ""

def test_extract_handles_common_second_level_suffix_com_cn():
    assert _extract_root_domain("api.alexandermcqueen.com.cn") == "alexandermcqueen.com.cn"

def test_extract_handles_common_second_level_suffix_co_uk():
    assert _extract_root_domain("login.example.co.uk") == "example.co.uk"

def test_extract_keeps_valid_country_tld_domain():
    assert _extract_root_domain("icat.sowind.ch") == "sowind.ch"


# ---------------------------------------------------------------------------
# _compute_trust
# ---------------------------------------------------------------------------

def test_trust_cert_org_match_is_high():
    score, signals = _compute_trust("gucci.com", "Kering", "kering.com", "crt_org")
    assert score == 3
    assert "cert_org_match" in signals

def test_trust_seed_subdomain_is_high():
    score, signals = _compute_trust("api.kering.com", "Kering", "kering.com", "crt_seed")
    assert score == 3
    assert "seed_match" in signals

def test_trust_seed_exact_match_is_high():
    score, signals = _compute_trust("kering.com", "Kering", "kering.com", "crt_seed")
    assert score == 3
    assert "seed_match" in signals

def test_trust_name_in_domain_is_medium():
    score, signals = _compute_trust("keringapps.com", "Kering", "kering.com", "crt_seed")
    assert score == 2
    assert "name_contains_target" in signals

def test_trust_pivot_1_is_medium():
    score, signals = _compute_trust("unrelated.com", "Kering", "kering.com", "pivot_1")
    assert score == 2
    assert "pivot_1" in signals

def test_trust_pivot_2_is_always_low():
    score, signals = _compute_trust("keringtest.com", "Kering", "kering.com", "pivot_2")
    assert score == 1
    assert "pivot_2" in signals

def test_trust_no_signals_is_low():
    score, signals = _compute_trust("randomdomain.com", "Kering", "kering.com", "crt_seed")
    assert score == 1

def test_trust_no_seed_domain():
    score, signals = _compute_trust("kering.com", "Kering", None, "crt_org")
    assert score == 3
    assert "cert_org_match" in signals

def test_trust_short_company_name_not_matched():
    # "ab" is < 4 chars, should not match "abcdef.com"
    score, signals = _compute_trust("abcdef.com", "AB", None, "crt_seed")
    assert "name_contains_target" not in signals


# ---------------------------------------------------------------------------
# _resolve_lei
# ---------------------------------------------------------------------------

def test_resolve_lei_uses_fuzzy_id_directly(monkeypatch):
    def fake_get_json(url, headers=None, params=None):
        if "fuzzycompletions" in url:
            return {"data": [{"id": "549300VGEJKB7SVUZR78"}]}
        raise AssertionError("lei-records fallback should not be called")

    monkeypatch.setattr(worker, "_get_json", fake_get_json)
    assert _resolve_lei("Kering") == "549300VGEJKB7SVUZR78"


def test_resolve_lei_falls_back_to_lei_records_when_fuzzy_has_no_id(monkeypatch):
    calls = []

    def fake_get_json(url, headers=None, params=None):
        calls.append((url, params))
        if "fuzzycompletions" in url:
            return {
                "data": [
                    {"type": "fuzzycompletions", "attributes": {"value": "KERING"}}
                ]
            }
        if "lei-records" in url:
            return {"data": [{"id": "549300VGEJKB7SVUZR78"}]}
        return None

    monkeypatch.setattr(worker, "_get_json", fake_get_json)
    assert _resolve_lei("Kering") == "549300VGEJKB7SVUZR78"
    assert any("lei-records" in url for url, _ in calls)


def test_resolve_lei_returns_none_when_no_match(monkeypatch):
    def fake_get_json(url, headers=None, params=None):
        if "fuzzycompletions" in url:
            return {"data": [{"attributes": {"value": "UNKNOWN ENTITY"}}]}
        if "lei-records" in url:
            return {"data": []}
        return None

    monkeypatch.setattr(worker, "_get_json", fake_get_json)
    assert _resolve_lei("Unknown Corp") is None
