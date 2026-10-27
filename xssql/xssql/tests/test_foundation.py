"""Unit tests for the foundation layer: config, budget, scope, http_client."""
import time

import pytest

from xssql.budget import Budget, ScanBudget
from xssql.config import load_config_from_dict, validate_config
from xssql.errors import (BudgetExceeded, ConfigError, ConsentRequiredError,
                            ScopeViolation)
from xssql.http_client import HttpClient, _TokenBucket
from xssql.models import Finding, ProbeResult, ScanConfig, Severity, VulnType
from xssql.scope import assert_in_scope, host_allowed


# ---------------------------------------------------------------- config
def _cfg(**kw):
    base = dict(target="http://127.0.0.1:5000/", consent=True)
    base.update(kw)
    return ScanConfig(**base)


@pytest.mark.parametrize("field,value", [
    ("max_depth", 11), ("max_depth", -1),
    ("max_pages", 0), ("max_pages", 5000),
    ("rate_limit_rps", 0), ("rate_limit_rps", 200),
    ("request_timeout_s", 0), ("request_timeout_s", 999),
    ("scan_deadline_s", 0), ("scan_deadline_s", 99999),
    ("max_requests", 0),
    ("boolean_threshold", 0.1), ("boolean_threshold", 1.5),
    ("boolean_delta", 0.0),
])
def test_validate_config_rejects_out_of_range(field, value):
    with pytest.raises(ConfigError):
        validate_config(_cfg(**{field: value}))


def test_validate_config_rejects_bad_scheme():
    with pytest.raises(ConfigError):
        validate_config(_cfg(target="ftp://x/"))


def test_validate_config_delta_must_be_below_theta():
    with pytest.raises(ConfigError):
        validate_config(_cfg(boolean_threshold=0.6, boolean_delta=0.6))


def test_load_config_requires_target():
    with pytest.raises(ConfigError):
        load_config_from_dict({"consent": True})


def test_public_summary_masks_cookie():
    cfg = _cfg(cookie="session=abc123")
    assert cfg.public_summary()["cookie"] == "***masked***"


# ---------------------------------------------------------------- budget
def test_budget_request_cap():
    b = Budget(ScanBudget(deadline_s=100, max_requests=2))
    b.spend_request(); b.spend_request()
    assert b.expired
    with pytest.raises(BudgetExceeded):
        b.spend_request()


def test_budget_deadline_expiry_with_fake_clock():
    t = {"v": 0.0}
    b = Budget(ScanBudget(deadline_s=5, max_requests=99), clock=lambda: t["v"])
    assert not b.expired
    t["v"] = 6.0
    assert b.expired
    assert b.remaining_s == 0.0


# ---------------------------------------------------------------- confidence
def test_confidence_band_boundaries():
    def band(c):
        return Finding(VulnType.SQLI_ERROR, Severity.HIGH, c, "u", "GET", "p",
                       __import__("xssql.models", fromlist=["ParamLocation"])
                       .ParamLocation.QUERY, "x", "e").confidence_band
    assert band(0.85) == "confirmed"
    assert band(0.8499) == "probable"
    assert band(0.60) == "probable"
    assert band(0.5999) == "weak"


# ---------------------------------------------------------------- scope
def test_scope_requires_consent():
    with pytest.raises(ConsentRequiredError):
        assert_in_scope("http://127.0.0.1/", _cfg(consent=False))


def test_scope_blocks_external_host():
    with pytest.raises(ScopeViolation):
        assert_in_scope("http://internal.example/", _cfg())


def test_scope_allows_localhost_and_allowlist():
    assert_in_scope("http://127.0.0.1/x", _cfg())
    cfg = _cfg(target="http://127.0.0.1/", allowlist=["lab.test"])
    assert host_allowed("lab.test", cfg)
    assert not host_allowed("evil.test", cfg)


# ---------------------------------------------------------------- rate limit
def test_token_bucket_spaces_calls():
    slept = []
    now = {"v": 0.0}
    tb = _TokenBucket(rps=10, sleep=lambda s: (slept.append(s),
                                               now.__setitem__("v", now["v"] + s)),
                      clock=lambda: now["v"])
    tb.wait()           # first call: no wait
    tb.wait()           # second call: must space by ~0.1s
    assert any(s > 0 for s in slept)


# ---------------------------------------------------------------- http client
class _FakeResp:
    def __init__(self, status_code, url, text="", location=None):
        self.status_code = status_code
        self.url = url
        self.text = text
        self.headers = {"Location": location} if location else {}

    @property
    def is_redirect(self):
        return 300 <= self.status_code < 400


class _FakeSession:
    """Minimal requests.Session stand-in for redirect-scope tests."""

    def __init__(self, redirect_to=None):
        self.redirect_to = redirect_to
        self.requested = []
        self.headers = {}

    def request(self, method, url, params=None, data=None, timeout=None,
                allow_redirects=False):
        self.requested.append((method, url))
        if self.redirect_to:
            return _FakeResp(302, url, location=self.redirect_to)
        return _FakeResp(200, url, text="<html>ok</html>")

    def get(self, url, timeout=None, allow_redirects=False):
        self.requested.append(("GET", url))
        return _FakeResp(200, url, text="<html>followed</html>")

    def close(self):
        pass


def test_http_client_does_not_follow_redirect_off_scope():
    cfg = _cfg(target="http://127.0.0.1:5000/", consent=True)
    budget = Budget(ScanBudget(deadline_s=100, max_requests=100))
    client = HttpClient(cfg, budget, sleep=lambda s: None)
    client._session = _FakeSession(redirect_to="http://evil.example/x")
    r = client.get("http://127.0.0.1:5000/page")
    # fail-closed: the off-scope redirect is not followed
    assert r.status_code == 302
    assert "evil.example" not in r.final_url
    assert not any(u == "http://evil.example/x" for _, u in client._session.requested)


def test_http_client_follows_same_host_redirect():
    cfg = _cfg(target="http://127.0.0.1:5000/", consent=True)
    budget = Budget(ScanBudget(deadline_s=100, max_requests=100))
    client = HttpClient(cfg, budget, sleep=lambda s: None)
    client._session = _FakeSession(redirect_to="http://127.0.0.1:5000/elsewhere")
    r = client.get("http://127.0.0.1:5000/page")
    # same-host (in-scope) redirect IS followed
    assert r.status_code == 200
    assert client._session.requested[-1] == ("GET", "http://127.0.0.1:5000/elsewhere")


def test_http_client_body_truncation_at_boundary():
    cfg = _cfg(target="http://127.0.0.1:5000/", consent=True,
              max_response_bytes=64)
    budget = Budget(ScanBudget(deadline_s=100, max_requests=100))
    client = HttpClient(cfg, budget, sleep=lambda s: None)

    class BigSession(_FakeSession):
        def request(self, method, url, params=None, data=None, timeout=None,
                    allow_redirects=False):
            return _FakeResp(200, url, text="A" * 1000)

    client._session = BigSession()
    r = client.get("http://127.0.0.1:5000/page")
    assert r.truncated is True
    assert len(r.body.encode("utf-8")) <= 64
