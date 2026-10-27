"""Unit tests for crawler extraction/dedupe and storage CRUD (WAL)."""
import sqlite3

from xssql.budget import Budget, ScanBudget
from xssql.crawler import Crawler, strip_values
from xssql.models import (Endpoint, Finding, ParamLocation, Parameter,
                            ProbeResult, ScanConfig, ScanStatus, Severity,
                            VulnType, CWE)
from xssql.storage import Storage


class FakeHttp:
    """Serves canned HTML bodies by URL path for crawler tests."""
    def __init__(self, pages):
        self.pages = pages

    def get(self, url, params=None, is_probe=False):
        from urllib.parse import urlsplit
        path = urlsplit(url).path or "/"
        body = self.pages.get(path, "")
        return ProbeResult(url=url, final_url=url, status_code=200 if body else 404,
                           body=body, elapsed_ms=1.0)

    def post(self, *a, **k):
        return ProbeResult("", "", 0, "", 0.0)


def _cfg():
    return ScanConfig(target="http://127.0.0.1:5000/", consent=True,
                      max_depth=2, max_pages=20)


def test_crawler_extracts_links_and_forms_and_dedupes():
    pages = {
        "/": (
            '<a href="/user?id=1">u</a>'
            '<a href="/user?id=2">u2</a>'          # same identity -> dedupe
            '<a href="/search?q=x">s</a>'
            '<a href="mailto:a@b.c">mail</a>'       # skipped
            '<a href="javascript:void(0)">js</a>'  # skipped
            '<form method="post" action="/login">'
            '<input name="username"><input name="password">'
            '<input type="submit"></form>'
        ),
        "/user": "<html>u</html>",
        "/search": "<html>s</html>",
        "/login": "<html>l</html>",
    }
    budget = Budget(ScanBudget(60, 2000))
    c = Crawler(_cfg(), FakeHttp(pages), budget)
    eps = c.crawl("http://127.0.0.1:5000/")

    sigs = {(e.method, strip_values(e.url), frozenset(p.name for p in e.params))
            for e in eps}
    # GET /user?id (deduped to one), GET /search?q, POST /login
    assert ("GET", "http://127.0.0.1:5000/user?id=", frozenset({"id"})) in sigs
    assert ("GET", "http://127.0.0.1:5000/search?q=", frozenset({"q"})) in sigs
    post = [e for e in eps if e.method == "POST"]
    assert len(post) == 1
    assert {p.name for p in post[0].params} == {"username", "password"}
    assert post[0].params[0].location == ParamLocation.FORM_BODY


def test_crawler_excludes_patterns():
    pages = {"/": '<a href="/logout?x=1">out</a><a href="/user?id=1">u</a>',
             "/user": "x", "/logout": "x"}
    cfg = _cfg(); cfg.exclude_url_patterns = ["/logout"]
    c = Crawler(cfg, FakeHttp(pages), Budget(ScanBudget(60, 2000)))
    eps = c.crawl("http://127.0.0.1:5000/")
    assert all("logout" not in e.url for e in eps)


# ---------------------------------------------------------------- storage
def _finding():
    return Finding(VulnType.SQLI_ERROR, Severity.HIGH, 0.90,
                   "http://127.0.0.1:5000/user?id=", "GET", "id",
                   ParamLocation.QUERY, "'", "db error snippet",
                   cwe=CWE[VulnType.SQLI_ERROR], remediation="use params")


def test_storage_wal_mode(tmp_path):
    db = str(tmp_path / "s.db")
    s = Storage(db)
    mode = s._conn.execute("PRAGMA journal_mode").fetchone()[0]
    assert mode.lower() == "wal"
    s.close()


def test_storage_crud_roundtrip(tmp_path):
    s = Storage(str(tmp_path / "s.db"))
    cfg = _cfg()
    sid = s.create_scan(cfg)
    s.add_endpoint(sid, Endpoint("http://127.0.0.1:5000/user?id=", "GET",
                                 [Parameter("id", ParamLocation.QUERY, "1")]))
    s.add_finding(sid, _finding())
    s.finish_scan(sid, ScanStatus.DONE, requests_sent=10, endpoints_found=1)

    scan = s.get_scan(sid)
    assert scan["status"] == "done"
    assert scan["requests_sent"] == 10
    eps = s.get_endpoints(sid)
    assert eps[0]["params"][0]["name"] == "id"
    fs = s.get_findings(sid)
    assert fs[0].vuln_type == VulnType.SQLI_ERROR
    assert fs[0].confidence == 0.90
    s.close()


def test_storage_concurrent_reader_under_wal(tmp_path):
    db = str(tmp_path / "s.db")
    writer = Storage(db)
    sid = writer.create_scan(_cfg())
    reader = sqlite3.connect(db)          # separate connection reads during write
    writer.add_finding(sid, _finding())
    rows = reader.execute("SELECT COUNT(*) FROM findings WHERE scan_id=?",
                          (sid,)).fetchone()
    assert rows[0] == 1
    reader.close(); writer.close()
