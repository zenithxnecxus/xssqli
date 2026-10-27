"""Tests for the reporter (escaping), CLI (args/exit codes), and dashboard."""
import pytest

from xssql.cli import main, _build_parser, EXIT_OK, EXIT_SCOPE, EXIT_CONFIG
from xssql.models import (CWE, Finding, ParamLocation, ReflectionContext,
                            ScanConfig, ScanStatus, Severity, VulnType)
from xssql.report import render_html_report
from xssql.storage import Storage
from xssql.webapp import create_app


# ---------------------------------------------------------------- report
def _seed(tmp_path):
    s = Storage(str(tmp_path / "r.db"))
    sid = s.create_scan(ScanConfig(target="http://127.0.0.1:5000/", consent=True))
    # evidence contains a raw <script> — must be escaped in the report
    s.add_finding(sid, Finding(
        VulnType.XSS_REFLECTED, Severity.HIGH, 0.85,
        "http://127.0.0.1:5000/search?q=", "GET", "q", ParamLocation.QUERY,
        "<script>alert(1)</script>", "reflected <script>alert(1)</script> here",
        reflection_context=None, cwe=CWE[VulnType.XSS_REFLECTED],
        remediation="encode output"))
    s.finish_scan(sid, ScanStatus.DONE, requests_sent=5, endpoints_found=1)
    return s, sid


def test_report_escapes_evidence(tmp_path):
    s, sid = _seed(tmp_path)
    html = render_html_report(s, sid)
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "<script>alert(1)</script>" not in html      # never raw
    s.close()


def test_report_renders_with_zero_findings(tmp_path):
    s = Storage(str(tmp_path / "z.db"))
    sid = s.create_scan(ScanConfig(target="http://127.0.0.1:5000/", consent=True))
    s.finish_scan(sid, ScanStatus.DONE)
    html = render_html_report(s, sid)
    assert "No findings" in html
    s.close()


# ---------------------------------------------------------------- CLI
def test_cli_version(capsys):
    assert main(["version"]) == EXIT_OK
    assert "2.0.0" in capsys.readouterr().out


def test_cli_scan_without_consent_is_scope_exit(tmp_path, capsys):
    code = main(["scan", "--target", "http://127.0.0.1:5000/",
                 "--db", str(tmp_path / "c.db")])
    assert code == EXIT_SCOPE          # consent missing -> fail closed -> 2


def test_cli_scan_bad_config_exit(tmp_path):
    code = main(["scan", "--target", "ftp://x/", "--i-am-authorized",
                 "--db", str(tmp_path / "c.db")])
    assert code == EXIT_CONFIG


def test_parser_requires_subcommand():
    with pytest.raises(SystemExit):
        _build_parser().parse_args([])


# ---------------------------------------------------------------- dashboard
def test_dashboard_consent_unchecked_rejected(tmp_path):
    app = create_app(db_path=str(tmp_path / "w.db"))
    client = app.test_client()
    # no scan row should be created, and status is 400
    resp = client.post("/scan/new", data={"target": "http://127.0.0.1:5000/"})
    assert resp.status_code == 400
    s = Storage(str(tmp_path / "w.db"))
    assert s.list_scans() == []
    s.close()


def test_dashboard_index_and_new_form(tmp_path):
    app = create_app(db_path=str(tmp_path / "w2.db"))
    client = app.test_client()
    assert client.get("/").status_code == 200
    assert b"authorized" in client.get("/scan/new").data.lower()


def test_dashboard_scan_runs_and_redirects(tmp_path):
    from xssql.evaluate import _LabServer, _import_lab
    lab = _import_lab()
    app = create_app(db_path=str(tmp_path / "w3.db"))
    client = app.test_client()
    with _LabServer(lab.create_app()) as srv:
        resp = client.post("/scan/new", data={
            "target": srv.base_url, "i_am_authorized": "1",
            "max_depth": "1", "max_pages": "10"})
    assert resp.status_code == 302
    assert "/scan/" in resp.headers["Location"]


# ---------------------------------------------------------------- SPA shell + static
def test_spa_shell_served_at_root(tmp_path):
    app = create_app(db_path=str(tmp_path / "spa.db"))
    client = app.test_client()
    resp = client.get("/")
    assert resp.status_code == 200
    body = resp.data.decode()
    assert 'id="app"' in body               # SPA mount point
    assert "/static/app.js" in body         # loads the SPA
    assert "/static/styles.css" in body


def test_static_assets_served(tmp_path):
    app = create_app(db_path=str(tmp_path / "spa2.db"))
    client = app.test_client()
    assert client.get("/static/app.js").status_code == 200
    assert client.get("/static/styles.css").status_code == 200
    assert b"renderFindings" in client.get("/static/app.js").data


# ---------------------------------------------------------------- JSON API
def _seed_scan(tmp_path):
    s = Storage(str(tmp_path / "api.db"))
    sid = s.create_scan(ScanConfig(target="http://127.0.0.1:5000/", consent=True))
    s.add_finding(sid, Finding(
        VulnType.XSS_REFLECTED, Severity.HIGH, 0.85,
        "http://127.0.0.1:5000/search?q=", "GET", "q", ParamLocation.QUERY,
        "<svvg/onx=k3v>", "reflected k3v here",
        reflection_context=ReflectionContext.TEXT, cwe=CWE[VulnType.XSS_REFLECTED],
        remediation="encode output"))
    s.finish_scan(sid, ScanStatus.DONE, requests_sent=5, endpoints_found=1)
    s.close()
    return sid


def test_api_scans_list(tmp_path):
    sid = _seed_scan(tmp_path)
    app = create_app(db_path=str(tmp_path / "api.db"))
    client = app.test_client()
    resp = client.get("/api/scans")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["scans"][0]["id"] == sid
    assert data["scans"][0]["findings_count"] == 1


def test_api_scan_detail_payload(tmp_path):
    sid = _seed_scan(tmp_path)
    app = create_app(db_path=str(tmp_path / "api.db"))
    client = app.test_client()
    data = client.get(f"/api/scans/{sid}").get_json()
    assert data["scan"]["id"] == sid
    assert data["scan"]["status"] == "done"
    assert data["scan"]["duration_s"] >= 0.0
    assert len(data["findings"]) == 1
    assert data["by_severity"]["high"] == 1
    assert data["by_type"]["xss_reflected"] == 1
    # evidence is delivered as data (escaping is the SPA's job via textContent)
    assert data["findings"][0]["evidence"] == "reflected k3v here"


def test_api_create_requires_consent(tmp_path):
    app = create_app(db_path=str(tmp_path / "api2.db"))
    client = app.test_client()
    resp = client.post("/api/scans", json={"target": "http://127.0.0.1:5000/"})
    assert resp.status_code == 400            # consent enforced server-side
    assert Storage(str(tmp_path / "api2.db")).list_scans() == []


def test_api_create_runs_scan_against_lab(tmp_path):
    from xssql.evaluate import _LabServer, _import_lab
    lab = _import_lab()
    app = create_app(db_path=str(tmp_path / "api3.db"))
    client = app.test_client()
    with _LabServer(lab.create_app()) as srv:
        resp = client.post("/api/scans", json={
            "target": srv.base_url, "consent": True,
            "max_depth": "1", "max_pages": "10", "deadline": 60, "rate": 50})
    assert resp.status_code == 201
    data = resp.get_json()
    assert data["scan"]["status"] == "done"
    assert len(data["findings"]) > 0
    # no findings should land on /safe-* routes (true negatives)
    assert all("/safe-" not in f["url"] for f in data["findings"])


def test_api_create_caps_deadline_server_side(tmp_path):
    """A direct API call cannot bypass the form's 60 s deadline limit."""
    import json
    db = str(tmp_path / "api4.db")
    app = create_app(db_path=db)
    client = app.test_client()
    # closed local port: the scan finishes immediately with no endpoints
    resp = client.post("/api/scans", json={
        "target": "http://127.0.0.1:9/", "consent": True, "deadline": 3600})
    assert resp.status_code == 201
    cfg = json.loads(Storage(db).list_scans()[0]["config_json"])
    assert cfg["scan_deadline_s"] == 60.0
