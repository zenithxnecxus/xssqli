"""Flask dashboard (DESIGN_DOC_V2 §15 / REVIEW_2 extension).

A small single-page frontend (vanilla JS, no build step) served at `/`,
backed by a JSON API that drives the SAME ScanEngine the CLI uses. Consent
is enforced server-side on every path that can start a scan (`POST
/scan/new` and `POST /api/scans`) — an unchecked box or missing `consent`
key is always rejected with 400 *before* any scan row is created, matching
the CLI's fail-closed ethics gate.

Routes
------
GET  /                     SPA shell (history + detail views, client-routed)
GET  /scan/new              plain HTML "start a scan" form
POST /scan/new               run a scan from form data -> redirect to /scan/<id>
GET  /scan/<id>              SPA shell (client reads the id from the URL)
GET  /scan/<id>/report.html  self-contained HTML report (download)
GET  /scan/<id>/report.pdf   PDF report (download) — new in xssql
GET  /scan/<id>/findings.json JSON findings export (download)
GET  /api/scans              scan history (list)
GET  /api/scans/<id>         scan detail: scan + findings + breakdowns
POST /api/scans               run a scan from a JSON body -> 201 + detail
"""
from __future__ import annotations

import os

from flask import (Flask, Response, abort, jsonify, redirect,
                   render_template_string, request)

from ..config import load_config_from_dict
from ..engine import ScanEngine
from ..errors import ConfigError, EthicsError, ScannerError
from ..report import export_findings_json, export_findings_pdf, render_html_report
from ..storage import Storage

_WEB_DEADLINE_CAP_S = 60.0     # a dashboard-initiated scan never runs longer
_WEB_REQUEST_CAP = 1500        # ...nor sends more requests than this


def create_app(db_path: str = "xssql.db") -> Flask:
    static_dir = os.path.join(os.path.dirname(__file__), "static")
    app = Flask(__name__, static_folder=static_dir, static_url_path="/static")

    # ------------------------------------------------------------- helpers
    def _cfg_dict(mapping, consent_key: str) -> dict:
        def num(key, default, cast):
            v = mapping.get(key, default)
            try:
                return cast(v)
            except (TypeError, ValueError):
                return default

        d = {
            "target": mapping.get("target", "") or "",
            "consent": bool(mapping.get(consent_key)),
            "max_depth": num("max_depth", 2, int),
            "max_pages": num("max_pages", 50, int),
            "rate_limit_rps": num("rate", 5.0, float),
            "scan_deadline_s": min(num("deadline", _WEB_DEADLINE_CAP_S, float),
                                   _WEB_DEADLINE_CAP_S),
            "max_requests": min(num("max_requests", _WEB_REQUEST_CAP, int),
                                _WEB_REQUEST_CAP),
        }
        cookie = mapping.get("cookie")
        if cookie:
            d["cookie"] = cookie
        allow = mapping.get("allow")
        if allow:
            d["allowlist"] = [h.strip() for h in str(allow).split(",") if h.strip()]
        return d

    def _run_scan(cfg_dict: dict):
        cfg = load_config_from_dict(cfg_dict)
        storage = Storage(db_path)
        try:
            return ScanEngine(cfg, storage).run()
        finally:
            storage.close()

    def _scan_payload(storage: Storage, scan_id: int):
        scan = storage.get_scan(scan_id)
        if scan is None:
            return None
        findings = storage.get_findings_raw(scan_id)
        by_severity: dict = {}
        by_type: dict = {}
        for f in findings:
            by_severity[f["severity"]] = by_severity.get(f["severity"], 0) + 1
            by_type[f["vuln_type"]] = by_type.get(f["vuln_type"], 0) + 1
        started = scan.get("started_at") or 0.0
        finished = scan.get("finished_at")
        scan_out = dict(scan)
        scan_out["duration_s"] = round(finished - started, 3) if finished else 0.0
        return {"scan": scan_out, "findings": findings,
                "endpoints": storage.get_endpoints(scan_id),
                "by_severity": by_severity, "by_type": by_type}

    # ------------------------------------------------------------- SPA shell
    @app.get("/")
    def index():
        return render_template_string(_SHELL_HTML)

    @app.get("/scan/<int:scan_id>")
    def scan_detail_page(scan_id):
        return render_template_string(_SHELL_HTML)

    # ------------------------------------------------------------- new-scan form
    @app.get("/scan/new")
    def new_scan_form():
        return render_template_string(_NEW_SCAN_HTML)

    @app.post("/scan/new")
    def submit_scan_form():
        if not request.form.get("i_am_authorized"):
            return ("Authorization required: tick \"I am authorized to test "
                    "this target\" before scanning.", 400)
        cfg_dict = _cfg_dict(request.form, "i_am_authorized")
        try:
            summary = _run_scan(cfg_dict)
        except (ConfigError, EthicsError) as exc:
            return (str(exc), 400)
        except ScannerError as exc:                       # pragma: no cover
            return (str(exc), 500)
        return redirect(f"/scan/{summary.scan_id}", code=302)

    # ------------------------------------------------------------- downloads
    @app.get("/scan/<int:scan_id>/report.html")
    def download_html(scan_id):
        storage = Storage(db_path)
        try:
            html = render_html_report(storage, scan_id)
        except ValueError:
            abort(404)
        finally:
            storage.close()
        return Response(html, mimetype="text/html")

    @app.get("/scan/<int:scan_id>/report.pdf")
    def download_pdf(scan_id):
        storage = Storage(db_path)
        try:
            pdf_bytes = export_findings_pdf(storage, scan_id)
        except ValueError:
            abort(404)
        finally:
            storage.close()
        return Response(pdf_bytes, mimetype="application/pdf", headers={
            "Content-Disposition": f'attachment; filename="scan-{scan_id}.pdf"'})

    @app.get("/scan/<int:scan_id>/findings.json")
    def download_json(scan_id):
        storage = Storage(db_path)
        try:
            text = export_findings_json(storage, scan_id)
        except ValueError:
            abort(404)
        finally:
            storage.close()
        return Response(text, mimetype="application/json")

    # ------------------------------------------------------------- JSON API
    @app.get("/api/scans")
    def api_scans():
        storage = Storage(db_path)
        rows = storage.list_scans()
        storage.close()
        return jsonify({"scans": rows})

    @app.get("/api/scans/<int:scan_id>")
    def api_scan_detail(scan_id):
        storage = Storage(db_path)
        payload = _scan_payload(storage, scan_id)
        storage.close()
        if payload is None:
            abort(404)
        return jsonify(payload)

    @app.post("/api/scans")
    def api_create_scan():
        data = request.get_json(silent=True) or {}
        if not data.get("consent"):
            return jsonify({"error": "consent required (set \"consent\": true)"}), 400
        cfg_dict = _cfg_dict(data, "consent")
        try:
            summary = _run_scan(cfg_dict)
        except (ConfigError, EthicsError) as exc:
            return jsonify({"error": str(exc)}), 400
        except ScannerError as exc:                        # pragma: no cover
            return jsonify({"error": str(exc)}), 500
        storage = Storage(db_path)
        payload = _scan_payload(storage, summary.scan_id)
        storage.close()
        return jsonify(payload), 201

    return app


# ---------------------------------------------------------------- templates
_SHELL_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>xssql dashboard</title>
  <link rel="stylesheet" href="/static/styles.css">
</head>
<body>
  <div id="app">Loading…</div>
  <script src="/static/app.js"></script>
</body>
</html>"""

_NEW_SCAN_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>New scan · xssql</title>
  <link rel="stylesheet" href="/static/styles.css">
</head>
<body>
  <main class="wrap">
    <h1>xssql — new scan</h1>
    <p class="warn">Only scan systems you own or are explicitly
       <strong>authorized</strong> to test. Unauthorized scanning may be
       illegal.</p>
    <form method="post" action="/scan/new" class="card">
      <label>Target URL
        <input type="url" name="target" placeholder="http://127.0.0.1:5000/" required>
      </label>
      <label class="checkbox">
        <input type="checkbox" name="i_am_authorized" value="1">
        I am authorized to test this target
      </label>
      <label>Max depth <input type="number" name="max_depth" value="2"></label>
      <label>Max pages <input type="number" name="max_pages" value="50"></label>
      <label>Rate (req/s) <input type="number" name="rate" value="5" step="0.1"></label>
      <label>Deadline (s, capped at 60) <input type="number" name="deadline" value="60"></label>
      <label>Cookie <input type="text" name="cookie" placeholder="optional"></label>
      <button type="submit">Start scan</button>
    </form>
    <p><a href="/">&larr; back to dashboard</a></p>
  </main>
</body>
</html>"""
