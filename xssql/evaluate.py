"""Evaluation harness: score the scanner against the ground-truth lab app.

`evaluate_against_lab` starts the bundled vulnerable lab app on a loopback
port, runs a full scan through the SAME ScanEngine the CLI/dashboard use, then
computes precision / recall / F1 against GROUND_TRUTH and checks the true
negatives on /safe-* routes. This turns the success criteria in REVIEW_2 §3.2
into a one-command, reproducible measurement.
"""
from __future__ import annotations

import os
import socket
import sys
import threading
import time
from wsgiref.simple_server import make_server, WSGIRequestHandler

from .config import load_config_from_dict
from .engine import ScanEngine
from .storage import Storage

# precision/recall/F1 targets (REVIEW_2 §3.2)
TARGET_PRECISION = 0.90
TARGET_RECALL = 0.80
TARGET_F1 = 0.85
TARGET_WALLCLOCK_S = 60.0


def _import_lab():
    """Locate tests/vuln_app.py relative to the repo and import it."""
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if repo_root not in sys.path:
        sys.path.insert(0, repo_root)
    from tests import vuln_app          # type: ignore
    return vuln_app


class _QuietHandler(WSGIRequestHandler):
    def log_message(self, *a):          # silence per-request logging
        return


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class _LabServer:
    """Context manager running the lab app on 127.0.0.1:<port> in a thread."""

    def __init__(self, app):
        self.port = _free_port()
        self._srv = make_server("127.0.0.1", self.port, app,
                                handler_class=_QuietHandler)
        self._thread = threading.Thread(target=self._srv.serve_forever,
                                        daemon=True)

    def __enter__(self):
        self._thread.start()
        time.sleep(0.3)
        return self

    def __exit__(self, *exc):
        self._srv.shutdown()

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.port}/"


def run_lab_scan(db_path: str = ":memory:", *, deadline_s: float = 60.0):
    """Run one full scan against a fresh lab server. Returns (storage, summary, lab)."""
    lab = _import_lab()
    app = lab.create_app()
    storage = Storage(db_path)
    with _LabServer(app) as srv:
        cfg = load_config_from_dict({
            "target": srv.base_url, "consent": True,
            "max_depth": 2, "max_pages": 30, "rate_limit_rps": 50.0,
            "scan_deadline_s": deadline_s, "max_requests": 4000,
        })
        summary = ScanEngine(cfg, storage).run()
    return storage, summary, lab


def _format(metrics, summary, lab, safe_fps) -> dict:
    passed = (metrics.precision >= TARGET_PRECISION
              and metrics.recall >= TARGET_RECALL
              and metrics.f1 >= TARGET_F1
              and not safe_fps
              and summary.duration_s <= TARGET_WALLCLOCK_S)

    def row(name, value, target, ok):
        mark = "PASS" if ok else "FAIL"
        return f"  {name:<22} {value:<10} target {target:<10} [{mark}]"

    lines = [
        "=" * 64,
        "  EVALUATION vs ground-truth lab app",
        "=" * 64,
        row("Precision", metrics.precision, f">= {TARGET_PRECISION}",
            metrics.precision >= TARGET_PRECISION),
        row("Recall", metrics.recall, f">= {TARGET_RECALL}",
            metrics.recall >= TARGET_RECALL),
        row("F1", metrics.f1, f">= {TARGET_F1}",
            metrics.f1 >= TARGET_F1),
        row("True negatives", "ok" if not safe_fps else f"{len(safe_fps)} FP",
            "0 FP", not safe_fps),
        row("Wall-clock (s)", summary.duration_s, f"<= {TARGET_WALLCLOCK_S}",
            summary.duration_s <= TARGET_WALLCLOCK_S),
        f"  TP={metrics.tp}  FP={metrics.fp}  FN={metrics.fn}  "
        f"requests={summary.requests_sent}  endpoints={summary.endpoints_found}",
        "-" * 64,
        "  Per-class:",
    ]
    for cls, m in metrics.by_type.items():
        lines.append(f"    {cls:<6} P={m['precision']:<6} R={m['recall']:<6} "
                     f"F1={m['f1']:<6} (tp={m['tp']} fp={m['fp']} fn={m['fn']})")
    if safe_fps:
        lines.append("  !! False positives on /safe-* routes:")
        for e in safe_fps:
            lines.append(f"       {e}")
    if metrics.false_positive_endpoints:
        lines.append("  False positives:")
        for e in metrics.false_positive_endpoints:
            lines.append(f"       {e}")
    lines.append("=" * 64)
    lines.append(f"  RESULT: {'PASS' if passed else 'FAIL'}")
    lines.append("=" * 64)
    return {"passed": passed, "report_text": "\n".join(lines),
            "metrics": metrics}


def _safe_route_fps(findings, lab) -> list[str]:
    from urllib.parse import urlsplit
    out = []
    for f in findings:
        path = urlsplit(f.url).path
        if any(path.endswith(sr) for sr in lab.SAFE_ROUTES):
            out.append(f"{f.method} {path}?{f.parameter}")
    return out


def evaluate_against_lab(db_path: str = "xssql.db") -> dict:
    storage, summary, lab = run_lab_scan(db_path)
    findings = storage.get_findings(summary.scan_id)
    metrics = lab.compute_metrics(findings)
    safe_fps = _safe_route_fps(findings, lab)
    result = _format(metrics, summary, lab, safe_fps)
    storage.close()
    return result


def score_existing(db_path: str, scan_id: int) -> dict:
    lab = _import_lab()
    storage = Storage(db_path)
    scan = storage.get_scan(scan_id)
    if scan is None:
        storage.close()
        return {"passed": False, "report_text": f"no scan #{scan_id}"}
    findings = storage.get_findings(scan_id)
    metrics = lab.compute_metrics(findings)
    safe_fps = _safe_route_fps(findings, lab)

    class _S:  # minimal shim for formatting
        duration_s = 0.0
        requests_sent = scan.get("requests_sent", 0)
        endpoints_found = scan.get("endpoints_found", 0)
    result = _format(metrics, _S(), lab, safe_fps)
    storage.close()
    return result
