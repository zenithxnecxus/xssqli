"""Command-line interface (DESIGN_DOC_V2 §15).

Commands: scan, report, serve, evaluate, version.
Exit codes: 0 ok · 1 runtime error · 2 scope/consent refused · 3 config error.

The ethics gate lives in the engine/scope layer, but the CLI makes consent an
explicit, visible flag (--i-am-authorized) and maps a refusal to exit code 2.
"""
from __future__ import annotations

import argparse
import sys

from . import __version__
from .config import load_config_from_cli
from .errors import ConfigError, EthicsError, ScannerError
from .events import EventType, ScanEvent
from .models import ScanStatus
from .storage import Storage

EXIT_OK, EXIT_ERR, EXIT_SCOPE, EXIT_CONFIG = 0, 1, 2, 3


def _log_event(ev: ScanEvent) -> None:
    quiet = {EventType.PAGE_CRAWLED}
    if ev.type in quiet:
        return
    print(f"  [{ev.type.value}] {ev.message}", file=sys.stderr)


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="xssql",
        description="xssql — web vulnerability scanner (SQLi + XSS + Open Redirect + SSTI). "
                    "For authorized/lab targets only.")
    sub = p.add_subparsers(dest="command", required=True)

    sc = sub.add_parser("scan", help="scan an authorized target")
    sc.add_argument("--target", required=True, help="http(s) URL to scan")
    sc.add_argument("--i-am-authorized", action="store_true",
                    help="REQUIRED consent: you own or may test this target")
    sc.add_argument("--allow", action="append", default=[],
                    help="extra in-scope host (repeatable)")
    sc.add_argument("--max-depth", type=int, default=2)
    sc.add_argument("--max-pages", type=int, default=50)
    sc.add_argument("--rate", type=float, default=5.0, help="requests/sec cap")
    sc.add_argument("--deadline", type=float, default=120.0, help="scan deadline (s)")
    sc.add_argument("--max-requests", type=int, default=2000)
    sc.add_argument("--cookie", default=None, help="session cookie header value")
    sc.add_argument("--db", default="xssql.db")
    sc.add_argument("--report", default=None, help="write HTML report to this path")
    sc.add_argument("--json", default=None, help="write JSON findings to this path")
    sc.add_argument("--pdf", default=None, help="write PDF report to this path")

    rp = sub.add_parser("report", help="(re)generate a report for a scan")
    rp.add_argument("--scan-id", type=int, required=True)
    rp.add_argument("--db", default="xssql.db")
    rp.add_argument("--out", required=True)
    rp.add_argument("--format", choices=["html", "pdf"], default="html",
                    help="output format for --out (default: html)")

    sv = sub.add_parser("serve", help="run the Flask dashboard (localhost)")
    sv.add_argument("--host", default="127.0.0.1")
    sv.add_argument("--port", type=int, default=5050)
    sv.add_argument("--db", default="xssql.db")

    ev = sub.add_parser("evaluate", help="score the scanner against the lab app")
    ev.add_argument("--scan-id", type=int, default=None,
                    help="score an existing scan (default: run a fresh lab scan)")
    ev.add_argument("--db", default="xssql.db")

    sub.add_parser("version", help="print version")
    return p


def _cmd_scan(args) -> int:
    try:
        cfg = load_config_from_cli(args)
    except ConfigError as exc:
        print(f"config error: {exc}", file=sys.stderr)
        return EXIT_CONFIG
    storage = Storage(args.db)
    try:
        from .engine import ScanEngine
        engine = ScanEngine(cfg, storage, emit=_log_event)
        summary = engine.run()
    except EthicsError as exc:
        print(f"refused (scope/consent): {exc}", file=sys.stderr)
        storage.close()
        return EXIT_SCOPE
    except ScannerError as exc:
        print(f"error: {exc}", file=sys.stderr)
        storage.close()
        return EXIT_ERR

    print(f"\nscan #{summary.scan_id}: {summary.status.value}")
    print(f"  endpoints: {summary.endpoints_found}  findings: {summary.findings_total}"
          f"  requests: {summary.requests_sent}  time: {summary.duration_s}s")
    print(f"  by severity: {summary.by_severity}")
    print(f"  by type:     {summary.by_type}")
    if summary.partial_reason:
        print(f"  partial: {summary.partial_reason}")

    from .report import (export_findings_json, export_findings_pdf,
                         render_html_report)
    if args.report:
        render_html_report(storage, summary.scan_id, args.report, cfg)
        print(f"  report: {args.report}")
    if args.json:
        export_findings_json(storage, summary.scan_id, args.json)
        print(f"  json:   {args.json}")
    if args.pdf:
        export_findings_pdf(storage, summary.scan_id, args.pdf)
        print(f"  pdf:    {args.pdf}")
    storage.close()
    return EXIT_OK


def _cmd_report(args) -> int:
    from .report import export_findings_pdf, render_html_report
    storage = Storage(args.db)
    try:
        if args.format == "pdf":
            export_findings_pdf(storage, args.scan_id, args.out)
        else:
            render_html_report(storage, args.scan_id, args.out)
        print(f"report written: {args.out}")
        return EXIT_OK
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERR
    finally:
        storage.close()


def _cmd_serve(args) -> int:
    from .webapp import create_app
    app = create_app(db_path=args.db)
    print(f"dashboard on http://{args.host}:{args.port}  (Ctrl-C to stop)")
    app.run(host=args.host, port=args.port, debug=False)
    return EXIT_OK


def _cmd_evaluate(args) -> int:
    from .evaluate import evaluate_against_lab, score_existing
    if args.scan_id is not None:
        result = score_existing(args.db, args.scan_id)
    else:
        result = evaluate_against_lab(args.db)
    print(result["report_text"])
    return EXIT_OK if result["passed"] else EXIT_ERR


def main(argv=None) -> int:
    args = _build_parser().parse_args(argv)
    if args.command == "version":
        print(__version__)
        return EXIT_OK
    return {
        "scan": _cmd_scan, "report": _cmd_report,
        "serve": _cmd_serve, "evaluate": _cmd_evaluate,
    }[args.command](args)


if __name__ == "__main__":        # pragma: no cover
    sys.exit(main())
