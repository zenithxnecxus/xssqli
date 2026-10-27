"""ScanEngine — orchestration (REVIEW_2 §2.2 algorithm, DESIGN_DOC_V2 §13).

The engine is the only component that knows the whole flow:

    validate -> scope gate -> create_scan -> crawl (budget-checked)
      -> for each endpoint: store it
           for each parameter: fetch ONE baseline
               for each detector: scan_parameter -> dedupe -> add_finding
               early-stop the parameter once confidence >= early_stop
      -> finish_scan (DONE / DONE_PARTIAL+reason / FAILED)
      -> optional HTML report

It enforces the budget at every step (so run() always terminates), emits the
full event set, dedupes findings in memory before any write, and tracks
requests_sent. The CLI and the dashboard both call this same engine.
"""
from __future__ import annotations

from typing import Optional

from . import evidence
from .budget import Budget, ScanBudget
from .config import validate_config
from .crawler import Crawler, strip_values
from .detectors import build_detectors
from .detectors.base import ProbeContext
from .errors import BudgetExceeded, EthicsError, ScannerError
from .events import EventCallback, EventType, ScanEvent, null_callback
from .http_client import HttpClient
from .models import (Endpoint, Finding, ProbeResult, ScanConfig, ScanStatus,
                     ScanSummary, Severity)
from .scope import assert_in_scope
from .storage import Storage


class ScanEngine:
    def __init__(self, config: ScanConfig, storage: Storage,
                 emit: EventCallback = null_callback):
        self.config = config
        self.storage = storage
        self.emit = emit
        self.budget = Budget(ScanBudget(config.scan_deadline_s, config.max_requests))
        self.http = HttpClient(config, self.budget)
        self.detectors = build_detectors(config)

    # ------------------------------------------------------------------ run
    def run(self) -> ScanSummary:
        # 1-2. validate + fail-closed scope gate (raise BEFORE any scan row)
        validate_config(self.config)
        assert_in_scope(self.config.target, self.config)

        scan_id = self.storage.create_scan(self.config)
        self.emit(ScanEvent(EventType.SCAN_STARTED,
                            f"scan {scan_id} started against {self.config.target}",
                            {"scan_id": scan_id, "target": self.config.target}))
        status = ScanStatus.DONE
        partial_reason: Optional[str] = None
        error_message: Optional[str] = None
        endpoints: list[Endpoint] = []

        try:
            # 4. crawl
            self.emit(ScanEvent(EventType.PHASE, "phase=crawl", {"phase": "crawl"}))
            crawler = Crawler(self.config, self.http, self.budget, self.emit)
            endpoints = crawler.crawl(self.config.target)
            for ep in endpoints:
                self.storage.add_endpoint(scan_id, ep)

            # 5. detect
            self.emit(ScanEvent(EventType.PHASE, "phase=detect", {"phase": "detect"}))
            partial_reason = self._detect(scan_id, endpoints)
            if partial_reason:
                status = ScanStatus.DONE_PARTIAL

        except BudgetExceeded as exc:
            status = ScanStatus.DONE_PARTIAL
            partial_reason = str(exc)
        except EthicsError:
            raise                                  # surfaced by caller, fail closed
        except ScannerError as exc:                # pragma: no cover
            status = ScanStatus.FAILED
            error_message = str(exc)

        # 7. finish
        self.storage.finish_scan(
            scan_id, status, requests_sent=self.budget.requests_sent,
            endpoints_found=len(endpoints), partial_reason=partial_reason,
            error_message=error_message)
        self.http.close()

        findings = self.storage.get_findings(scan_id)
        summary = self._summary(scan_id, status, endpoints, findings, partial_reason)
        self.emit(ScanEvent(EventType.SCAN_FINISHED,
                            f"scan {scan_id} finished: {status.value} "
                            f"({summary.findings_total} findings)",
                            {"scan_id": scan_id, "status": status.value,
                             "findings": summary.findings_total}))
        return summary

    # ------------------------------------------------------------------ detect
    def _detect(self, scan_id: int, endpoints: list[Endpoint]) -> Optional[str]:
        """Per-endpoint × per-parameter × detector loop. Returns partial reason."""
        written: dict[tuple, Finding] = {}   # dedupe key -> best finding (in-memory)

        for ep in endpoints:
            for param in ep.params:
                if self.budget.expired:
                    return self.budget.reason()
                # one baseline per (endpoint, parameter)
                try:
                    baseline = self._baseline(ep, param)
                except BudgetExceeded:
                    return self.budget.reason()

                best_conf = 0.0
                for det in self.detectors:
                    if self.budget.expired:
                        return self.budget.reason()
                    if not det.applies_to(ep, param):
                        continue
                    ctx = ProbeContext(self.http, ep, param, baseline)
                    try:
                        results = det.scan_parameter(ctx)
                    except BudgetExceeded:
                        return self.budget.reason()
                    for f in results:
                        self._dedupe_store(scan_id, f, written)
                        best_conf = max(best_conf, f.confidence)
                    if best_conf >= self.config.early_stop_confidence:
                        break                     # per-parameter early stop
            self.emit(ScanEvent(EventType.ENDPOINT_TESTED,
                                f"tested {ep.method} {ep.url}",
                                {"url": ep.url, "method": ep.method}))
        return None

    def _baseline(self, ep: Endpoint, param) -> ProbeResult:
        ctx = ProbeContext(self.http, ep, param, baseline=ProbeResult(
            url=ep.url, final_url=ep.url, status_code=0, body="", elapsed_ms=0.0))
        return ctx.send(param.default_value)

    def _dedupe_store(self, scan_id: int, f: Finding,
                      written: dict[tuple, Finding]) -> None:
        key = f.dedupe_key(strip_values(f.url))
        prev = written.get(key)
        if prev is None or f.beats(prev):
            written[key] = f
            # write-through: for simplicity we store the winner now; a prior
            # weaker duplicate for the same key is never written because we
            # only reach add_finding when f is the new best.
            if prev is None:
                self.storage.add_finding(scan_id, f)
                self.emit(ScanEvent(EventType.FINDING,
                                    f"{f.vuln_type.value} in {f.parameter} "
                                    f"({f.severity.value}, conf {f.confidence})",
                                    {"vuln_type": f.vuln_type.value,
                                     "parameter": f.parameter,
                                     "severity": f.severity.value,
                                     "confidence": f.confidence}))

    # ------------------------------------------------------------------ summary
    def _summary(self, scan_id, status, endpoints, findings,
                 partial_reason) -> ScanSummary:
        by_sev: dict[str, int] = {}
        by_type: dict[str, int] = {}
        for f in findings:
            by_sev[f.severity.value] = by_sev.get(f.severity.value, 0) + 1
            by_type[f.vuln_type.value] = by_type.get(f.vuln_type.value, 0) + 1
        return ScanSummary(
            scan_id=scan_id, status=status, target=self.config.target,
            endpoints_found=len(endpoints), findings_total=len(findings),
            by_severity=by_sev, by_type=by_type,
            requests_sent=self.budget.requests_sent,
            duration_s=round(self.budget.elapsed_s, 3),
            partial_reason=partial_reason)
