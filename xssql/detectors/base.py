"""Detector base: ProbeContext + the Detector contract every class implements.

A detector never touches HttpClient directly. It only sees a ProbeContext
bound to one (endpoint, parameter) pair, and calls ctx.send(value) to issue
exactly one request with *value* substituted for that parameter (every other
parameter on the endpoint stays at its crawled default). That narrow surface
is what keeps detectors unit-testable with a scripted fake (see
tests/test_detectors.py) and keeps every probe automatically bound by the
engine's budget / rate-limit / scope rules, since those all live inside
HttpClient and the detector never bypasses it.
"""
from __future__ import annotations

from urllib.parse import urlencode, urlsplit, urlunsplit

from ..models import (CWE, REMEDIATION, Endpoint, Finding, Parameter,
                      ParamLocation, ProbeResult, ReflectionContext,
                      ScanConfig, Severity, VulnType)


class ProbeContext:
    """One (endpoint, parameter) pair a detector probes against."""

    def __init__(self, http, endpoint: Endpoint, parameter: Parameter,
                 baseline: ProbeResult):
        self.http = http
        self.endpoint = endpoint
        self.parameter = parameter
        self.baseline = baseline

    def send(self, value: str) -> ProbeResult:
        """Issue one request with *value* in `parameter`, others at default."""
        values = {p.name: p.default_value for p in self.endpoint.params}
        values[self.parameter.name] = value
        if self.parameter.location == ParamLocation.FORM_BODY:
            return self.http.post(self.endpoint.url, data=values, is_probe=True)
        # QUERY and FORM_GET both travel as a query string on a GET.
        parts = urlsplit(self.endpoint.url)
        base = urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))
        full = base + (("?" + urlencode(values)) if values else "")
        return self.http.get(full, is_probe=True)


class Detector:
    """Base class every concrete detector extends."""

    name = "base"

    def __init__(self, config: ScanConfig):
        self.config = config

    def applies_to(self, endpoint: Endpoint, parameter: Parameter) -> bool:
        """True if this detector should probe this (endpoint, parameter)."""
        return True

    def scan_parameter(self, ctx: ProbeContext) -> list[Finding]:
        raise NotImplementedError


def make_finding(ctx: ProbeContext, vuln_type: VulnType, severity: Severity,
                 confidence: float, payload: str, evidence_text: str, *,
                 reflection_context: ReflectionContext | None = None,
                 manual_review: bool = False) -> Finding:
    """Build a Finding from a ProbeContext, filling CWE/remediation from the
    shared lookup tables in models.py so every detector stays consistent."""
    return Finding(
        vuln_type=vuln_type, severity=severity, confidence=confidence,
        url=ctx.endpoint.url, method=ctx.endpoint.method,
        parameter=ctx.parameter.name, param_location=ctx.parameter.location,
        payload=payload, evidence=evidence_text,
        reflection_context=reflection_context,
        cwe=CWE.get(vuln_type, ""), remediation=REMEDIATION.get(vuln_type, ""),
        manual_review=manual_review,
    )
