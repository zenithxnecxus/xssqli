"""SQL injection detector: error-based, then boolean-differential (CWE-89).

Strategy (cheapest/most-certain signal first):
  1. error-based  — append a handful of syntax-breaking payloads; if any
     response carries a recognized DB error fingerprint, that is strong,
     single-request-confirmed evidence (confidence 0.90, HIGH).
  2. boolean-based — only tried if no error fired. Send a TRUE/FALSE
     condition pair; the evidence.boolean_divergence rule fires when TRUE
     stays statistically identical to the baseline while FALSE visibly
     diverges (confidence 0.75, HIGH).

Both stop at the first hit — one finding per (endpoint, parameter) is enough
to prove injectability; piling on duplicate findings from more payloads would
only produce dedupe noise for the engine.
"""
from __future__ import annotations

from .. import evidence
from ..models import Severity, VulnType
from .base import Detector, ProbeContext, make_finding


class SQLiDetector(Detector):
    name = "sqli"

    # Minimal syntax-breaking suffixes; order = cheapest/most-universal first.
    _ERROR_PAYLOADS = ["'", "\"", "');--", "' OR '", '" OR "', "' AND '1'='2"]

    # (true-condition suffix, false-condition suffix) pairs, numeric and
    # both quote styles so the detector works regardless of the param's
    # native type/quoting in the backend query.
    _BOOLEAN_PAIRS = [
        (" AND 1=1", " AND 1=2"),
        ("' AND '1'='1", "' AND '1'='2"),
        ('" AND "1"="1', '" AND "1"="2'),
        (" OR 1=1", " OR 1=2"),
    ]

    def applies_to(self, endpoint, parameter) -> bool:
        return True

    def scan_parameter(self, ctx: ProbeContext) -> list:
        base_value = ctx.parameter.default_value or ""
        cap = max(1, self.config.max_payloads_per_param)

        # 1. error-based
        for suffix in self._ERROR_PAYLOADS[:cap]:
            payload = base_value + suffix
            res = ctx.send(payload)
            if not res.ok:
                continue
            hits = evidence.find_sql_error_signatures(res.body)
            if hits:
                family, snippet = hits[0]
                return [make_finding(
                    ctx, VulnType.SQLI_ERROR, Severity.HIGH, 0.90, payload,
                    f"DB error signature matched [{family}]: {snippet}",
                )]

        # 2. boolean-differential
        for true_suffix, false_suffix in self._BOOLEAN_PAIRS[:cap]:
            r_true = ctx.send(base_value + true_suffix)
            r_false = ctx.send(base_value + false_suffix)
            if not (r_true.ok and r_false.ok):
                continue
            fired, ratios = evidence.boolean_divergence(
                ctx.baseline.body, r_true.body, r_false.body,
                self.config.boolean_threshold, self.config.boolean_delta)
            if fired:
                return [make_finding(
                    ctx, VulnType.SQLI_BOOLEAN, Severity.HIGH, 0.75,
                    base_value + true_suffix,
                    f"boolean divergence: TRUE~baseline, FALSE diverges {ratios}",
                )]
        return []
