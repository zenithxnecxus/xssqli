"""Reflected XSS detector: canary -> context -> proof (CWE-79).

A random, unguessable canary token carrying the four HTML metacharacters
(" ' < >) is sent as the parameter value. We then look at the *reflected*
region around the canary in the response:

  * not reflected at all              -> no finding
  * reflected, but html/percent-encoded -> encoding works, no finding
  * reflected with raw metacharacters   -> classify the surrounding markup
    (script / double-quoted attr / single-quoted attr / text node) and
    raise a finding whose severity follows the context (script+attr = HIGH,
    text node = MEDIUM), confidence 0.85.

The random canary (instead of a fixed marker) means two different parameters
on the same page can never be confused with each other's reflection.
"""
from __future__ import annotations

import secrets

from .. import evidence
from ..models import ReflectionContext, Severity, VulnType
from .base import Detector, ProbeContext, make_finding

_METACHARS = "\"'<>"


class XSSDetector(Detector):
    name = "xss"

    def applies_to(self, endpoint, parameter) -> bool:
        return True

    def scan_parameter(self, ctx: ProbeContext) -> list:
        canary = "xq" + secrets.token_hex(4)          # e.g. "xq1a2b3c4d"
        payload = canary + _METACHARS
        res = ctx.send(payload)
        if not res.ok or canary not in res.body:
            return []                                  # not reflected at all

        if evidence.html_encoded_form(res.body, canary):
            return []                                  # app escapes output

        survived = evidence.metacharacters_unencoded(res.body, canary)
        if not survived:
            return []                                  # metachars did not survive

        context = self._classify(res.body, canary)
        severity = (Severity.HIGH
                    if context in (ReflectionContext.SCRIPT,
                                   ReflectionContext.ATTR_DQ,
                                   ReflectionContext.ATTR_SQ)
                    else Severity.MEDIUM)
        snippet = evidence.extract_snippet(res.body, canary)
        return [make_finding(
            ctx, VulnType.XSS_REFLECTED, severity, 0.85, payload,
            f"canary reflected unencoded in {context.value} context: {snippet}",
            reflection_context=context,
        )]

    @staticmethod
    def _classify(body: str, marker: str) -> ReflectionContext:
        idx = body.find(marker)
        if idx < 0:
            return ReflectionContext.NOT_REFLECTED
        before = body[max(0, idx - 300):idx].lower()
        if before.rfind("<script") > before.rfind("</script"):
            return ReflectionContext.SCRIPT
        gt = before.rfind(">")
        dq = before.rfind('="')
        sq = before.rfind("='")
        if dq > gt and dq >= sq:
            return ReflectionContext.ATTR_DQ
        if sq > gt and sq > dq:
            return ReflectionContext.ATTR_SQ
        return ReflectionContext.TEXT
