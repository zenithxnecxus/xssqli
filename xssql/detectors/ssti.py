"""Server-Side Template Injection detector — new in xssql (CWE-1336).

Classic math-canary technique, dual-confirmed to avoid a one-shot false
positive (a page that just happens to contain "49" somewhere): if a
template engine is compiling our input as template *source* rather than
treating it as plain data, `{{7*7}}`-style syntax gets evaluated server
side and the arithmetic result appears in the response. We probe with two
independent arithmetic expressions (7*7 and 8*8) across the common engine
syntaxes (Jinja2/Twig, ERB, Smarty-ish `{...}`, EL/Freemarker `${...}`,
Razor `@(...)`); only a payload whose *own* syntax produces *both* expected
results, while neither number was already present in the baseline, counts
as a finding.
"""
from __future__ import annotations

from ..models import Severity, VulnType
from .base import Detector, ProbeContext, make_finding

# (payload template, expected result) pairs, grouped by engine syntax family.
# Each family is tried as a pair (49-probe, 64-probe) so a single family must
# agree on both before we call it confirmed.
_FAMILIES = [
    ("{{%s}}", "jinja2/twig"),
    ("${%s}", "el/freemarker"),
    ("#{%s}", "ruby-interpolation/smarty"),
    ("<%%= %s %%>", "erb"),
    ("@(%s)", "razor"),
]


class SSTIDetector(Detector):
    name = "ssti"

    def applies_to(self, endpoint, parameter) -> bool:
        return True

    def scan_parameter(self, ctx: ProbeContext) -> list:
        cap = max(1, self.config.max_payloads_per_param)
        baseline_body = ctx.baseline.body or ""

        for template, engine in _FAMILIES[:cap]:
            probe_a = template % "7*7"
            probe_b = template % "8*8"

            res_a = ctx.send(probe_a)
            if not res_a.ok or "49" not in res_a.body or "49" in baseline_body:
                continue
            res_b = ctx.send(probe_b)
            if not res_b.ok or "64" not in res_b.body or "64" in baseline_body:
                continue

            return [make_finding(
                ctx, VulnType.SSTI, Severity.HIGH, 0.90, probe_a,
                f"arithmetic canary evaluated server-side ({engine} syntax): "
                f"{probe_a!r} -> contains '49', {probe_b!r} -> contains '64'",
            )]
        return []
