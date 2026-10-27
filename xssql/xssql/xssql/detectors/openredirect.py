"""Open Redirect detector — new in xssql (CWE-601).

Only ever sends payloads pointing at hosts the scanner itself owns no
interest in reaching (an `.invalid` TLD, which RFC 2606 reserves and which
can never resolve) — and even if it could resolve, HttpClient's redirect
follower already refuses to chase an off-scope Location (scope.py,
DESIGN_DOC_V2 P2), so no request is ever actually sent to the probed host.
Detection works purely by reading the *unfollowed* 3xx response's Location
header: if the app parrots our attacker-controlled URL back verbatim, that is
the vulnerability — nothing downstream needs to be reached to prove it.

`applies_to` is narrowed to parameters whose name hints at a redirect
target, or whose crawled default value already looks like a URL/path --
redirect params are a small, named minority of all parameters, so this
keeps the request budget for the other detectors.
"""
from __future__ import annotations

from ..models import Severity, VulnType
from .base import Detector, ProbeContext, make_finding

_REDIRECT_PARAM_HINTS = (
    "url", "redirect", "redirect_uri", "redirect_url", "return", "returnurl",
    "return_url", "returnto", "next", "continue", "dest", "destination",
    "target", "out", "u", "r", "link", "forward", "goto", "callback", "redir",
    "location", "to",
)

# .invalid is reserved by RFC 2606 and will never resolve on the public
# internet — a safe canary host for a pure "does Location echo me" check.
_CANARY_HOST = "xssql-oob-check.invalid"
_PAYLOADS = [
    f"https://{_CANARY_HOST}/",
    f"//{_CANARY_HOST}/",            # protocol-relative bypass of a naive "http" filter
    f"https://trusted.example.{_CANARY_HOST}/",  # subdomain-confusion bypass
]

_REDIRECT_CODES = {301, 302, 303, 307, 308}


class OpenRedirectDetector(Detector):
    name = "open_redirect"

    def applies_to(self, endpoint, parameter) -> bool:
        name = parameter.name.lower()
        if any(hint in name for hint in _REDIRECT_PARAM_HINTS):
            return True
        dv = (parameter.default_value or "").lower()
        return dv.startswith("http://") or dv.startswith("https://") or dv.startswith("/")

    def scan_parameter(self, ctx: ProbeContext) -> list:
        cap = max(1, self.config.max_payloads_per_param)
        for payload in _PAYLOADS[:cap]:
            res = ctx.send(payload)
            if not res.ok or res.status_code not in _REDIRECT_CODES:
                continue
            location = (res.headers or {}).get("Location", "")
            if _CANARY_HOST in location.lower():
                return [make_finding(
                    ctx, VulnType.OPEN_REDIRECT, Severity.MEDIUM, 0.90, payload,
                    f"unvalidated redirect: app set Location: {location!r} "
                    f"from attacker-controlled input",
                )]
        return []
