"""Fail-closed ethics gate (DESIGN_DOC_V2 §2, §8).

No scan proceeds unless:
  1. consent is explicitly given (--i-am-authorized), AND
  2. the target host is localhost, the seed host, or on the allowlist.

Both checks fail closed: anything unexpected raises rather than permitting.
"""
from __future__ import annotations

from urllib.parse import urlparse

from .errors import ConsentRequiredError, ScopeViolation
from .models import ScanConfig

_LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}


def _host_of(url: str) -> str:
    return (urlparse(url).hostname or "").lower()


def host_allowed(host: str, cfg: ScanConfig) -> bool:
    """True if host is in scope for this scan."""
    host = (host or "").lower()
    if not host:
        return False
    if host in _LOCAL_HOSTS:
        return True
    if host == _host_of(cfg.target):          # same host as the seed target
        return True
    allow = {h.lower() for h in cfg.allowlist}
    return host in allow


def assert_in_scope(url: str, cfg: ScanConfig) -> None:
    """Gate a URL. Raises on consent or scope failure (fail closed)."""
    if not cfg.consent:
        raise ConsentRequiredError(
            "Authorization required: scanning is disabled without explicit "
            "consent (--i-am-authorized). Only scan systems you own or are "
            "permitted to test."
        )
    host = _host_of(url)
    if not host_allowed(host, cfg):
        raise ScopeViolation(
            f"Host '{host}' is out of scope. Permitted: localhost, the target "
            f"host ({_host_of(cfg.target)}), and any --allow entries."
        )
