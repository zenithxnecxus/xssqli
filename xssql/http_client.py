"""Single HTTP gateway (DESIGN_DOC_V2 §8).

All network I/O funnels through here so these cross-cutting concerns live in
one place: session reuse, token-bucket rate limiting, body truncation, a
redirect cap, split retry policy (crawl GETs vs probes), per-request timeout
bounded by the remaining budget, and a budget hook before every send.

4xx/5xx are returned as ordinary ProbeResults (they are signal, not errors).
"""
from __future__ import annotations

import time
from typing import Optional
from urllib.parse import urljoin, urlparse

import requests

from .budget import Budget
from .models import ProbeResult
from .scope import host_allowed

_MAX_REDIRECTS = 5


class _TokenBucket:
    """Simple rate limiter: spaces sends to <= rps."""

    def __init__(self, rps: float, sleep=time.sleep, clock=time.monotonic):
        self._min_interval = 1.0 / rps if rps > 0 else 0.0
        self._sleep = sleep
        self._clock = clock
        self._last = 0.0

    def wait(self) -> None:
        if self._min_interval <= 0:
            return
        now = self._clock()
        gap = self._min_interval - (now - self._last)
        if gap > 0:
            self._sleep(gap)
        self._last = self._clock()


class HttpClient:
    def __init__(self, cfg, budget: Budget, sleep=time.sleep):
        self._cfg = cfg
        self._budget = budget
        self._session = requests.Session()
        if cfg.cookie:
            self._session.headers["Cookie"] = cfg.cookie
        self._session.headers["User-Agent"] = "xssql/2.0 (course project)"
        self._bucket = _TokenBucket(cfg.rate_limit_rps, sleep=sleep)

    # crawl GETs tolerate transient errors (retry 3); probes must not be
    # retried blindly (retry 1) — a repeated injection probe skews evidence.
    def get(self, url: str, params: Optional[dict] = None,
            is_probe: bool = False) -> ProbeResult:
        return self._send("GET", url, params=params, data=None,
                          retries=1 if is_probe else 3)

    def post(self, url: str, data: Optional[dict] = None,
             is_probe: bool = False) -> ProbeResult:
        return self._send("POST", url, params=None, data=data,
                          retries=1 if is_probe else 3)

    def _timeout(self) -> float:
        return max(0.1, min(self._cfg.request_timeout_s,
                            self._budget.remaining_s or self._cfg.request_timeout_s))

    def _send(self, method, url, params, data, retries) -> ProbeResult:
        last_err = None
        for attempt in range(retries + 1):
            self._budget.spend_request()   # raises BudgetExceeded -> caught by engine
            self._bucket.wait()
            t0 = time.monotonic()
            try:
                resp = self._session.request(
                    method, url, params=params, data=data,
                    timeout=self._timeout(), allow_redirects=False,
                )
                resp = self._follow_redirects(resp)
                body = resp.text or ""
                truncated = False
                if len(body.encode("utf-8", "ignore")) > self._cfg.max_response_bytes:
                    body = body.encode("utf-8", "ignore")[
                        : self._cfg.max_response_bytes].decode("utf-8", "ignore")
                    truncated = True
                return ProbeResult(
                    url=url, final_url=resp.url, status_code=resp.status_code,
                    body=body, elapsed_ms=(time.monotonic() - t0) * 1000,
                    truncated=truncated,
                    headers={"Location": resp.headers.get("Location", "")}
                    if resp.headers.get("Location") else {},
                )
            except requests.RequestException as exc:
                last_err = str(exc)
                if attempt >= retries:
                    return ProbeResult(url=url, final_url=url, status_code=0,
                                       body="", elapsed_ms=(time.monotonic() - t0) * 1000,
                                       error=last_err)
        return ProbeResult(url=url, final_url=url, status_code=0, body="",
                           elapsed_ms=0.0, error=last_err or "unknown")

    def _follow_redirects(self, resp):
        """Follow up to _MAX_REDIRECTS hops, but fail closed on scope.

        A redirect to a non-http(s) scheme or to a host outside the permitted
        target scope is NOT followed — redirects must not bypass the ethics
        gate (DESIGN_DOC_V2 §2 / P2). We stop at the redirect response so no
        request is sent to an unauthorized host.
        """
        hops = 0
        while resp.is_redirect and hops < _MAX_REDIRECTS:
            loc = resp.headers.get("Location")
            if not loc:
                break
            next_url = urljoin(resp.url, loc)
            parsed = urlparse(next_url)
            if (parsed.scheme not in ("http", "https")
                    or not host_allowed(parsed.hostname or "", self._cfg)):
                break                      # off-scope / unsafe scheme: do not follow
            self._budget.spend_request()
            self._bucket.wait()
            resp = self._session.get(next_url, timeout=self._timeout(),
                                     allow_redirects=False)
            hops += 1
        return resp

    def close(self):
        self._session.close()
