"""Same-host BFS crawler → attack surface (DESIGN_DOC_V2 §12).

The crawler's only job is *discovery*: turn a seed URL into a de-duplicated
list of Endpoints with their testable Parameters. It never injects anything —
that strict separation keeps detectors unit-testable and keeps the crawler's
request count bounded by max_pages.

Discovery rules:
  * BFS, bounded by max_depth and max_pages
  * same-host only (scope gate is also consulted, fail closed)
  * <a href> query keys        → ParamLocation.QUERY
  * <form method=get> fields    → ParamLocation.FORM_GET
  * <form method=post> fields   → ParamLocation.FORM_BODY
  * skip mailto:/javascript:/data:/tel: and any exclude_url_patterns
  * dedupe endpoints by (url_without_values, method, frozenset(param_names))
"""
from __future__ import annotations

import re
from collections import deque
from urllib.parse import urljoin, urlparse, urlsplit, urlunsplit, parse_qs

from bs4 import BeautifulSoup

from .budget import Budget
from .events import EventCallback, EventType, ScanEvent, null_callback
from .errors import BudgetExceeded
from .http_client import HttpClient
from .models import CrawledPage, Endpoint, ParamLocation, Parameter, ScanConfig
from .scope import host_allowed

_SKIP_SCHEMES = ("mailto:", "javascript:", "data:", "tel:", "#")


def strip_values(url: str) -> str:
    """Return URL with query values removed but keys kept (identity key)."""
    parts = urlsplit(url)
    keys = sorted(parse_qs(parts.query, keep_blank_values=True).keys())
    q = "&".join(f"{k}=" for k in keys)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, q, ""))


def _same_host(url: str, seed_host: str) -> bool:
    return (urlparse(url).hostname or "").lower() == seed_host.lower()


class Crawler:
    def __init__(self, cfg: ScanConfig, http: HttpClient, budget: Budget,
                 emit: EventCallback = null_callback):
        self._cfg = cfg
        self._http = http
        self._budget = budget
        self._emit = emit
        self._exclude = [re.compile(p) for p in cfg.exclude_url_patterns]
        self.pages: list[CrawledPage] = []

    # ----------------------------------------------------------------- public
    def crawl(self, seed: str) -> list[Endpoint]:
        seed_host = (urlparse(seed).hostname or "").lower()
        seen_urls: set[str] = set()
        endpoints: dict[tuple, Endpoint] = {}
        q: deque[tuple[str, int]] = deque([(seed, 0)])
        seen_urls.add(strip_values(seed))

        while q and len(self.pages) < self._cfg.max_pages:
            url, depth = q.popleft()
            if self._excluded(url):
                continue
            try:
                res = self._http.get(url, is_probe=False)
            except BudgetExceeded:
                break   # engine will mark DONE_PARTIAL
            if not res.ok or not res.body:
                continue

            soup = BeautifulSoup(res.body, "lxml")
            page = CrawledPage(url=url, final_url=res.final_url,
                               status_code=res.status_code, depth=depth,
                               title=(soup.title.string.strip()
                                      if soup.title and soup.title.string else ""))
            self.pages.append(page)
            self._emit(ScanEvent(EventType.PAGE_CRAWLED,
                                 f"crawled {url} ({res.status_code})",
                                 {"url": url, "depth": depth,
                                  "status": res.status_code}))

            # 1. GET endpoints from <a href> with query keys
            for ep in self._endpoints_from_links(url, soup, seed_host, depth, q, seen_urls):
                self._register(endpoints, ep)
            # 2. endpoints from <form>
            for ep in self._endpoints_from_forms(url, soup):
                self._register(endpoints, ep)

        return list(endpoints.values())

    # ----------------------------------------------------------------- links
    def _endpoints_from_links(self, base, soup, seed_host, depth, q, seen):
        out: list[Endpoint] = []
        for a in soup.find_all("a", href=True):
            href = a["href"].strip()
            if not href or href.lower().startswith(_SKIP_SCHEMES):
                continue
            absu = urljoin(base, href)
            if urlparse(absu).scheme not in ("http", "https"):
                continue
            if not _same_host(absu, seed_host) or not host_allowed(
                    urlparse(absu).hostname or "", self._cfg):
                continue
            if self._excluded(absu):
                continue

            # queue for further crawling (BFS, depth-bounded)
            ident = strip_values(absu)
            if ident not in seen and depth + 1 <= self._cfg.max_depth:
                seen.add(ident)
                q.append((absu, depth + 1))

            # if it carries query params, it is a testable GET endpoint
            params = parse_qs(urlsplit(absu).query, keep_blank_values=True)
            if params:
                plist = [Parameter(name=k, location=ParamLocation.QUERY,
                                   default_value=(v[0] if v else ""))
                         for k, v in params.items()]
                out.append(Endpoint(url=strip_values(absu), method="GET",
                                    params=plist))
        return out

    # ----------------------------------------------------------------- forms
    def _endpoints_from_forms(self, base, soup) -> list[Endpoint]:
        out: list[Endpoint] = []
        for form in soup.find_all("form"):
            action = urljoin(base, (form.get("action") or base).strip())
            if self._excluded(action):
                continue
            method = (form.get("method") or "GET").strip().upper()
            location = (ParamLocation.FORM_BODY if method == "POST"
                        else ParamLocation.FORM_GET)
            params: list[Parameter] = []
            for field in form.find_all(["input", "textarea", "select"]):
                name = field.get("name")
                if not name:
                    continue
                itype = (field.get("type") or "").lower()
                if itype in ("submit", "button", "image", "reset", "file"):
                    continue
                default = field.get("value") or ""
                params.append(Parameter(name=name, location=location,
                                        default_value=default))
            if params:
                out.append(Endpoint(url=strip_values(action), method=method,
                                    params=params))
        return out

    # ----------------------------------------------------------------- helpers
    def _register(self, endpoints: dict, ep: Endpoint) -> None:
        key = ep.identity()
        if key not in endpoints:
            endpoints[key] = ep
            self._emit(ScanEvent(EventType.ENDPOINT_FOUND,
                                 f"endpoint {ep.method} {ep.url} "
                                 f"({len(ep.params)} params)",
                                 {"url": ep.url, "method": ep.method,
                                  "params": [p.name for p in ep.params]}))

    def _excluded(self, url: str) -> bool:
        return any(p.search(url) for p in self._exclude)
