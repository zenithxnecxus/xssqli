"""Core datatypes: enums, dataclasses, remediation map (DESIGN_DOC_V2 §5).

Everything the layers pass around is defined here so there is a single source
of truth for the data model. Dataclasses are plain (no behaviour) except for a
couple of derived convenience properties.
"""
from __future__ import annotations

import enum
from dataclasses import dataclass, field, asdict
from typing import Any, Optional


# ---------------------------------------------------------------- enums
class VulnType(str, enum.Enum):
    SQLI_ERROR = "sqli_error"
    SQLI_BOOLEAN = "sqli_boolean"
    XSS_REFLECTED = "xss_reflected"
    OPEN_REDIRECT = "open_redirect"
    SSTI = "ssti"


class Severity(str, enum.Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ParamLocation(str, enum.Enum):
    QUERY = "query"          # ?key=value
    FORM_GET = "form_get"    # <form method=get>
    FORM_BODY = "form_body"  # <form method=post>


class ScanStatus(str, enum.Enum):
    RUNNING = "running"
    DONE = "done"
    DONE_PARTIAL = "done_partial"   # budget/deadline hit; results kept
    FAILED = "failed"


class ReflectionContext(str, enum.Enum):
    NOT_REFLECTED = "not_reflected"
    ENCODED = "encoded"
    TEXT = "text"            # text node
    ATTR_DQ = "attr_dq"      # double-quoted attribute
    ATTR_SQ = "attr_sq"      # single-quoted attribute
    SCRIPT = "script"        # inside <script>


# severity ordering for dedupe tie-breaks
_SEV_RANK = {Severity.HIGH: 3, Severity.MEDIUM: 2, Severity.LOW: 1, Severity.INFO: 0}


# ---------------------------------------------------------------- dataclasses
@dataclass(frozen=True)
class Parameter:
    name: str
    location: ParamLocation
    default_value: str = ""

    def key(self) -> tuple:
        return (self.name, self.location.value)


@dataclass
class Endpoint:
    url: str                       # URL without parameter *values*
    method: str                    # GET / POST
    params: list[Parameter] = field(default_factory=list)

    def identity(self) -> tuple:
        return (self.url, self.method.upper(),
                frozenset(p.name for p in self.params))


@dataclass
class CrawledPage:
    url: str
    final_url: str
    status_code: int
    depth: int
    title: str = ""


@dataclass
class ProbeResult:
    """Normalized outcome of a single HTTP send."""
    url: str
    final_url: str
    status_code: int
    body: str
    elapsed_ms: float
    truncated: bool = False
    error: Optional[str] = None
    headers: dict = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.error is None


@dataclass
class Finding:
    vuln_type: VulnType
    severity: Severity
    confidence: float
    url: str
    method: str
    parameter: str
    param_location: ParamLocation
    payload: str
    evidence: str
    reflection_context: Optional[ReflectionContext] = None
    cwe: str = ""
    remediation: str = ""
    manual_review: bool = False

    @property
    def confidence_band(self) -> str:
        """0.85+ = confirmed, 0.60-0.84 = probable, <0.60 = weak (dropped)."""
        if self.confidence >= 0.85:
            return "confirmed"
        if self.confidence >= 0.60:
            return "probable"
        return "weak"

    def dedupe_key(self, normalized_url: str) -> tuple:
        return (self.vuln_type.value, self.method.upper(), normalized_url,
                self.parameter, self.param_location.value)

    def beats(self, other: "Finding") -> bool:
        """True if self should win a dedupe tie against other."""
        if self.confidence != other.confidence:
            return self.confidence > other.confidence
        return _SEV_RANK[self.severity] > _SEV_RANK[other.severity]


@dataclass
class ScanConfig:
    target: str
    consent: bool = False
    allowlist: list[str] = field(default_factory=list)
    max_depth: int = 2
    max_pages: int = 50
    rate_limit_rps: float = 5.0
    request_timeout_s: float = 10.0
    max_response_bytes: int = 512 * 1024
    scan_deadline_s: float = 120.0
    max_requests: int = 2000
    max_payloads_per_param: int = 25
    boolean_threshold: float = 0.85    # theta
    boolean_delta: float = 0.10        # delta gap
    early_stop_confidence: float = 0.85
    exclude_url_patterns: list[str] = field(default_factory=list)
    cookie: str = ""                   # masked in public summary

    def public_summary(self) -> dict[str, Any]:
        d = asdict(self)
        if d.get("cookie"):
            d["cookie"] = "***masked***"
        return d


@dataclass
class ScanSummary:
    scan_id: int
    status: ScanStatus
    target: str
    endpoints_found: int
    findings_total: int
    by_severity: dict[str, int]
    by_type: dict[str, int]
    requests_sent: int
    duration_s: float
    partial_reason: Optional[str] = None


# ---------------------------------------------------------------- remediation
CWE = {
    VulnType.SQLI_ERROR: "CWE-89",
    VulnType.SQLI_BOOLEAN: "CWE-89",
    VulnType.XSS_REFLECTED: "CWE-79",
    VulnType.OPEN_REDIRECT: "CWE-601",
    VulnType.SSTI: "CWE-1336",
}

REMEDIATION = {
    VulnType.SQLI_ERROR: (
        "Use parameterized queries / prepared statements so user input is "
        "never concatenated into SQL. Apply least-privilege DB accounts and "
        "disable verbose database error messages in production."
    ),
    VulnType.SQLI_BOOLEAN: (
        "Use parameterized queries / prepared statements. Blind SQLi arises "
        "from the same root cause as error-based — bind all parameters and "
        "validate input types server-side."
    ),
    VulnType.XSS_REFLECTED: (
        "Contextually encode all untrusted output (HTML, attribute, JS, URL). "
        "Prefer auto-escaping template engines, set a strict Content-Security-"
        "Policy, and validate/allow-list input where feasible."
    ),
    VulnType.OPEN_REDIRECT: (
        "Never redirect to a raw user-controlled URL. Validate the target "
        "against an allowlist of paths/hosts, or use an indirection token "
        "(e.g. a lookup id) instead of passing the destination in the URL."
    ),
    VulnType.SSTI: (
        "Never render a template engine's compile/eval step with "
        "user-controlled input as the template source. Treat template "
        "syntax as code: pass user input only as template *data*, use a "
        "logic-less/sandboxed templating mode, and keep the engine patched."
    ),
}
