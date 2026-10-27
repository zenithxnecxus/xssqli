"""Unit tests for SQLi and XSS detectors using mocked probe responses."""
from xssql.detectors.base import ProbeContext
from xssql.detectors.sqli import SQLiDetector
from xssql.detectors.xss import XSSDetector
from xssql.models import (Endpoint, ParamLocation, Parameter, ProbeResult,
                            ReflectionContext, ScanConfig, Severity, VulnType)


def _cfg():
    return ScanConfig(target="http://127.0.0.1:5000/", consent=True)


class ScriptedCtx(ProbeContext):
    """ProbeContext whose send() is driven by a response function."""
    def __init__(self, respond, baseline_body=""):
        ep = Endpoint("http://127.0.0.1:5000/x", "GET",
                      [Parameter("id", ParamLocation.QUERY, "1")])
        param = ep.params[0]
        baseline = ProbeResult("u", "u", 200, baseline_body, 1.0)
        super().__init__(http=None, endpoint=ep, parameter=param, baseline=baseline)
        self._respond = respond
        self.sent = []

    def send(self, value):
        self.sent.append(value)
        return self._respond(value)


# ---------------------------------------------------------------- SQLi error
def test_sqli_error_detects_signature():
    def respond(v):
        body = ('unrecognized token: "\'"' if "'" in v else "ok rows alice")
        return ProbeResult("u", "u", 200, body, 1.0)
    f = SQLiDetector(_cfg()).scan_parameter(ScriptedCtx(respond))
    assert len(f) == 1
    assert f[0].vuln_type == VulnType.SQLI_ERROR
    assert f[0].severity == Severity.HIGH
    assert f[0].confidence == 0.90


def test_sqli_error_mysql_family():
    def respond(v):
        body = ("You have an error in your SQL syntax; check the manual"
                if "'" in v else "normal")
        return ProbeResult("u", "u", 200, body, 1.0)
    f = SQLiDetector(_cfg()).scan_parameter(ScriptedCtx(respond))
    assert f and "MySQL" in f[0].evidence


# ---------------------------------------------------------------- SQLi boolean
def test_sqli_boolean_fires_on_delta():
    baseline = "ROWS alice bob carol " * 20

    def respond(v):
        if "1=1" in v or "'1'='1" in v or '"1"="1' in v:
            return ProbeResult("u", "u", 200, baseline, 1.0)        # true ~ base
        if "1=2" in v or "'1'='2" in v or '"1"="2' in v:
            return ProbeResult("u", "u", 200, "no rows " * 20, 1.0)  # false diverges
        return ProbeResult("u", "u", 200, baseline, 1.0)            # no error

    f = SQLiDetector(_cfg()).scan_parameter(ScriptedCtx(respond, baseline))
    assert len(f) == 1
    assert f[0].vuln_type == VulnType.SQLI_BOOLEAN
    assert f[0].confidence == 0.75


def test_sqli_boolean_silent_when_no_divergence():
    same = "identical page " * 20

    def respond(v):
        return ProbeResult("u", "u", 200, same, 1.0)       # nothing ever changes
    f = SQLiDetector(_cfg()).scan_parameter(ScriptedCtx(respond, same))
    assert f == []


# ---------------------------------------------------------------- XSS
def test_xss_text_context_confirmed():
    def respond(v):
        # reflect the value verbatim (unencoded) in a text node
        return ProbeResult("u", "u", 200, f"<html><body><p>{v}</p></body></html>", 1.0)
    f = XSSDetector(_cfg()).scan_parameter(ScriptedCtx(respond))
    assert len(f) == 1
    assert f[0].vuln_type == VulnType.XSS_REFLECTED
    assert f[0].confidence == 0.85
    assert f[0].severity == Severity.MEDIUM            # text node -> MEDIUM
    assert f[0].reflection_context == ReflectionContext.TEXT


def test_xss_attribute_context_high():
    def respond(v):
        return ProbeResult("u", "u", 200,
                           f'<input type="text" value="{v}">', 1.0)
    f = XSSDetector(_cfg()).scan_parameter(ScriptedCtx(respond))
    assert f and f[0].severity == Severity.HIGH
    assert f[0].reflection_context == ReflectionContext.ATTR_DQ


def test_xss_encoded_reflection_no_finding():
    import html

    def respond(v):
        return ProbeResult("u", "u", 200,
                           f"<p>{html.escape(v)}</p>", 1.0)          # escaped
    f = XSSDetector(_cfg()).scan_parameter(ScriptedCtx(respond))
    assert f == []


def test_xss_not_reflected_no_finding():
    def respond(v):
        return ProbeResult("u", "u", 200, "<p>static</p>", 1.0)     # never reflects
    f = XSSDetector(_cfg()).scan_parameter(ScriptedCtx(respond))
    assert f == []
