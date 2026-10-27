"""Evidence helpers: the comparison + signal-extraction primitives.

Detectors never compare raw bodies directly. They go through this module so
that volatile tokens (CSRF, session IDs, nonces, timestamps, auto-increment
IDs) are stripped *before* any similarity math — the normalization is owned
here so a detector cannot accidentally skip it (DESIGN_DOC_V2 §11).

Contents:
  * normalize_response  — strip volatile tokens, collapse whitespace
  * similarity_ratio    — difflib ratio on normalized, length-capped bodies
  * similar             — threshold wrapper
  * boolean_divergence  — the SQLi boolean delta rule (returns ratios dict)
  * extract_snippet     — context window around a match, HTML-safe for report
  * html_encoded_form   — did the app encode our metacharacters?
  * metacharacters_unencoded — raw < > " ' survived in the body?
  * find_sql_error_signatures — DB error fingerprints by family
"""
from __future__ import annotations

import difflib
import html
import re
from typing import Iterable, Optional

# bodies longer than this are truncated before difflib (keeps comparison O(n)
# and bounds worst-case cost on large pages) — 64 KB per DESIGN_DOC_V2 §11.
_SIM_CAP_BYTES = 64 * 1024

# ---------------------------------------------------------------- normalization
# Each pattern targets a class of value that legitimately changes between two
# otherwise-identical responses. Stripping them prevents false divergence.
_VOLATILE_PATTERNS = [
    # CSRF / anti-forgery tokens in hidden inputs or meta tags
    (re.compile(r'(name=["\'](?:csrf_token|csrfmiddlewaretoken|authenticity_token|__RequestVerificationToken)["\']\s+value=["\'])[^"\']*(["\'])',
                re.I), r"\1\2"),
    (re.compile(r'(name=["\'](?:csrf_token|csrfmiddlewaretoken|authenticity_token|__RequestVerificationToken)["\'])[^>]*?(value=["\'])[^"\']*(["\'])',
                re.I), r"\1 \2\3"),
    # session identifiers in cookies/links
    (re.compile(r'((?:session(?:id)?|sid|phpsessid|jsessionid)=)[A-Za-z0-9+/=_-]{6,}', re.I),
     r"\1<SID>"),
    # CSP / inline nonces
    (re.compile(r'(nonce=["\'])[^"\']+(["\'])', re.I), r"\1<NONCE>\2"),
    # ISO-ish timestamps and times
    (re.compile(r'\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?'),
     "<TS>"),
    (re.compile(r'\b\d{2}:\d{2}:\d{2}\b'), "<TIME>"),
    # epoch-ish numbers (cache-busters, request ids)
    (re.compile(r'\b\d{10,13}\b'), "<EPOCH>"),
    # generic "...id=1234" auto-increment style identifiers in attributes
    (re.compile(r'((?:request|trace|correlation|req)[-_]?id["\'=:\s]+)[A-Za-z0-9-]{6,}', re.I),
     r"\1<ID>"),
]

_WS = re.compile(r"\s+")


def normalize_response(body: str) -> str:
    """Return a comparison-stable version of *body*.

    Volatile tokens are replaced with fixed placeholders and runs of
    whitespace are collapsed. This is deterministic and idempotent.
    """
    if not body:
        return ""
    out = body
    for pattern, repl in _VOLATILE_PATTERNS:
        out = pattern.sub(repl, out)
    out = _WS.sub(" ", out).strip()
    return out


def _cap(s: str) -> str:
    """Byte-cap a (normalized) string for difflib."""
    b = s.encode("utf-8", "ignore")
    if len(b) <= _SIM_CAP_BYTES:
        return s
    return b[:_SIM_CAP_BYTES].decode("utf-8", "ignore")


# ---------------------------------------------------------------- similarity
def similarity_ratio(a: str, b: str) -> float:
    """Similarity in [0,1] between two bodies after normalization + cap.

    1.0 == identical (post-normalization); 0.0 == nothing in common.
    """
    na, nb = _cap(normalize_response(a)), _cap(normalize_response(b))
    if not na and not nb:
        return 1.0
    return difflib.SequenceMatcher(None, na, nb, autojunk=False).ratio()


def similar(a: str, b: str, threshold: float) -> bool:
    """True if two bodies are at least *threshold* similar."""
    return similarity_ratio(a, b) >= threshold


# ---------------------------------------------------------------- boolean delta
def boolean_divergence(baseline: str, r_true: str, r_false: str,
                       threshold: float, delta: float) -> tuple[bool, dict]:
    """The boolean-based SQLi decision rule.

    Fires iff the TRUE condition keeps the page ~unchanged while the FALSE
    condition visibly diverges::

        ratio(baseline, r_true)  >= theta          (true looks like normal)
        ratio(r_true,  r_false)  <= theta - delta   (false clearly differs)

    All three inputs are compared through similarity_ratio (so normalization
    always runs). Returns (fired, ratios) where ratios is kept as evidence.
    """
    base_true = similarity_ratio(baseline, r_true)
    true_false = similarity_ratio(r_true, r_false)
    base_false = similarity_ratio(baseline, r_false)
    fired = (base_true >= threshold) and (true_false <= (threshold - delta))
    ratios = {
        "ratio_baseline_true": round(base_true, 4),
        "ratio_true_false": round(true_false, 4),
        "ratio_baseline_false": round(base_false, 4),
        "theta": threshold,
        "delta": delta,
        "gap_required": round(threshold - delta, 4),
    }
    return fired, ratios


# ---------------------------------------------------------------- snippets
def extract_snippet(body: str, needle: str, window: int = 80) -> str:
    """Return a short, HTML-escaped context window around *needle*.

    Used so report evidence shows *where* a signature/reflection appeared
    without dumping the whole page. The returned text is safe to drop into an
    HTML report verbatim (escaped). Returns "" if the needle is absent.
    """
    if not body or not needle:
        return ""
    idx = body.lower().find(needle.lower())
    if idx < 0:
        return ""
    start = max(0, idx - window)
    end = min(len(body), idx + len(needle) + window)
    frag = body[start:end]
    prefix = "…" if start > 0 else ""
    suffix = "…" if end < len(body) else ""
    return prefix + html.escape(frag) + suffix


# ---------------------------------------------------------------- encoding check
_METACHARS = ["<", ">", '"', "'"]
_ENCODED_FORMS = {
    "<": ["&lt;", "&#60;", "&#x3c;", "%3c"],
    ">": ["&gt;", "&#62;", "&#x3e;", "%3e"],
    '"': ["&quot;", "&#34;", "&#x22;", "%22"],
    "'": ["&#39;", "&#x27;", "&apos;", "%27"],
}


def metacharacters_unencoded(body: str, marker: str) -> list[str]:
    """Which raw metacharacters appear immediately next to *marker* in body.

    We look only at the reflected region (around the marker) so unrelated raw
    '<' elsewhere on the page do not count. Returns the raw metachars that
    survived un-encoded.
    """
    if not body or marker not in body:
        return []
    survived = []
    i = body.find(marker)
    region = body[i: i + len(marker) + 12]   # marker plus trailing metachars
    for ch in _METACHARS:
        if ch in region:
            survived.append(ch)
    return survived


def html_encoded_form(body: str, marker: str) -> bool:
    """True if our metacharacters came back HTML/percent-encoded near marker.

    Indicates the application escaped output (auto-escaping works) — so a
    reflection in that spot is not exploitable and should NOT raise a finding.
    """
    if not body or marker not in body:
        return False
    i = body.find(marker)
    region = body[i: i + len(marker) + 24].lower()
    for forms in _ENCODED_FORMS.values():
        for enc in forms:
            if enc in region:
                return True
    return False


# ---------------------------------------------------------------- SQL signatures
# Error fingerprints grouped by DB family. Matching any one is strong evidence
# that attacker-controlled input reached the SQL parser (CWE-89).
SQL_ERROR_SIGNATURES: dict[str, list[re.Pattern]] = {
    "MySQL": [
        re.compile(r"SQL syntax.*MySQL", re.I),
        re.compile(r"Warning.*\bmysqli?_", re.I),
        re.compile(r"MySqlException", re.I),
        re.compile(r"check the manual that corresponds to your (?:MySQL|MariaDB) server version", re.I),
        re.compile(r"You have an error in your SQL syntax", re.I),
    ],
    "PostgreSQL": [
        re.compile(r"PostgreSQL.*ERROR", re.I),
        re.compile(r"\bpg_(?:query|exec)\(", re.I),
        re.compile(r"PSQLException", re.I),
        re.compile(r"unterminated quoted string at or near", re.I),
    ],
    "SQLite": [
        re.compile(r"SQLite/JDBCDriver", re.I),
        re.compile(r"SQLite\.Exception", re.I),
        re.compile(r"\bsqlite3\.OperationalError\b", re.I),
        re.compile(r"unrecognized token:", re.I),
        re.compile(r"near \".*\": syntax error", re.I),
        re.compile(r"no such column", re.I),
    ],
    "MSSQL": [
        re.compile(r"Microsoft SQL Server", re.I),
        re.compile(r"ODBC SQL Server Driver", re.I),
        re.compile(r"Unclosed quotation mark after the character string", re.I),
        re.compile(r"System\.Data\.SqlClient\.SqlException", re.I),
    ],
    "Oracle": [
        re.compile(r"\bORA-\d{5}", re.I),
        re.compile(r"Oracle error", re.I),
        re.compile(r"quoted string not properly terminated", re.I),
    ],
    "Generic": [
        re.compile(r"SQL syntax error", re.I),
        re.compile(r"Unclosed quotation mark", re.I),
        re.compile(r"syntax error at or near", re.I),
        re.compile(r"Dynamic SQL Error", re.I),
    ],
}


def find_sql_error_signatures(body: str) -> list[tuple[str, str]]:
    """Return list of (family, matched_text) for every DB error signature hit.

    Empty list means no SQL error fingerprint was present.
    """
    if not body:
        return []
    hits: list[tuple[str, str]] = []
    for family, patterns in SQL_ERROR_SIGNATURES.items():
        for pat in patterns:
            m = pat.search(body)
            if m:
                hits.append((family, m.group(0)[:160]))
                break  # one hit per family is enough
    return hits
