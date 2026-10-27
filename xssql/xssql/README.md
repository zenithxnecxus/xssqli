# xssql — web vulnerability scanner (SQLi + XSS + Open Redirect + SSTI)

A course-safe, evidence-first **DAST** (Dynamic Application Security Testing)
scanner. Given one **explicitly authorized** target it crawls the same-host
attack surface and tests every parameter for:

- **SQL Injection** (CWE-89) — error-based and boolean-differential
- **Reflected XSS** (CWE-79) — canary → context → proof
- **Open Redirect** (CWE-601) — *new in xssql*
- **Server-Side Template Injection / SSTI** (CWE-1336) — *new in xssql*

It persists every finding with verifiable evidence to SQLite, and reports
through a CLI, a Flask dashboard, and self-contained **HTML, JSON, and PDF**
reports.

> **Ethics by construction.** No scan runs without explicit consent
> (`--i-am-authorized`) **and** a host-scope check (localhost / target host /
> allowlist). The gate fails closed. This tool is for systems you own or are
> authorized to test — the bundled lab app, DVWA, bWAPP — never third parties.
> Unauthorized scanning may be illegal.

xssql is a renamed/extended fork of a course project ("Lightweight Web
Vulnerability Scanner"); the original SQLi/XSS engine, the ethics gate, the
budget/crawl/storage layers, and the lab-based evaluation harness are
unchanged — this fork adds two new detector classes, a PDF report, and
dashboard download links for all three report formats.

---

## Install

```bash
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e .
python -m xssql version        # -> 2.0.0
```

## Quick start (against the bundled lab app)

```bash
# 1. start the intentionally-vulnerable benchmark app (localhost only)
python tests/vuln_app.py                 # serves http://127.0.0.1:5000/

# 2. scan it and generate reports
python -m xssql scan \
    --target http://127.0.0.1:5000/ \
    --i-am-authorized \
    --report reports/scan.html \
    --json   reports/scan.json \
    --pdf    reports/scan.pdf

# 3. open the dashboard
python -m xssql serve                  # http://127.0.0.1:5050/

# 4. reproduce the evaluation metrics
python -m xssql evaluate
```

## Commands

| Command | Purpose |
|---|---|
| `scan`     | Scan an authorized target; optional `--report` / `--json` / `--pdf`. |
| `report`   | (Re)generate a report for a stored scan: `--format html\|pdf`. |
| `serve`    | Run the Flask dashboard (binds `127.0.0.1`). |
| `evaluate` | Run a full scan on the lab app and print precision/recall/F1. |
| `version`  | Print the version. |

**Exit codes:** `0` ok · `1` runtime error · `2` scope/consent refused · `3` config error.

## Dashboard UI

`python -m xssql serve` starts a localhost-bound interactive dashboard at
`http://127.0.0.1:5050/`. It is a small single-page frontend (vanilla JS, no
build step, no framework) backed by a JSON API that calls the **same**
`ScanEngine` as the CLI:

- **Scan history** — list of past scans with status, findings, endpoints,
  requests, and duration.
- **New scan** (`/scan/new`) — enter a target, set crawl/rate/deadline
  options, and tick the mandatory authorization box. Consent is enforced
  server-side (unchecked ⇒ 400, no scan row). Deadline and request count are
  additionally capped server-side (60s / 1500 requests) so a dashboard scan
  can never bypass the CLI's own bounds. The scan runs through the shared
  engine and the result appears immediately.
- **Scan detail** — summary stat cards, severity/type breakdown, and a
  findings table with payload/evidence/CWE/remediation.
- **Downloads** — `report.html`, `report.pdf` (new), and `findings.json` links
  for every scan.

Evidence is rendered with `textContent` (never `innerHTML`), so a reflected-XSS
payload captured as evidence cannot execute in the dashboard. The dashboard
cannot bypass the CLI's consent, scope, or request-budget controls.

## Architecture (strict one-directional layers)

```
Interfaces     : CLI (cli.py) · Flask dashboard (webapp/)        — thin callers
Orchestration  : ScanEngine — budget, events, dedupe-before-write
Discovery      : Crawler (same-host BFS) → Endpoint/Parameter surface
Detection      : Detector registry — SQLiDetector · XSSDetector ·
                 OpenRedirectDetector · SSTIDetector  (both new)
Infrastructure : HttpClient (rate limit, retries, truncation, budget hook)
                 Storage (SQLite WAL) · Evidence helpers · Scope/ethics gate
Reporting      : HTML (Jinja2, autoescaped) · JSON · PDF (reportlab)
```

The dashboard and the CLI call the **same** `ScanEngine`. Detectors receive one
`(endpoint, parameter)` at a time via a `ProbeContext` and never crawl or
touch `HttpClient` directly, so they are unit-testable in isolation. All
response comparison goes through `evidence.py`, which normalizes away
volatile tokens (CSRF, session IDs, timestamps) **before** any similarity
math — a detector cannot skip it.

## Detection methods

- **SQLi — error-based:** inject minimal quote/syntax breakers; match the
  response against DB error signatures across 6 families (MySQL, PostgreSQL,
  SQLite, MSSQL, Oracle, generic) → `HIGH`, confidence `0.90`, with the error
  snippet as evidence.
- **SQLi — boolean-based (Δ-rule):** send TRUE/FALSE condition pairs; fire iff
  `ratio(baseline, true) ≥ θ` **and** `ratio(true, false) ≤ θ − Δ`
  (θ = 0.85, Δ = 0.10) on normalized bodies → `HIGH`, confidence `0.75`, with
  the three similarity ratios stored as evidence.
- **Reflected XSS — canary → context → proof:** inject a unique, random
  canary carrying `" ' < >`; if it's not reflected or comes back
  HTML/percent-encoded, **no finding**; if raw metacharacters survive,
  classify the reflection context (script/attribute > text) → confidence
  `0.85` (`HIGH` in script/attribute, `MEDIUM` in text).
- **Open Redirect — Location echo *(new)*:** only probes parameters whose
  name hints at a redirect target (`url`, `redirect`, `next`, `return`, …) or
  whose default value already looks like a URL/path; sends an absolute URL,
  a protocol-relative URL, and a subdomain-confusion URL all pointing at an
  RFC 2606 `.invalid` canary host (so no real request can ever leave the
  machine even in principle — `HttpClient` also refuses to *follow* an
  off-scope redirect); fires only if the app's `Location` header echoes the
  canary host back verbatim → `MEDIUM`, confidence `0.90`.
- **SSTI — dual arithmetic canary *(new)*:** sends two independent arithmetic
  expressions (`7*7`, `8*8`) across five common template-engine syntaxes
  (Jinja2/Twig `{{ }}`, EL/Freemarker `${ }`, Ruby/Smarty `#{ }`, ERB
  `<%= %>`, Razor `@( )`); only fires when **both** results appear and
  neither was already present in the baseline, which rules out a page that
  just happens to contain "49" → `HIGH`, confidence `0.90`.

Detection probes are deliberately minimal — no stacked queries, UNION
extraction, DB-takeover payloads, real redirect targets, or template RCE
payloads. The scanner *detects and reports for remediation*; it does not
exploit.

## Measured results (on the bundled lab app, now covering all 4 classes)

| Metric | Target | Measured |
|---|---|---|
| Precision | ≥ 0.90 | **1.00** |
| Recall | ≥ 0.80 | **1.00** |
| F1 | ≥ 0.85 | **1.00** |
| True-negative rate (`/safe-*`) | 100% | **100%** (0 findings) |
| Wall-clock | ≤ 60 s | **~6–7 s** |
| Unit + e2e tests | 100% green | **76 passed** |

Reproduce with `python -m xssql evaluate`.

## Testing

```bash
pip install -e ".[dev]"
pytest -q
```

The suite covers config validation, budget/termination, the fail-closed scope
gate, the HTTP gateway (**including off-scope redirect blocking** and body
truncation), evidence math (normalization, Δ-rule edges, signature families),
crawler extraction/dedupe, storage CRUD under WAL, all four detectors (mocked
responses), engine (event order, dedupe, partial-on-deadline), report
escaping (HTML and PDF), CLI exit codes, dashboard consent enforcement, and
the end-to-end accuracy targets against the lab app's SQLi/XSS/open-redirect/
SSTI routes and their `/safe-*` negatives.

## Responsible use

This project exists to help developers *find and fix* injection, redirect,
and template-injection bugs in systems they control. The fail-closed consent
and scope gate are intentional. Do not point it at systems you are not
authorized to test.
