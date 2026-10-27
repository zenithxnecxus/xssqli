"""Ground-truth vulnerable lab application (benchmark target).

PURPOSE AND SAFETY
------------------
This is an intentionally vulnerable Flask app that exists ONLY as a local,
labeled benchmark for the scanner's own evaluation. It binds to 127.0.0.1,
holds no real data, and must never be exposed to a network. Every route is
annotated with its ground-truth label so `evaluate` can compute precision,
recall and F1 for the scanner — i.e. this file is a *measuring instrument*,
not a deployable service.

It uses an in-memory SQLite DB and deliberately-wrong patterns (string-built
SQL, unescaped output) on the "vulnerable" routes, and the correct patterns
(parameterized queries, escaping) on the "/safe-*" routes, so the scanner can
be scored against both positives and true negatives.

Layout:
  SQLi (error + boolean)      : /user, /product, /article, /order, /lookup, /note
  SQLi auth-bypass style      : POST /login
  Reflected XSS (contexts)    : /search, /greet, /echo, /profile, /comment, /tag
  Safe negatives              : /safe-user, /safe-search, /safe-profile
GROUND_TRUTH lists every (path, method, param, vuln_type) that *should* fire.
"""
from __future__ import annotations

import html
import sqlite3
from dataclasses import dataclass

from flask import Flask, redirect, render_template_string, request, Response

# ---------------------------------------------------------------- shared CSS
_CSS = """
  *{box-sizing:border-box;margin:0;padding:0}
  :root{
    --bg:#0f172a;--surface:#1e293b;--surface2:#273449;--border:#334155;
    --text:#e2e8f0;--muted:#94a3b8;--accent:#38bdf8;--red:#f87171;
    --green:#4ade80;--yellow:#fbbf24;--orange:#fb923c;
    --font:'Segoe UI',system-ui,sans-serif;--mono:'Cascadia Code','Fira Code',monospace
  }
  body{background:var(--bg);color:var(--text);font-family:var(--font);
       min-height:100vh;line-height:1.55}
  a{color:var(--accent);text-decoration:none}
  a:hover{text-decoration:underline;opacity:.85}
  /* topbar */
  .topbar{background:var(--surface);border-bottom:1px solid var(--border);
          padding:0 24px;display:flex;align-items:center;gap:14px;height:52px}
  .topbar .logo{font-weight:700;font-size:17px;letter-spacing:.3px;color:#fff}
  .topbar .logo span{color:var(--red)}
  .topbar .pill{font-size:11px;font-weight:700;padding:3px 9px;border-radius:99px;
                letter-spacing:.05em;text-transform:uppercase}
  .pill-warn{background:#7f1d1d;color:var(--red);border:1px solid var(--red)}
  .pill-safe{background:#14532d;color:var(--green);border:1px solid var(--green)}
  .topbar .sub{color:var(--muted);font-size:13px;margin-left:auto}
  /* layout */
  .container{max-width:1020px;margin:0 auto;padding:28px 20px 60px}
  /* banner */
  .banner{background:#431407;border:1px solid var(--orange);border-radius:10px;
          padding:14px 18px;margin-bottom:26px;font-size:13px;color:#fed7aa;
          display:flex;gap:10px;align-items:flex-start}
  .banner b{color:var(--orange)}
  /* section headers */
  .sh{font-size:11px;text-transform:uppercase;letter-spacing:.09em;
      color:var(--muted);font-weight:700;margin:0 0 10px}
  /* grid of endpoint cards */
  .grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(210px,1fr));gap:12px;margin-bottom:28px}
  .card{background:var(--surface);border:1px solid var(--border);border-radius:10px;
        padding:14px 16px;transition:border-color .15s}
  .card:hover{border-color:var(--accent)}
  .card .route{font-family:var(--mono);font-size:13px;font-weight:700;margin-bottom:5px}
  .card .desc{font-size:12px;color:var(--muted);margin-bottom:10px}
  .card a{font-size:13px;font-weight:600}
  .tag{display:inline-block;font-size:10px;font-weight:700;padding:2px 7px;
       border-radius:99px;text-transform:uppercase;letter-spacing:.05em;margin-bottom:6px}
  .tag-sqli{background:#450a0a;color:var(--red);border:1px solid #7f1d1d}
  .tag-xss{background:#422006;color:var(--yellow);border:1px solid #92400e}
  .tag-safe{background:#052e16;color:var(--green);border:1px solid #14532d}
  /* login form */
  .login-box{background:var(--surface);border:1px solid var(--border);border-radius:10px;
             padding:18px 20px;max-width:380px}
  .login-box h3{font-size:15px;margin-bottom:12px;color:var(--muted);font-weight:600}
  .login-box input{background:var(--surface2);border:1px solid var(--border);
                   border-radius:7px;padding:8px 11px;color:var(--text);
                   font-size:14px;width:100%;margin-bottom:8px}
  .login-box button{background:var(--accent);color:#0c1a2e;font-weight:700;
                    border:none;border-radius:7px;padding:9px 18px;
                    cursor:pointer;font-size:14px;width:100%}
  /* result pages */
  .result{background:var(--surface);border:1px solid var(--border);
          border-radius:10px;padding:18px 20px;margin-top:18px}
  .result p{margin-bottom:6px;font-size:14px}
  pre.db-error{background:#1e0000;border:1px solid #7f1d1d;border-radius:8px;
               padding:14px 16px;font-family:var(--mono);font-size:13px;
               color:var(--red);margin-top:8px;white-space:pre-wrap;word-break:break-word}
  .back{margin-top:16px;font-size:13px}
"""

# shared page wrapper
def _page(title: str, body: str, badge: str = "vuln", badge_label: str = "Vulnerable") -> str:
    pill_cls = "pill-warn" if badge == "vuln" else "pill-safe"
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>{html.escape(title)} · Vuln Lab</title>
  <style>{_CSS}</style>
</head>
<body>
  <div class="topbar">
    <div class="logo">⚡ Vuln<span>Lab</span></div>
    <span class="pill {pill_cls}">{html.escape(badge_label)}</span>
    <span class="sub">Benchmark target · localhost only · Bistrit Koirala / 23BCE2298</span>
  </div>
  <div class="container">
    {body}
  </div>
</body>
</html>"""


# ---------------------------------------------------------------- in-memory DB
def _make_db() -> sqlite3.Connection:
    con = sqlite3.connect(":memory:", check_same_thread=False)
    con.executescript(
        """
        CREATE TABLE users(id INTEGER PRIMARY KEY, name TEXT, email TEXT, role TEXT);
        INSERT INTO users(id,name,email,role) VALUES
            (1,'alice','alice@lab.test','user'),
            (2,'bob','bob@lab.test','user'),
            (3,'carol','carol@lab.test','admin');
        CREATE TABLE products(id INTEGER PRIMARY KEY, title TEXT, price REAL);
        INSERT INTO products(id,title,price) VALUES
            (1,'Keyboard',29.0),(2,'Mouse',15.0),(3,'Monitor',180.0);
        CREATE TABLE articles(id INTEGER PRIMARY KEY, slug TEXT, body TEXT);
        INSERT INTO articles(id,slug,body) VALUES
            (1,'intro','Welcome to the lab'),(2,'guide','How to test safely');
        CREATE TABLE orders(id INTEGER PRIMARY KEY, ref TEXT, total REAL);
        INSERT INTO orders(id,ref,total) VALUES (1,'R-100',44.0),(2,'R-101',195.0);
        CREATE TABLE notes(id INTEGER PRIMARY KEY, tag TEXT, text TEXT);
        INSERT INTO notes(id,tag,text) VALUES (1,'todo','buy milk'),(2,'idea','ship it');
        CREATE TABLE creds(id INTEGER PRIMARY KEY, username TEXT, password TEXT);
        INSERT INTO creds(id,username,password) VALUES (1,'admin','s3cret');
        """
    )
    con.commit()
    return con


def create_app() -> Flask:
    app = Flask(__name__)
    db = _make_db()

    def q(sql: str):
        cur = db.execute(sql)
        return cur.fetchall()

    def vq(sql: str) -> str:
        """Vulnerable-route query helper that LEAKS DB errors into the page.

        This models the common misconfiguration of verbose database errors
        being shown to the user (display_errors on). On success it returns the
        rows as HTML; on a DB error it returns the raw error message in the
        body — exactly the signal an error-based detector fingerprints. Still
        localhost-only and holding no real data.
        """
        try:
            rows = db.execute(sql).fetchall()
            return "".join(
                "<p>" + " ".join(html.escape(str(c)) for c in r) + "</p>"
                for r in rows)
        except sqlite3.Error as exc:
            # Verbose DB error leaked to the response (the vulnerability). The
            # message text is escaped so THIS route leaks only a SQL signature,
            # not a reflected-XSS vector — keeping each route a single-class
            # benchmark. The SQL fingerprints (e.g. "unrecognized token:") are
            # plain text and survive escaping intact.
            return f"<pre class='db-error'>SQL error: {html.escape(str(exc))}</pre>"

    # ------------------------------------------------------------ home / index
    @app.route("/")
    def index():
        sqli_cards = [
            ("/user?id=1",     "id",   "Numeric param concatenated into SQL"),
            ("/product?id=1",  "id",   "Product lookup — numeric injection"),
            ("/article?slug=intro", "slug", "String param, single-quote context"),
            ("/order?ref=R-100",    "ref",  "String param — order lookup"),
            ("/lookup?id=1",   "id",   "Notes lookup — numeric injection"),
            ("/note?id=1",     "id",   "Text notes — numeric injection"),
        ]
        xss_cards = [
            ("/search?q=test",     "q",    "Text-node reflection"),
            ("/greet?name=sam",    "name", "Text-node reflection"),
            ("/echo?msg=hi",       "msg",  "Text-node reflection"),
            ("/profile?bio=hello", "bio",  "Double-quoted attribute context"),
            ("/comment?text=hi",   "text", "Text node — two reflections"),
            ("/tag?name=red",      "name", "Single-quoted attribute context"),
        ]
        redir_cards = [
            ("/go?url=/safe-user?id=1", "url", "Unvalidated redirect target"),
        ]
        ssti_cards = [
            ("/render?name=world", "name", "User input compiled as template source"),
        ]
        safe_cards = [
            ("/safe-user?id=1",    "id",   "Parameterized query — no error leak"),
            ("/safe-search?q=test","q",    "html.escape() applied before output"),
            ("/safe-profile?bio=hi","bio", "Attribute value escaped with quote=True"),
            ("/safe-go?url=/safe-user?id=1", "url", "Relative-path allowlist before redirecting"),
            ("/safe-render?name=world", "name", "User input passed as template data only"),
        ]

        def render_cards(cards, cls, label):
            out = []
            for href, param, desc in cards:
                route = "/" + href.split("?")[0].lstrip("/")
                out.append(f"""
                <div class="card">
                  <span class="tag tag-{cls}">{label}</span>
                  <div class="route">{html.escape(route)}</div>
                  <div class="desc">{html.escape(desc)}</div>
                  <a href="{html.escape(href)}">?{html.escape(param)}= →</a>
                </div>""")
            return "\n".join(out)

        body = f"""
        <div class="banner">
          <span>⚠</span>
          <div>
            <b>Intentionally Vulnerable Benchmark</b> — This app exists only as a
            scanner evaluation target. It runs on <b>localhost only</b>, holds no real
            data, and must never be exposed to a network.
            Every "Vulnerable" route has a labeled ground-truth entry used to compute
            precision / recall / F1.
          </div>
        </div>

        <div class="sh">SQL Injection targets · CWE-89 · error-based &amp; boolean-differential</div>
        <div class="grid">{render_cards(sqli_cards, 'sqli', 'SQLi')}</div>

        <div class="sh">Reflected XSS targets · CWE-79 · text / attribute contexts</div>
        <div class="grid">{render_cards(xss_cards, 'xss', 'XSS')}</div>

        <div class="sh">Open Redirect targets · CWE-601 · new in xssql</div>
        <div class="grid">{render_cards(redir_cards, 'sqli', 'Redirect')}</div>

        <div class="sh">SSTI targets · CWE-1336 · new in xssql</div>
        <div class="grid">{render_cards(ssti_cards, 'sqli', 'SSTI')}</div>

        <div class="sh">Safe negatives · parameterized queries + escaped output</div>
        <div class="grid">{render_cards(safe_cards, 'safe', 'Safe')}</div>

        <div class="sh">Auth bypass (SQLi) · POST /login</div>
        <div class="login-box">
          <h3>Login — both fields are injectable (username + password)</h3>
          <form method="post" action="/login">
            <input name="username" placeholder="username" value="">
            <input name="password" placeholder="password" value="" type="password">
            <button type="submit">Login</button>
          </form>
        </div>
        """
        return _page("Lab Index", body)

    # ================================================= SQLi — error + boolean
    @app.route("/user")
    def user():                      # VULN: id concatenated into SQL (numeric)
        uid = request.args.get("id", "1")
        body = vq(f"SELECT name,email FROM users WHERE id = {uid}")
        return "<html><body>" + body + "</body></html>"

    @app.route("/product")
    def product():                   # VULN numeric
        pid = request.args.get("id", "1")
        body = vq(f"SELECT title,price FROM products WHERE id = {pid}")
        return "<html><body>" + body + "</body></html>"

    @app.route("/article")
    def article():                   # VULN: string param, single-quote context
        slug = request.args.get("slug", "intro")
        body = vq(f"SELECT body FROM articles WHERE slug = '{slug}'")
        return "<html><body>" + body + "</body></html>"

    @app.route("/order")
    def order():                     # VULN: string param
        ref = request.args.get("ref", "R-100")
        body = vq(f"SELECT total FROM orders WHERE ref = '{ref}'")
        return "<html><body>" + body + "</body></html>"

    @app.route("/lookup")
    def lookup():                    # VULN numeric
        nid = request.args.get("id", "1")
        body = vq(f"SELECT tag,text FROM notes WHERE id = {nid}")
        return "<html><body>" + body + "</body></html>"

    @app.route("/note")
    def note():                      # VULN numeric
        nid = request.args.get("id", "1")
        body = vq(f"SELECT text FROM notes WHERE id = {nid}")
        return "<html><body>" + body + "</body></html>"

    @app.route("/login", methods=["POST"])
    def login():                     # VULN: classic auth-bypass style injection
        u = request.form.get("username", "")
        p = request.form.get("password", "")
        body = vq(f"SELECT username FROM creds WHERE username = '{u}' AND password = '{p}'")
        if "<p>" in body:
            return "<html><body>welcome<br>" + body + "</body></html>"
        # error (leaked) or no match — both returned in body
        return "<html><body>" + (body or "invalid") + "</body></html>"

    # ================================================= Reflected XSS contexts
    @app.route("/search")
    def search():                    # VULN: text-node reflection
        term = request.args.get("q", "")
        return f"<html><body><h2>Results for {term}</h2></body></html>"

    @app.route("/greet")
    def greet():                     # VULN: text node
        name = request.args.get("name", "")
        return f"<html><body><p>Hello, {name}!</p></body></html>"

    @app.route("/echo")
    def echo():                      # VULN: text node
        msg = request.args.get("msg", "")
        return f"<html><body><div>{msg}</div></body></html>"

    @app.route("/profile")
    def profile():                   # VULN: double-quoted attribute context
        bio = request.args.get("bio", "")
        return f'<html><body><input type="text" value="{bio}"></body></html>'

    @app.route("/comment")
    def comment():                   # VULN: text node (multiple reflections)
        text = request.args.get("text", "")
        return f"<html><body><p>{text}</p><blockquote>{text}</blockquote></body></html>"

    @app.route("/tag")
    def tag():                       # VULN: single-quoted attribute context
        name = request.args.get("name", "")
        return f"<html><body><span class='{name}'>tag</span></body></html>"

    # ================================================= Safe negatives
    @app.route("/safe-user")
    def safe_user():                 # SAFE: parameterized query
        uid = request.args.get("id", "1")
        try:
            rows = db.execute("SELECT name,email FROM users WHERE id = ?", (uid,)).fetchall()
        except sqlite3.Error:
            rows = []                # typed mismatch -> empty, no error leak
        return "<html><body>" + "".join(
            f"<p>{html.escape(r[0])} {html.escape(r[1])}</p>" for r in rows) + "</body></html>"

    @app.route("/safe-search")
    def safe_search():               # SAFE: output escaped
        term = request.args.get("q", "")
        return f"<html><body><h2>Results for {html.escape(term)}</h2></body></html>"

    @app.route("/safe-profile")
    def safe_profile():              # SAFE: attribute value escaped
        bio = request.args.get("bio", "")
        return f'<html><body><input type="text" value="{html.escape(bio, quote=True)}"></body></html>'

    # ================================================= Open Redirect (new)
    @app.route("/go")
    def go():                        # VULN: redirects to a raw, unvalidated URL
        target = request.args.get("url", "/")
        return redirect(target)

    @app.route("/safe-go")
    def safe_go():                   # SAFE: only relative, same-app paths allowed
        target = request.args.get("url", "/")
        if not target.startswith("/") or target.startswith("//"):
            target = "/"
        return redirect(target)

    # ================================================= SSTI (new)
    @app.route("/render")
    def render():                    # VULN: user input compiled as template source
        # html.escape() neutralizes <, >, ", ' (so this route is SSTI-only,
        # not also classic XSS) but it does NOT touch { or } — so Jinja
        # expression syntax like {{7*7}} still gets compiled and evaluated,
        # which is exactly the SSTI root cause (CWE-1336): the issue is that
        # user input reaches the template *source*, not that it's escaped.
        name = html.escape(request.args.get("name", "world"))
        return render_template_string(f"<html><body><p>Hello {name}!</p></body></html>")

    @app.route("/safe-render")
    def safe_render():               # SAFE: user input passed as template data only
        name = request.args.get("name", "world")
        return render_template_string(
            "<html><body><p>Hello {{ name }}!</p></body></html>", name=name)

    return app


# ---------------------------------------------------------------- ground truth
@dataclass(frozen=True)
class Truth:
    path: str
    method: str
    parameter: str
    vuln_type: str          # "sqli" (either sqli_* type) or "xss"


# Every (endpoint, parameter) that SHOULD produce a finding, with the class.
# vuln_type "sqli" matches either sqli_error or sqli_boolean (both are CWE-89).
GROUND_TRUTH: list[Truth] = [
    Truth("/user", "GET", "id", "sqli"),
    Truth("/product", "GET", "id", "sqli"),
    Truth("/article", "GET", "slug", "sqli"),
    Truth("/order", "GET", "ref", "sqli"),
    Truth("/lookup", "GET", "id", "sqli"),
    Truth("/note", "GET", "id", "sqli"),
    Truth("/login", "POST", "username", "sqli"),
    Truth("/login", "POST", "password", "sqli"),   # same query — also injectable
    Truth("/search", "GET", "q", "xss"),
    Truth("/greet", "GET", "name", "xss"),
    Truth("/echo", "GET", "msg", "xss"),
    Truth("/profile", "GET", "bio", "xss"),
    Truth("/comment", "GET", "text", "xss"),
    Truth("/tag", "GET", "name", "xss"),
    Truth("/go", "GET", "url", "open_redirect"),
    Truth("/render", "GET", "name", "ssti"),
]

# Routes that must yield ZERO findings (true negatives).
SAFE_ROUTES = ["/safe-user", "/safe-search", "/safe-profile",
              "/safe-go", "/safe-render"]


@dataclass
class Metrics:
    tp: int
    fp: int
    fn: int
    precision: float
    recall: float
    f1: float
    by_type: dict
    false_positive_endpoints: list


def _truth_class(vt: str) -> str:
    return "sqli" if vt.startswith("sqli") else ("xss" if vt.startswith("xss") else vt)


def compute_metrics(findings, truth=GROUND_TRUTH) -> Metrics:
    """Score a list of Finding-like objects against GROUND_TRUTH.

    A finding matches a truth row when path (url endswith), method, parameter
    and class agree. Multiple findings for the same truth row count once.
    """
    def path_of(url: str) -> str:
        from urllib.parse import urlsplit
        return urlsplit(url).path or url

    truth_set = {(t.path, t.method.upper(), t.parameter, _truth_class(t.vuln_type))
                 for t in truth}
    matched_truth = set()
    fp_endpoints = []
    seen_finding_keys = set()
    tp = fp = 0

    for f in findings:
        vt = f.vuln_type.value if hasattr(f.vuln_type, "value") else str(f.vuln_type)
        key = (path_of(f.url), f.method.upper(), f.parameter, _truth_class(vt))
        if key in seen_finding_keys:
            continue
        seen_finding_keys.add(key)
        if key in truth_set:
            tp += 1
            matched_truth.add(key)
        else:
            fp += 1
            fp_endpoints.append(f"{f.method} {path_of(f.url)}?{f.parameter} ({vt})")

    fn = len(truth_set) - len(matched_truth)
    precision = tp / (tp + fp) if (tp + fp) else 1.0
    recall = tp / (tp + fn) if (tp + fn) else 1.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0

    by_type: dict[str, dict] = {}
    for cls in ("sqli", "xss", "open_redirect", "ssti"):
        cls_truth = {k for k in truth_set if k[3] == cls}
        cls_tp = len({k for k in matched_truth if k[3] == cls})
        cls_fp = len([e for e in fp_endpoints if f"({cls}" in e or cls in e.split("(")[-1]])
        cls_fn = len(cls_truth) - cls_tp
        p = cls_tp / (cls_tp + cls_fp) if (cls_tp + cls_fp) else 1.0
        r = cls_tp / (cls_tp + cls_fn) if (cls_tp + cls_fn) else 1.0
        fm = (2 * p * r / (p + r)) if (p + r) else 0.0
        by_type[cls] = {"tp": cls_tp, "fp": cls_fp, "fn": cls_fn,
                        "precision": round(p, 4), "recall": round(r, 4),
                        "f1": round(fm, 4)}

    return Metrics(tp=tp, fp=fp, fn=fn,
                   precision=round(precision, 4), recall=round(recall, 4),
                   f1=round(f1, 4), by_type=by_type,
                   false_positive_endpoints=fp_endpoints)


if __name__ == "__main__":        # pragma: no cover
    # Bound to localhost ONLY. This app is a benchmark, never a service.
    create_app().run(host="127.0.0.1", port=5000, debug=False)
