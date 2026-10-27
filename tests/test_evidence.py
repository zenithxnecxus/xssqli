"""Unit tests for evidence helpers (normalization, delta rule, signatures)."""
from xssql import evidence


def test_normalize_strips_csrf_token():
    a = '<input name="csrf_token" value="AAA111">hello'
    b = '<input name="csrf_token" value="ZZZ999">hello'
    assert evidence.similarity_ratio(a, b) >= 0.99


def test_normalize_strips_session_and_timestamp():
    a = "sessionid=abc123def456 time 2024-01-01T10:00:00 body"
    b = "sessionid=zzz999yyy888 time 2024-06-02T22:31:11 body"
    assert evidence.similarity_ratio(a, b) >= 0.99


def test_identical_pages_ratio_one():
    assert evidence.similarity_ratio("<html>x</html>", "<html>x</html>") == 1.0


def test_boolean_divergence_fires_on_true_false_pair():
    baseline = "ROWS: alice bob carol " * 20
    r_true = "ROWS: alice bob carol " * 20            # true ~ baseline
    r_false = "no results found " * 20                # false diverges
    fired, ratios = evidence.boolean_divergence(baseline, r_true, r_false,
                                                threshold=0.85, delta=0.10)
    assert fired
    assert ratios["ratio_baseline_true"] >= 0.85
    assert ratios["ratio_true_false"] <= 0.75


def test_boolean_divergence_does_not_fire_when_both_similar():
    baseline = "same content here " * 20
    r_true = "same content here " * 20
    r_false = "same content here " * 20               # no divergence
    fired, _ = evidence.boolean_divergence(baseline, r_true, r_false, 0.85, 0.10)
    assert not fired


def test_boolean_divergence_edge_just_below_gap():
    # true≈baseline but false only marginally differs -> must NOT fire
    baseline = "x" * 1000
    r_true = "x" * 1000
    r_false = "x" * 995 + "yyyyy"                      # ~99% similar
    fired, ratios = evidence.boolean_divergence(baseline, r_true, r_false, 0.85, 0.10)
    assert not fired


def test_sql_error_signatures_per_family():
    cases = {
        "MySQL": "You have an error in your SQL syntax; check the manual",
        "SQLite": 'unrecognized token: "\'"',
        "PostgreSQL": "PostgreSQL query failed: ERROR: syntax",
        "MSSQL": "Unclosed quotation mark after the character string",
        "Oracle": "ORA-00933: SQL command not properly ended",
    }
    for family, body in cases.items():
        hits = evidence.find_sql_error_signatures(body)
        fams = {f for f, _ in hits}
        assert family in fams, f"{family} not detected in {hits}"


def test_no_sql_signature_on_clean_page():
    assert evidence.find_sql_error_signatures("<html>all good</html>") == []


def test_encoded_metachars_detected():
    body = "reflect k3vABC &lt;&gt; here"
    assert evidence.html_encoded_form(body, "k3vABC")
    assert evidence.metacharacters_unencoded(body, "k3vABC") == []


def test_unencoded_metachars_detected():
    body = 'reflect k3vABC<>"\' here'
    survived = evidence.metacharacters_unencoded(body, "k3vABC")
    assert "<" in survived and ">" in survived


def test_extract_snippet_is_html_escaped():
    body = "before <script>evil</script> after target zone"
    snip = evidence.extract_snippet(body, "target")
    assert "<script>" not in snip            # escaped
    assert "target" in snip
