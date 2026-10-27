"""End-to-end evaluation: the scanner must hit its accuracy targets on the lab.

This is the test that backs the results chapter: it runs a full scan through
the real engine against the ground-truth app and asserts the REVIEW_2 §3.2
success criteria (precision >= 0.90, recall >= 0.80, F1 >= 0.85, zero findings
on /safe-* routes, wall-clock <= 60 s).
"""
from xssql.evaluate import (evaluate_against_lab, run_lab_scan,
                              TARGET_F1, TARGET_PRECISION, TARGET_RECALL)


def test_metrics_meet_targets():
    result = evaluate_against_lab(":memory:")
    m = result["metrics"]
    assert m.precision >= TARGET_PRECISION, result["report_text"]
    assert m.recall >= TARGET_RECALL, result["report_text"]
    assert m.f1 >= TARGET_F1, result["report_text"]
    assert result["passed"]


def test_zero_findings_on_safe_routes():
    storage, summary, lab = run_lab_scan(":memory:")
    from urllib.parse import urlsplit
    findings = storage.get_findings(summary.scan_id)
    safe_hits = [f for f in findings
                 if any(urlsplit(f.url).path.endswith(sr) for sr in lab.SAFE_ROUTES)]
    assert safe_hits == [], f"false positives on safe routes: {safe_hits}"
    storage.close()


def test_scan_wall_clock_bounded():
    storage, summary, _ = run_lab_scan(":memory:")
    assert summary.duration_s <= 60.0
    storage.close()
