"""Engine tests: event order, dedupe, partial-on-deadline, termination."""
from xssql.engine import ScanEngine
from xssql.events import EventType
from xssql.config import load_config_from_dict
from xssql.models import ScanStatus
from xssql.storage import Storage
from xssql.evaluate import _LabServer, _import_lab


def _run(deadline=60.0, max_requests=4000, collect_events=False):
    lab = _import_lab()
    app = lab.create_app()
    storage = Storage(":memory:")
    events = []
    with _LabServer(app) as srv:
        cfg = load_config_from_dict({
            "target": srv.base_url, "consent": True, "max_pages": 30,
            "rate_limit_rps": 50.0, "scan_deadline_s": deadline,
            "max_requests": max_requests,
        })
        emit = events.append if collect_events else (lambda e: None)
        summary = ScanEngine(cfg, storage, emit=emit).run()
    return storage, summary, events


def test_event_order_and_types():
    storage, summary, events = _run(collect_events=True)
    types = [e.type for e in events]
    assert types[0] == EventType.SCAN_STARTED
    assert types[-1] == EventType.SCAN_FINISHED
    assert EventType.PHASE in types
    assert EventType.ENDPOINT_FOUND in types
    assert EventType.FINDING in types
    # scan_started precedes first finding; finding precedes scan_finished
    assert types.index(EventType.SCAN_STARTED) < types.index(EventType.FINDING)
    assert types.index(EventType.FINDING) < types.index(EventType.SCAN_FINISHED)
    storage.close()


def test_summary_counts_match_findings_table():
    storage, summary, _ = _run()
    rows = storage.get_findings(summary.scan_id)
    assert summary.findings_total == len(rows)
    by_type = {}
    for f in rows:
        by_type[f.vuln_type.value] = by_type.get(f.vuln_type.value, 0) + 1
    assert summary.by_type == by_type
    storage.close()


def test_no_duplicate_findings_per_key():
    storage, summary, _ = _run()
    rows = storage.get_findings(summary.scan_id)
    from xssql.crawler import strip_values
    keys = [f.dedupe_key(strip_values(f.url)) for f in rows]
    assert len(keys) == len(set(keys)), "duplicate findings written"
    storage.close()


def test_tiny_deadline_returns_partial_and_terminates():
    # 1s deadline: scan must still return a valid summary (DONE or DONE_PARTIAL)
    storage, summary, _ = _run(deadline=1.0)
    assert summary.status in (ScanStatus.DONE, ScanStatus.DONE_PARTIAL)
    assert isinstance(summary.requests_sent, int)
    storage.close()


def test_request_cap_terminates():
    storage, summary, _ = _run(max_requests=15)
    assert summary.status in (ScanStatus.DONE, ScanStatus.DONE_PARTIAL)
    assert summary.requests_sent <= 15
    storage.close()
