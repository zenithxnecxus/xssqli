"""SQLite persistence with WAL (DESIGN_DOC_V2 §7, v1.1 schema).

Three tables — scans, endpoints, findings — with foreign keys. WAL mode plus a
busy timeout lets the dashboard read while a scan writes. All writes of
findings go through add_finding(), which the engine only calls *after* its own
in-memory dedupe, so the table never holds duplicates for one scan.
"""
from __future__ import annotations

import json
import sqlite3
import time
from dataclasses import asdict
from typing import Any, Optional

from .errors import StorageError
from .models import (Endpoint, Finding, ParamLocation, ReflectionContext,
                     ScanConfig, ScanStatus, Severity, VulnType)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    target          TEXT    NOT NULL,
    status          TEXT    NOT NULL,
    config_json     TEXT    NOT NULL,
    started_at      REAL    NOT NULL,
    finished_at     REAL,
    requests_sent   INTEGER NOT NULL DEFAULT 0,
    endpoints_found INTEGER NOT NULL DEFAULT 0,
    partial_reason  TEXT,
    error_message   TEXT
);

CREATE TABLE IF NOT EXISTS endpoints (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id   INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    url       TEXT    NOT NULL,
    method    TEXT    NOT NULL,
    params    TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS findings (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id            INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    vuln_type          TEXT    NOT NULL,
    severity           TEXT    NOT NULL,
    confidence         REAL    NOT NULL,
    url                TEXT    NOT NULL,
    method             TEXT    NOT NULL,
    parameter          TEXT    NOT NULL,
    param_location     TEXT    NOT NULL,
    payload            TEXT    NOT NULL,
    evidence           TEXT    NOT NULL,
    reflection_context TEXT,
    cwe                TEXT,
    remediation        TEXT,
    manual_review      INTEGER NOT NULL DEFAULT 0,
    created_at         REAL    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_endpoints_scan ON endpoints(scan_id);
"""


class Storage:
    def __init__(self, db_path: str = "xssql.db"):
        self.db_path = db_path
        try:
            self._conn = sqlite3.connect(db_path, check_same_thread=False)
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA journal_mode=WAL;")
            self._conn.execute("PRAGMA busy_timeout=5000;")
            self._conn.execute("PRAGMA foreign_keys=ON;")
            self._conn.executescript(_SCHEMA)
            self._conn.commit()
        except sqlite3.Error as exc:               # pragma: no cover
            raise StorageError(f"could not open database: {exc}") from exc

    # ---------------------------------------------------------------- scans
    def create_scan(self, cfg: ScanConfig) -> int:
        cur = self._conn.execute(
            "INSERT INTO scans(target, status, config_json, started_at) "
            "VALUES (?,?,?,?)",
            (cfg.target, ScanStatus.RUNNING.value,
             json.dumps(cfg.public_summary()), time.time()),
        )
        self._conn.commit()
        return int(cur.lastrowid)

    def finish_scan(self, scan_id: int, status: ScanStatus, *,
                    requests_sent: int = 0, endpoints_found: int = 0,
                    partial_reason: Optional[str] = None,
                    error_message: Optional[str] = None) -> None:
        self._conn.execute(
            "UPDATE scans SET status=?, finished_at=?, requests_sent=?, "
            "endpoints_found=?, partial_reason=?, error_message=? WHERE id=?",
            (status.value, time.time(), requests_sent, endpoints_found,
             partial_reason, error_message, scan_id),
        )
        self._conn.commit()

    def get_scan(self, scan_id: int) -> Optional[dict[str, Any]]:
        row = self._conn.execute("SELECT * FROM scans WHERE id=?",
                                 (scan_id,)).fetchone()
        return dict(row) if row else None

    def list_scans(self, limit: int = 100) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT s.*, "
            "(SELECT COUNT(*) FROM findings f WHERE f.scan_id = s.id) "
            "AS findings_count "
            "FROM scans s ORDER BY s.id DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]

    # ---------------------------------------------------------------- endpoints
    def add_endpoint(self, scan_id: int, ep: Endpoint) -> int:
        params = [{"name": p.name, "location": p.location.value,
                   "default_value": p.default_value} for p in ep.params]
        cur = self._conn.execute(
            "INSERT INTO endpoints(scan_id, url, method, params) VALUES (?,?,?,?)",
            (scan_id, ep.url, ep.method, json.dumps(params)),
        )
        self._conn.commit()
        return int(cur.lastrowid)

    def get_endpoints(self, scan_id: int) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT * FROM endpoints WHERE scan_id=? ORDER BY id", (scan_id,)
        ).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["params"] = json.loads(d["params"])
            out.append(d)
        return out

    # ---------------------------------------------------------------- findings
    def add_finding(self, scan_id: int, f: Finding) -> int:
        cur = self._conn.execute(
            "INSERT INTO findings(scan_id, vuln_type, severity, confidence, url, "
            "method, parameter, param_location, payload, evidence, "
            "reflection_context, cwe, remediation, manual_review, created_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (scan_id, f.vuln_type.value, f.severity.value, f.confidence, f.url,
             f.method, f.parameter, f.param_location.value, f.payload,
             f.evidence,
             f.reflection_context.value if f.reflection_context else None,
             f.cwe, f.remediation, int(f.manual_review), time.time()),
        )
        self._conn.commit()
        return int(cur.lastrowid)

    def get_findings(self, scan_id: int) -> list[Finding]:
        rows = self._conn.execute(
            "SELECT * FROM findings WHERE scan_id=? "
            "ORDER BY confidence DESC, id", (scan_id,)).fetchall()
        return [self._row_to_finding(r) for r in rows]

    def get_findings_raw(self, scan_id: int) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT * FROM findings WHERE scan_id=? "
            "ORDER BY confidence DESC, id", (scan_id,)).fetchall()
        return [dict(r) for r in rows]

    @staticmethod
    def _row_to_finding(r: sqlite3.Row) -> Finding:
        rc = r["reflection_context"]
        return Finding(
            vuln_type=VulnType(r["vuln_type"]),
            severity=Severity(r["severity"]),
            confidence=r["confidence"],
            url=r["url"], method=r["method"], parameter=r["parameter"],
            param_location=ParamLocation(r["param_location"]),
            payload=r["payload"], evidence=r["evidence"],
            reflection_context=ReflectionContext(rc) if rc else None,
            cwe=r["cwe"] or "", remediation=r["remediation"] or "",
            manual_review=bool(r["manual_review"]),
        )

    # ---------------------------------------------------------------- lifecycle
    def close(self) -> None:
        try:
            self._conn.close()
        except sqlite3.Error:                       # pragma: no cover
            pass
