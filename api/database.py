"""
SQLite database persistence layer for VulnPatch.

Provides database initialization, table creation, and CRUD operations
for scans, findings, evidence, agent_logs, and reports.
Uses Python's built-in sqlite3 module with JSON serialization for
complex fields.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Default database location: f:\test\data\vulnpatch.db
_DEFAULT_DB_DIR = Path(__file__).resolve().parent.parent / "data"
_DEFAULT_DB_PATH = _DEFAULT_DB_DIR / "vulnpatch.db"


def _get_db_path() -> Path:
    """Return the database file path, creating parent directories if needed."""
    db_path = _DEFAULT_DB_PATH
    db_path.parent.mkdir(parents=True, exist_ok=True)
    return db_path


# ---------------------------------------------------------------------------
# Connection helper
# ---------------------------------------------------------------------------

_local = threading.local()


def _get_connection(db_path: Optional[str] = None) -> sqlite3.Connection:
    """
    Return a thread-local SQLite connection.

    Each thread gets its own connection to avoid concurrency issues.
    The connection is created lazily and reused within the same thread.
    """
    if not hasattr(_local, "connection") or _local.connection is None:
        path = db_path or str(_get_db_path())
        conn = sqlite3.connect(path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        _local.connection = conn
    return _local.connection


def close_connection() -> None:
    """Close the thread-local connection (useful for testing / cleanup)."""
    if hasattr(_local, "connection") and _local.connection is not None:
        _local.connection.close()
        _local.connection = None


# ---------------------------------------------------------------------------
# Table definitions
# ---------------------------------------------------------------------------

_CREATE_TABLES_SQL = """
-- Projects table: top-level project grouping
CREATE TABLE IF NOT EXISTS projects (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    repo_url        TEXT NOT NULL DEFAULT '',
    language        TEXT NOT NULL DEFAULT '',
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Scans table: one row per audit session
CREATE TABLE IF NOT EXISTS scans (
    scan_id         TEXT PRIMARY KEY,
    project_id      TEXT,
    summary_json    TEXT NOT NULL DEFAULT '{}',
    metadata_json   TEXT NOT NULL DEFAULT '{}',
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at      TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS idx_scans_project_id ON scans(project_id);

-- Findings table: individual vulnerability findings within a scan
CREATE TABLE IF NOT EXISTS findings (
    id              TEXT PRIMARY KEY,
    scan_id         TEXT NOT NULL,
    rule_id         TEXT NOT NULL,
    type            TEXT NOT NULL,
    cwe             TEXT,
    severity        TEXT NOT NULL DEFAULT 'UNKNOWN',
    confidence      TEXT NOT NULL DEFAULT 'low',
    file_path       TEXT NOT NULL,
    start_line      INTEGER NOT NULL,
    end_line        INTEGER,
    message         TEXT NOT NULL,
    engine          TEXT NOT NULL,
    evidence_json   TEXT NOT NULL DEFAULT '{}',
    metadata_json   TEXT NOT NULL DEFAULT '{}',
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at      TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);

-- Evidence table: evidence bundles associated with findings
CREATE TABLE IF NOT EXISTS evidence (
    id                  TEXT PRIMARY KEY,
    scan_id             TEXT NOT NULL,
    finding_id          TEXT,
    finding_json        TEXT NOT NULL DEFAULT '{}',
    code_unit_json      TEXT,
    snippets_json       TEXT NOT NULL DEFAULT '[]',
    call_chain_json     TEXT NOT NULL DEFAULT '[]',
    agent_hypotheses_json TEXT NOT NULL DEFAULT '[]',
    agent_logs_json     TEXT NOT NULL DEFAULT '[]',
    judge_decision_json TEXT,
    cwe_info_json       TEXT NOT NULL DEFAULT '{}',
    score_breakdown_json TEXT NOT NULL DEFAULT '{}',
    metadata_json       TEXT NOT NULL DEFAULT '{}',
    created_at          TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at          TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_evidence_scan_id ON evidence(scan_id);

-- Agent logs table: execution logs from agents
CREATE TABLE IF NOT EXISTS agent_logs (
    id              TEXT PRIMARY KEY,
    scan_id         TEXT NOT NULL,
    agent_name      TEXT NOT NULL,
    stage           TEXT NOT NULL,
    message         TEXT NOT NULL,
    input_refs_json TEXT NOT NULL DEFAULT '[]',
    output_refs_json TEXT NOT NULL DEFAULT '[]',
    timestamp       TEXT NOT NULL DEFAULT (datetime('now')),
    metadata_json   TEXT NOT NULL DEFAULT '{}',
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at      TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_agent_logs_scan_id ON agent_logs(scan_id);

-- Reports table: generated reports metadata
CREATE TABLE IF NOT EXISTS reports (
    id              TEXT PRIMARY KEY,
    scan_id         TEXT NOT NULL,
    format          TEXT NOT NULL,
    content         TEXT,
    file_path       TEXT,
    metadata_json   TEXT NOT NULL DEFAULT '{}',
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at      TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_reports_scan_id ON reports(scan_id);

-- Users table: for JWT-based authentication
CREATE TABLE IF NOT EXISTS users (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    username        TEXT    NOT NULL UNIQUE,
    password_hash   TEXT    NOT NULL,
    salt            TEXT    NOT NULL,
    is_admin        INTEGER NOT NULL DEFAULT 0,
    created_at      TEXT    NOT NULL DEFAULT (datetime('now')),
    updated_at      TEXT    NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
"""


# ---------------------------------------------------------------------------
# Initialization
# ---------------------------------------------------------------------------

_initialized = threading.local()


def init_db(db_path: Optional[str] = None) -> None:
    """
    Initialize the database: create tables if they do not exist.

    This function is idempotent; calling it multiple times is safe.
    It only runs the CREATE TABLE statements once per thread.
    """
    if getattr(_initialized, "done", False):
        return

    conn = _get_connection(db_path)
    conn.executescript(_CREATE_TABLES_SQL)
    conn.commit()
    _initialized.done = True


def _ensure_init(db_path: Optional[str] = None) -> None:
    """Ensure the database is initialized before any operation."""
    if not getattr(_initialized, "done", False):
        init_db(db_path)


# ---------------------------------------------------------------------------
# Helper: current UTC timestamp as ISO string
# ---------------------------------------------------------------------------

def _now_utc() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Scan CRUD
# ---------------------------------------------------------------------------

def create_scan(
    scan_id: str,
    summary_json: str = "{}",
    metadata_json: str = "{}",
    project_id: Optional[str] = None,
) -> None:
    """Insert a new scan record."""
    _ensure_init()
    conn = _get_connection()
    now = _now_utc()
    conn.execute(
        """
        INSERT OR REPLACE INTO scans (scan_id, project_id, summary_json, metadata_json, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (scan_id, project_id, summary_json, metadata_json, now, now),
    )
    conn.commit()


def get_scan(scan_id: str) -> Optional[dict[str, Any]]:
    """Retrieve a scan by scan_id. Returns a dict or None."""
    _ensure_init()
    conn = _get_connection()
    row = conn.execute(
        "SELECT * FROM scans WHERE scan_id = ?", (scan_id,)
    ).fetchone()
    if row is None:
        return None
    return dict(row)


def get_all_scans() -> list[dict[str, Any]]:
    """Retrieve all scans, ordered by created_at descending."""
    _ensure_init()
    conn = _get_connection()
    rows = conn.execute(
        "SELECT * FROM scans ORDER BY created_at DESC"
    ).fetchall()
    return [dict(r) for r in rows]


def get_latest_scan() -> Optional[dict[str, Any]]:
    """Retrieve the most recently created scan."""
    _ensure_init()
    conn = _get_connection()
    row = conn.execute(
        "SELECT * FROM scans ORDER BY created_at DESC LIMIT 1"
    ).fetchone()
    if row is None:
        return None
    return dict(row)


def update_scan(
    scan_id: str,
    summary_json: Optional[str] = None,
    metadata_json: Optional[str] = None,
) -> bool:
    """Update a scan's summary and/or metadata. Returns True if updated."""
    _ensure_init()
    conn = _get_connection()
    now = _now_utc()

    # Build dynamic SET clause
    sets: list[str] = ["updated_at = ?"]
    params: list[Any] = [now]

    if summary_json is not None:
        sets.append("summary_json = ?")
        params.append(summary_json)
    if metadata_json is not None:
        sets.append("metadata_json = ?")
        params.append(metadata_json)

    params.append(scan_id)

    cursor = conn.execute(
        f"UPDATE scans SET {', '.join(sets)} WHERE scan_id = ?",
        params,
    )
    conn.commit()
    return cursor.rowcount > 0


def delete_scan(scan_id: str) -> bool:
    """Delete a scan and all associated records (cascading). Returns True if deleted."""
    _ensure_init()
    conn = _get_connection()
    cursor = conn.execute("DELETE FROM scans WHERE scan_id = ?", (scan_id,))
    conn.commit()
    return cursor.rowcount > 0


def has_scan(scan_id: str) -> bool:
    """Check if a scan exists."""
    _ensure_init()
    conn = _get_connection()
    row = conn.execute(
        "SELECT 1 FROM scans WHERE scan_id = ?", (scan_id,)
    ).fetchone()
    return row is not None


def get_scan_ids() -> list[str]:
    """Return all scan_ids, ordered by created_at descending."""
    _ensure_init()
    conn = _get_connection()
    rows = conn.execute(
        "SELECT scan_id FROM scans ORDER BY created_at DESC"
    ).fetchall()
    return [r["scan_id"] for r in rows]


# ---------------------------------------------------------------------------
# Finding CRUD
# ---------------------------------------------------------------------------

def create_finding(finding_data: dict[str, Any]) -> None:
    """
    Insert a new finding record.

    Expected keys in finding_data:
        id, scan_id, rule_id, type, cwe, severity, confidence,
        file_path, start_line, end_line, message, engine,
        evidence (dict), metadata (dict)
    """
    _ensure_init()
    conn = _get_connection()
    now = _now_utc()
    conn.execute(
        """
        INSERT OR REPLACE INTO findings (
            id, scan_id, rule_id, type, cwe, severity, confidence,
            file_path, start_line, end_line, message, engine,
            evidence_json, metadata_json, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            finding_data.get("id"),
            finding_data.get("scan_id"),
            finding_data.get("rule_id"),
            finding_data.get("type"),
            finding_data.get("cwe"),
            finding_data.get("severity", "UNKNOWN"),
            finding_data.get("confidence", "low"),
            finding_data.get("file_path"),
            finding_data.get("start_line"),
            finding_data.get("end_line"),
            finding_data.get("message"),
            finding_data.get("engine"),
            json.dumps(finding_data.get("evidence", {}), ensure_ascii=False),
            json.dumps(finding_data.get("metadata", {}), ensure_ascii=False),
            now,
            now,
        ),
    )
    conn.commit()


def bulk_create_findings(findings: list[dict[str, Any]]) -> None:
    """Insert multiple findings in a single transaction."""
    _ensure_init()
    conn = _get_connection()
    now = _now_utc()
    rows = [
        (
            f.get("id"),
            f.get("scan_id"),
            f.get("rule_id"),
            f.get("type"),
            f.get("cwe"),
            f.get("severity", "UNKNOWN"),
            f.get("confidence", "low"),
            f.get("file_path"),
            f.get("start_line"),
            f.get("end_line"),
            f.get("message"),
            f.get("engine"),
            json.dumps(f.get("evidence", {}), ensure_ascii=False),
            json.dumps(f.get("metadata", {}), ensure_ascii=False),
            now,
            now,
        )
        for f in findings
    ]
    conn.executemany(
        """
        INSERT OR REPLACE INTO findings (
            id, scan_id, rule_id, type, cwe, severity, confidence,
            file_path, start_line, end_line, message, engine,
            evidence_json, metadata_json, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        rows,
    )
    conn.commit()


def get_findings(scan_id: str) -> list[dict[str, Any]]:
    """Get all findings for a scan, with evidence/metadata parsed from JSON."""
    _ensure_init()
    conn = _get_connection()
    rows = conn.execute(
        "SELECT * FROM findings WHERE scan_id = ? ORDER BY created_at",
        (scan_id,),
    ).fetchall()
    result = []
    for r in rows:
        d = dict(r)
        d["evidence"] = json.loads(d["evidence_json"])
        d["metadata"] = json.loads(d["metadata_json"])
        del d["evidence_json"]
        del d["metadata_json"]
        result.append(d)
    return result


def get_finding(finding_id: str) -> Optional[dict[str, Any]]:
    """Get a single finding by ID."""
    _ensure_init()
    conn = _get_connection()
    row = conn.execute(
        "SELECT * FROM findings WHERE id = ?", (finding_id,)
    ).fetchone()
    if row is None:
        return None
    d = dict(row)
    d["evidence"] = json.loads(d["evidence_json"])
    d["metadata"] = json.loads(d["metadata_json"])
    del d["evidence_json"]
    del d["metadata_json"]
    return d


def delete_findings_by_scan(scan_id: str) -> int:
    """Delete all findings for a scan. Returns number of deleted rows."""
    _ensure_init()
    conn = _get_connection()
    cursor = conn.execute(
        "DELETE FROM findings WHERE scan_id = ?", (scan_id,)
    )
    conn.commit()
    return cursor.rowcount


# ---------------------------------------------------------------------------
# Evidence CRUD
# ---------------------------------------------------------------------------

def create_evidence(evidence_data: dict[str, Any]) -> None:
    """
    Insert a new evidence record.

    Expected keys:
        id, scan_id, finding_id, finding (dict), code_unit (dict|None),
        snippets (list), call_chain (list), agent_hypotheses (list),
        agent_logs (list), judge_decision (dict|None), cwe_info (dict),
        score_breakdown (dict), metadata (dict)
    """
    _ensure_init()
    conn = _get_connection()
    now = _now_utc()
    conn.execute(
        """
        INSERT OR REPLACE INTO evidence (
            id, scan_id, finding_id, finding_json, code_unit_json,
            snippets_json, call_chain_json, agent_hypotheses_json,
            agent_logs_json, judge_decision_json, cwe_info_json,
            score_breakdown_json, metadata_json, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            evidence_data.get("id"),
            evidence_data.get("scan_id"),
            evidence_data.get("finding_id"),
            json.dumps(evidence_data.get("finding", {}), ensure_ascii=False),
            json.dumps(evidence_data.get("code_unit"), ensure_ascii=False) if evidence_data.get("code_unit") else None,
            json.dumps(evidence_data.get("snippets", []), ensure_ascii=False),
            json.dumps(evidence_data.get("call_chain", []), ensure_ascii=False),
            json.dumps(evidence_data.get("agent_hypotheses", []), ensure_ascii=False),
            json.dumps(evidence_data.get("agent_logs", []), ensure_ascii=False),
            json.dumps(evidence_data.get("judge_decision"), ensure_ascii=False) if evidence_data.get("judge_decision") else None,
            json.dumps(evidence_data.get("cwe_info", {}), ensure_ascii=False),
            json.dumps(evidence_data.get("score_breakdown", {}), ensure_ascii=False),
            json.dumps(evidence_data.get("metadata", {}), ensure_ascii=False),
            now,
            now,
        ),
    )
    conn.commit()


def bulk_create_evidence(evidence_list: list[dict[str, Any]]) -> None:
    """Insert multiple evidence records in a single transaction."""
    _ensure_init()
    conn = _get_connection()
    now = _now_utc()
    rows = [
        (
            e.get("id"),
            e.get("scan_id"),
            e.get("finding_id"),
            json.dumps(e.get("finding", {}), ensure_ascii=False),
            json.dumps(e.get("code_unit"), ensure_ascii=False) if e.get("code_unit") else None,
            json.dumps(e.get("snippets", []), ensure_ascii=False),
            json.dumps(e.get("call_chain", []), ensure_ascii=False),
            json.dumps(e.get("agent_hypotheses", []), ensure_ascii=False),
            json.dumps(e.get("agent_logs", []), ensure_ascii=False),
            json.dumps(e.get("judge_decision"), ensure_ascii=False) if e.get("judge_decision") else None,
            json.dumps(e.get("cwe_info", {}), ensure_ascii=False),
            json.dumps(e.get("score_breakdown", {}), ensure_ascii=False),
            json.dumps(e.get("metadata", {}), ensure_ascii=False),
            now,
            now,
        )
        for e in evidence_list
    ]
    conn.executemany(
        """
        INSERT OR REPLACE INTO evidence (
            id, scan_id, finding_id, finding_json, code_unit_json,
            snippets_json, call_chain_json, agent_hypotheses_json,
            agent_logs_json, judge_decision_json, cwe_info_json,
            score_breakdown_json, metadata_json, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        rows,
    )
    conn.commit()


def get_evidence(scan_id: str) -> list[dict[str, Any]]:
    """Get all evidence bundles for a scan, with JSON fields parsed."""
    _ensure_init()
    conn = _get_connection()
    rows = conn.execute(
        "SELECT * FROM evidence WHERE scan_id = ? ORDER BY created_at",
        (scan_id,),
    ).fetchall()
    result = []
    for r in rows:
        d = dict(r)
        d["finding"] = json.loads(d["finding_json"])
        d["code_unit"] = json.loads(d["code_unit_json"]) if d["code_unit_json"] else None
        d["snippets"] = json.loads(d["snippets_json"])
        d["call_chain"] = json.loads(d["call_chain_json"])
        d["agent_hypotheses"] = json.loads(d["agent_hypotheses_json"])
        d["agent_logs"] = json.loads(d["agent_logs_json"])
        d["judge_decision"] = json.loads(d["judge_decision_json"]) if d["judge_decision_json"] else None
        d["cwe_info"] = json.loads(d["cwe_info_json"])
        d["score_breakdown"] = json.loads(d["score_breakdown_json"])
        d["metadata"] = json.loads(d["metadata_json"])
        # Remove raw JSON columns
        for key in (
            "finding_json", "code_unit_json", "snippets_json",
            "call_chain_json", "agent_hypotheses_json", "agent_logs_json",
            "judge_decision_json", "cwe_info_json", "score_breakdown_json",
            "metadata_json",
        ):
            del d[key]
        result.append(d)
    return result


def delete_evidence_by_scan(scan_id: str) -> int:
    """Delete all evidence for a scan. Returns number of deleted rows."""
    _ensure_init()
    conn = _get_connection()
    cursor = conn.execute(
        "DELETE FROM evidence WHERE scan_id = ?", (scan_id,)
    )
    conn.commit()
    return cursor.rowcount


# ---------------------------------------------------------------------------
# Agent Log CRUD
# ---------------------------------------------------------------------------

def create_agent_log(log_data: dict[str, Any]) -> None:
    """
    Insert a new agent log record.

    Expected keys:
        id, scan_id, agent_name, stage, message,
        input_refs (list), output_refs (list), timestamp, metadata (dict)
    """
    _ensure_init()
    conn = _get_connection()
    now = _now_utc()
    conn.execute(
        """
        INSERT OR REPLACE INTO agent_logs (
            id, scan_id, agent_name, stage, message,
            input_refs_json, output_refs_json, timestamp,
            metadata_json, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            log_data.get("id"),
            log_data.get("scan_id"),
            log_data.get("agent_name"),
            log_data.get("stage"),
            log_data.get("message"),
            json.dumps(log_data.get("input_refs", []), ensure_ascii=False),
            json.dumps(log_data.get("output_refs", []), ensure_ascii=False),
            log_data.get("timestamp", now),
            json.dumps(log_data.get("metadata", {}), ensure_ascii=False),
            now,
            now,
        ),
    )
    conn.commit()


def bulk_create_agent_logs(logs: list[dict[str, Any]]) -> None:
    """Insert multiple agent log records in a single transaction."""
    _ensure_init()
    conn = _get_connection()
    now = _now_utc()
    rows = [
        (
            log.get("id"),
            log.get("scan_id"),
            log.get("agent_name"),
            log.get("stage"),
            log.get("message"),
            json.dumps(log.get("input_refs", []), ensure_ascii=False),
            json.dumps(log.get("output_refs", []), ensure_ascii=False),
            log.get("timestamp", now),
            json.dumps(log.get("metadata", {}), ensure_ascii=False),
            now,
            now,
        )
        for log in logs
    ]
    conn.executemany(
        """
        INSERT OR REPLACE INTO agent_logs (
            id, scan_id, agent_name, stage, message,
            input_refs_json, output_refs_json, timestamp,
            metadata_json, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        rows,
    )
    conn.commit()


def get_agent_logs(scan_id: str) -> list[dict[str, Any]]:
    """Get all agent logs for a scan, with JSON fields parsed."""
    _ensure_init()
    conn = _get_connection()
    rows = conn.execute(
        "SELECT * FROM agent_logs WHERE scan_id = ? ORDER BY timestamp",
        (scan_id,),
    ).fetchall()
    result = []
    for r in rows:
        d = dict(r)
        d["input_refs"] = json.loads(d["input_refs_json"])
        d["output_refs"] = json.loads(d["output_refs_json"])
        d["metadata"] = json.loads(d["metadata_json"])
        del d["input_refs_json"]
        del d["output_refs_json"]
        del d["metadata_json"]
        result.append(d)
    return result


def delete_agent_logs_by_scan(scan_id: str) -> int:
    """Delete all agent logs for a scan. Returns number of deleted rows."""
    _ensure_init()
    conn = _get_connection()
    cursor = conn.execute(
        "DELETE FROM agent_logs WHERE scan_id = ?", (scan_id,)
    )
    conn.commit()
    return cursor.rowcount


# ---------------------------------------------------------------------------
# Report CRUD
# ---------------------------------------------------------------------------

def create_report(report_data: dict[str, Any]) -> None:
    """
    Insert a new report record.

    Expected keys:
        id, scan_id, format, content, file_path, metadata (dict)
    """
    _ensure_init()
    conn = _get_connection()
    now = _now_utc()
    conn.execute(
        """
        INSERT OR REPLACE INTO reports (
            id, scan_id, format, content, file_path,
            metadata_json, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            report_data.get("id"),
            report_data.get("scan_id"),
            report_data.get("format"),
            report_data.get("content"),
            report_data.get("file_path"),
            json.dumps(report_data.get("metadata", {}), ensure_ascii=False),
            now,
            now,
        ),
    )
    conn.commit()


def get_reports(scan_id: str) -> list[dict[str, Any]]:
    """Get all reports for a scan."""
    _ensure_init()
    conn = _get_connection()
    rows = conn.execute(
        "SELECT * FROM reports WHERE scan_id = ? ORDER BY created_at DESC",
        (scan_id,),
    ).fetchall()
    result = []
    for r in rows:
        d = dict(r)
        d["metadata"] = json.loads(d["metadata_json"])
        del d["metadata_json"]
        result.append(d)
    return result


def delete_reports_by_scan(scan_id: str) -> int:
    """Delete all reports for a scan. Returns number of deleted rows."""
    _ensure_init()
    conn = _get_connection()
    cursor = conn.execute(
        "DELETE FROM reports WHERE scan_id = ?", (scan_id,)
    )
    conn.commit()
    return cursor.rowcount


# ---------------------------------------------------------------------------
# Full scan result helpers (for reconstructing AuditResult)
# ---------------------------------------------------------------------------

def save_full_scan_result(
    scan_id: str,
    summary: dict[str, Any],
    findings: list[dict[str, Any]],
    evidence: list[dict[str, Any]],
    agent_logs: list[dict[str, Any]],
    metadata: dict[str, Any] | None = None,
) -> None:
    """
    Save a complete scan result (AuditResult) to the database.

    This is the main entry point for persisting an AuditResult.
    It stores the summary in the scans table and all related records
    in their respective tables.
    """
    _ensure_init()
    conn = _get_connection()

    # Save scan
    now = _now_utc()
    conn.execute(
        """
        INSERT OR REPLACE INTO scans (scan_id, summary_json, metadata_json, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?)
        """,
        (scan_id, json.dumps(summary, ensure_ascii=False),
         json.dumps(metadata or {}, ensure_ascii=False), now, now),
    )

    # Save findings
    if findings:
        finding_rows = []
        for f in findings:
            evidence_dict = f.pop("evidence", {}) if isinstance(f.get("evidence"), dict) else {}
            meta_dict = f.pop("metadata", {}) if isinstance(f.get("metadata"), dict) else {}
            finding_rows.append((
                f.get("id"),
                scan_id,
                f.get("rule_id"),
                f.get("type"),
                f.get("cwe"),
                f.get("severity", "UNKNOWN"),
                f.get("confidence", "low"),
                f.get("file_path"),
                f.get("start_line"),
                f.get("end_line"),
                f.get("message"),
                f.get("engine"),
                json.dumps(evidence_dict, ensure_ascii=False),
                json.dumps(meta_dict, ensure_ascii=False),
                now, now,
            ))
            # Restore popped keys
            f["evidence"] = evidence_dict
            f["metadata"] = meta_dict
        conn.executemany(
            """
            INSERT OR REPLACE INTO findings (
                id, scan_id, rule_id, type, cwe, severity, confidence,
                file_path, start_line, end_line, message, engine,
                evidence_json, metadata_json, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            finding_rows,
        )

    # Save evidence bundles
    if evidence:
        evidence_rows = []
        for e in evidence:
            finding_id = None
            finding_dict = e.get("finding") or {}
            if isinstance(finding_dict, dict):
                finding_id = finding_dict.get("id")
            evidence_rows.append((
                e.get("id"),
                scan_id,
                finding_id,
                json.dumps(finding_dict, ensure_ascii=False),
                json.dumps(e.get("code_unit"), ensure_ascii=False) if e.get("code_unit") else None,
                json.dumps(e.get("snippets", []), ensure_ascii=False),
                json.dumps(e.get("call_chain", []), ensure_ascii=False),
                json.dumps(e.get("agent_hypotheses", []), ensure_ascii=False),
                json.dumps(e.get("agent_logs", []), ensure_ascii=False),
                json.dumps(e.get("judge_decision"), ensure_ascii=False) if e.get("judge_decision") else None,
                json.dumps(e.get("cwe_info", {}), ensure_ascii=False),
                json.dumps(e.get("score_breakdown", {}), ensure_ascii=False),
                json.dumps(e.get("metadata", {}), ensure_ascii=False),
                now, now,
            ))
        conn.executemany(
            """
            INSERT OR REPLACE INTO evidence (
                id, scan_id, finding_id, finding_json, code_unit_json,
                snippets_json, call_chain_json, agent_hypotheses_json,
                agent_logs_json, judge_decision_json, cwe_info_json,
                score_breakdown_json, metadata_json, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            evidence_rows,
        )

    # Save agent logs
    if agent_logs:
        log_rows = []
        for log in agent_logs:
            log_rows.append((
                log.get("id"),
                scan_id,
                log.get("agent_name"),
                log.get("stage"),
                log.get("message"),
                json.dumps(log.get("input_refs", []), ensure_ascii=False),
                json.dumps(log.get("output_refs", []), ensure_ascii=False),
                log.get("timestamp", now),
                json.dumps(log.get("metadata", {}), ensure_ascii=False),
                now, now,
            ))
        conn.executemany(
            """
            INSERT OR REPLACE INTO agent_logs (
                id, scan_id, agent_name, stage, message,
                input_refs_json, output_refs_json, timestamp,
                metadata_json, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            log_rows,
        )

    conn.commit()


def load_full_scan_result(scan_id: str) -> Optional[dict[str, Any]]:
    """
    Load a complete scan result from the database.

    Returns a dict with keys: summary, findings, evidence, agent_logs, metadata.
    Returns None if the scan_id does not exist.
    """
    _ensure_init()
    conn = _get_connection()

    # Load scan
    row = conn.execute(
        "SELECT * FROM scans WHERE scan_id = ?", (scan_id,)
    ).fetchone()
    if row is None:
        return None

    scan = dict(row)
    summary = json.loads(scan["summary_json"])
    metadata = json.loads(scan["metadata_json"])

    # Load findings
    findings = get_findings(scan_id)

    # Load evidence
    evidence = get_evidence(scan_id)

    # Load agent logs
    agent_logs = get_agent_logs(scan_id)

    return {
        "summary": summary,
        "findings": findings,
        "evidence": evidence,
        "agent_logs": agent_logs,
        "metadata": metadata,
    }


# ---------------------------------------------------------------------------
# Project CRUD
# ---------------------------------------------------------------------------

def create_project(
    project_id: str,
    name: str,
    description: str = "",
    repo_url: str = "",
    language: str = "",
) -> dict[str, Any]:
    """Insert a new project record and return it as a dict."""
    _ensure_init()
    conn = _get_connection()
    now = _now_utc()
    conn.execute(
        """
        INSERT INTO projects (id, name, description, repo_url, language, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (project_id, name, description, repo_url, language, now, now),
    )
    conn.commit()
    return get_project(project_id)  # type: ignore[return-value]


def get_project(project_id: str) -> Optional[dict[str, Any]]:
    """Retrieve a project by id. Returns a dict or None."""
    _ensure_init()
    conn = _get_connection()
    row = conn.execute(
        "SELECT * FROM projects WHERE id = ?", (project_id,)
    ).fetchone()
    if row is None:
        return None
    return dict(row)


def get_all_projects(
    search: Optional[str] = None,
    offset: int = 0,
    limit: int = 50,
) -> list[dict[str, Any]]:
    """
    Retrieve all projects, optionally filtered by search term, with pagination.

    Returns projects ordered by created_at descending.
    """
    _ensure_init()
    conn = _get_connection()

    if search:
        like = f"%{search}%"
        rows = conn.execute(
            """
            SELECT * FROM projects
            WHERE name LIKE ? OR description LIKE ?
            ORDER BY created_at DESC
            LIMIT ? OFFSET ?
            """,
            (like, like, limit, offset),
        ).fetchall()
    else:
        rows = conn.execute(
            """
            SELECT * FROM projects
            ORDER BY created_at DESC
            LIMIT ? OFFSET ?
            """,
            (limit, offset),
        ).fetchall()
    return [dict(r) for r in rows]


def count_projects(search: Optional[str] = None) -> int:
    """Count total projects, optionally filtered by search term."""
    _ensure_init()
    conn = _get_connection()
    if search:
        like = f"%{search}%"
        row = conn.execute(
            "SELECT COUNT(*) as cnt FROM projects WHERE name LIKE ? OR description LIKE ?",
            (like, like),
        ).fetchone()
    else:
        row = conn.execute("SELECT COUNT(*) as cnt FROM projects").fetchone()
    return row["cnt"]  # type: ignore[return-value]


def update_project(
    project_id: str,
    name: Optional[str] = None,
    description: Optional[str] = None,
    repo_url: Optional[str] = None,
    language: Optional[str] = None,
) -> bool:
    """Update a project's fields. Returns True if updated."""
    _ensure_init()
    conn = _get_connection()
    now = _now_utc()

    sets: list[str] = ["updated_at = ?"]
    params: list[Any] = [now]

    if name is not None:
        sets.append("name = ?")
        params.append(name)
    if description is not None:
        sets.append("description = ?")
        params.append(description)
    if repo_url is not None:
        sets.append("repo_url = ?")
        params.append(repo_url)
    if language is not None:
        sets.append("language = ?")
        params.append(language)

    params.append(project_id)

    cursor = conn.execute(
        f"UPDATE projects SET {', '.join(sets)} WHERE id = ?",
        params,
    )
    conn.commit()
    return cursor.rowcount > 0


def delete_project(project_id: str) -> bool:
    """
    Delete a project and set project_id to NULL on associated scans.

    Returns True if deleted.
    """
    _ensure_init()
    conn = _get_connection()

    # Dissociate scans from this project (SET NULL via FK)
    conn.execute(
        "UPDATE scans SET project_id = NULL WHERE project_id = ?",
        (project_id,),
    )

    cursor = conn.execute("DELETE FROM projects WHERE id = ?", (project_id,))
    conn.commit()
    return cursor.rowcount > 0


def has_project(project_id: str) -> bool:
    """Check if a project exists."""
    _ensure_init()
    conn = _get_connection()
    row = conn.execute(
        "SELECT 1 FROM projects WHERE id = ?", (project_id,)
    ).fetchone()
    return row is not None


def get_project_scans(project_id: str) -> list[dict[str, Any]]:
    """Retrieve all scans for a project, ordered by created_at descending."""
    _ensure_init()
    conn = _get_connection()
    rows = conn.execute(
        "SELECT * FROM scans WHERE project_id = ? ORDER BY created_at DESC",
        (project_id,),
    ).fetchall()
    return [dict(r) for r in rows]


def get_project_scan_count(project_id: str) -> int:
    """Count scans for a project."""
    _ensure_init()
    conn = _get_connection()
    row = conn.execute(
        "SELECT COUNT(*) as cnt FROM scans WHERE project_id = ?",
        (project_id,),
    ).fetchone()
    return row["cnt"]  # type: ignore[return-value]


def get_project_stats(project_id: str) -> dict[str, Any]:
    """
    Get aggregated statistics for a project.

    Returns:
        total_scans, total_findings, findings_by_severity, latest_scan
    """
    _ensure_init()
    conn = _get_connection()

    # Total scans
    scan_row = conn.execute(
        "SELECT COUNT(*) as cnt FROM scans WHERE project_id = ?",
        (project_id,),
    ).fetchone()
    total_scans = scan_row["cnt"]  # type: ignore[union-attr]

    # Latest scan
    latest_row = conn.execute(
        "SELECT * FROM scans WHERE project_id = ? ORDER BY created_at DESC LIMIT 1",
        (project_id,),
    ).fetchone()
    latest_scan = dict(latest_row) if latest_row else None

    # Findings by severity across all project scans
    severity_rows = conn.execute(
        """
        SELECT f.severity, COUNT(*) as cnt
        FROM findings f
        JOIN scans s ON f.scan_id = s.scan_id
        WHERE s.project_id = ?
        GROUP BY f.severity
        """,
        (project_id,),
    ).fetchall()
    findings_by_severity = {r["severity"]: r["cnt"] for r in severity_rows}

    # Total findings
    total_findings = sum(findings_by_severity.values())

    return {
        "total_scans": total_scans,
        "total_findings": total_findings,
        "findings_by_severity": findings_by_severity,
        "latest_scan": latest_scan,
    }


# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------

def clear_all() -> None:
    """Delete all data from all tables."""
    _ensure_init()
    conn = _get_connection()
    conn.execute("DELETE FROM reports")
    conn.execute("DELETE FROM agent_logs")
    conn.execute("DELETE FROM evidence")
    conn.execute("DELETE FROM findings")
    conn.execute("DELETE FROM scans")
    conn.execute("DELETE FROM projects")
    conn.commit()


# ---------------------------------------------------------------------------
# User CRUD (for JWT authentication)
# ---------------------------------------------------------------------------

def create_user(
    username: str,
    password_hash: str,
    salt: str,
    is_admin: bool = False,
) -> int:
    """Insert a new user. Returns the user id."""
    _ensure_init()
    conn = _get_connection()
    now = _now_utc()
    cursor = conn.execute(
        """
        INSERT INTO users (username, password_hash, salt, is_admin, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (username, password_hash, salt, 1 if is_admin else 0, now, now),
    )
    conn.commit()
    return cursor.lastrowid  # type: ignore[return-value]


def get_user_by_username(username: str) -> Optional[dict[str, Any]]:
    """Retrieve a user by username. Returns a dict or None."""
    _ensure_init()
    conn = _get_connection()
    row = conn.execute(
        "SELECT * FROM users WHERE username = ?", (username,)
    ).fetchone()
    if row is None:
        return None
    d = dict(row)
    d["is_admin"] = bool(d["is_admin"])
    return d


def get_user_by_id(user_id: int) -> Optional[dict[str, Any]]:
    """Retrieve a user by id. Returns a dict or None."""
    _ensure_init()
    conn = _get_connection()
    row = conn.execute(
        "SELECT * FROM users WHERE id = ?", (user_id,)
    ).fetchone()
    if row is None:
        return None
    d = dict(row)
    d["is_admin"] = bool(d["is_admin"])
    return d


def user_exists(username: str) -> bool:
    """Check if a username already exists."""
    _ensure_init()
    conn = _get_connection()
    row = conn.execute(
        "SELECT 1 FROM users WHERE username = ?", (username,)
    ).fetchone()
    return row is not None
