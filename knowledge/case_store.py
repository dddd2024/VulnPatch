"""SQLite-backed store for the self-evolving repair case library.

The repair-case lifecycle owns its two tables instead of extending the legacy
scan database API.  It still defaults to ``data/vulnpatch.db`` so one SQLite
file can be used in production, while ``VULNPATCH_DB_PATH`` isolates demos and
tests.
"""
from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sqlite3
from typing import Any

from knowledge.case_models import CaseEvent, RepairCase

_ROOT = Path(__file__).resolve().parent.parent
_DEFAULT_DB = _ROOT / "data" / "vulnpatch.db"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS repair_cases (
    case_id TEXT PRIMARY KEY,
    cwe TEXT,
    vulnerability_type TEXT NOT NULL DEFAULT 'unknown',
    language TEXT NOT NULL DEFAULT 'unknown',
    framework TEXT NOT NULL DEFAULT 'generic',
    source_finding_id TEXT,
    source_scan_id TEXT,
    outcome TEXT NOT NULL,
    strategy TEXT NOT NULL,
    original_code TEXT NOT NULL DEFAULT '',
    patched_code TEXT NOT NULL DEFAULT '',
    verification_json TEXT,
    trust_score REAL NOT NULL DEFAULT 0.0,
    failure_reason TEXT,
    evidence_refs_json TEXT NOT NULL DEFAULT '[]',
    retrieved_count INTEGER NOT NULL DEFAULT 0,
    successful_reuse_count INTEGER NOT NULL DEFAULT 0,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_repair_cases_cwe ON repair_cases(cwe);
CREATE INDEX IF NOT EXISTS idx_repair_cases_outcome ON repair_cases(outcome);
CREATE INDEX IF NOT EXISTS idx_repair_cases_language ON repair_cases(language);
CREATE TABLE IF NOT EXISTS case_events (
    event_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    scan_id TEXT,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    FOREIGN KEY (case_id) REFERENCES repair_cases(case_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_case_events_case_id ON case_events(case_id);
CREATE INDEX IF NOT EXISTS idx_case_events_created_at ON case_events(created_at);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _db_path() -> Path:
    configured = os.getenv("VULNPATCH_DB_PATH")
    path = Path(configured).expanduser() if configured else _DEFAULT_DB
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(_db_path())
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.executescript(_SCHEMA)
    return conn


def _decode_case(row: sqlite3.Row | None) -> RepairCase | None:
    if row is None:
        return None
    raw = dict(row)
    raw["verification"] = json.loads(raw.pop("verification_json")) if raw.get("verification_json") else None
    raw["evidence_refs"] = json.loads(raw.pop("evidence_refs_json") or "[]")
    raw["metadata"] = json.loads(raw.pop("metadata_json") or "{}")
    return RepairCase(**raw)


class CaseStore:
    """Persistence boundary for repair cases and immutable evolution events."""

    def __init__(self) -> None:
        with _connect():
            pass

    def add_case(self, case: RepairCase) -> RepairCase:
        raw = case.model_dump(mode="json")
        with _connect() as conn:
            conn.execute(
                """
                INSERT INTO repair_cases (
                    case_id, cwe, vulnerability_type, language, framework,
                    source_finding_id, source_scan_id, outcome, strategy,
                    original_code, patched_code, verification_json, trust_score,
                    failure_reason, evidence_refs_json, retrieved_count,
                    successful_reuse_count, metadata_json, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(case_id) DO UPDATE SET
                    cwe=excluded.cwe, vulnerability_type=excluded.vulnerability_type,
                    language=excluded.language, framework=excluded.framework,
                    source_finding_id=excluded.source_finding_id,
                    source_scan_id=excluded.source_scan_id, outcome=excluded.outcome,
                    strategy=excluded.strategy, original_code=excluded.original_code,
                    patched_code=excluded.patched_code,
                    verification_json=excluded.verification_json,
                    trust_score=excluded.trust_score,
                    failure_reason=excluded.failure_reason,
                    evidence_refs_json=excluded.evidence_refs_json,
                    retrieved_count=excluded.retrieved_count,
                    successful_reuse_count=excluded.successful_reuse_count,
                    metadata_json=excluded.metadata_json, updated_at=excluded.updated_at
                """,
                (
                    raw["case_id"], raw.get("cwe"), raw.get("vulnerability_type", "unknown"),
                    raw.get("language", "unknown"), raw.get("framework", "generic"),
                    raw.get("source_finding_id"), raw.get("source_scan_id"), raw["outcome"],
                    raw["strategy"], raw.get("original_code", ""), raw.get("patched_code", ""),
                    json.dumps(raw.get("verification"), ensure_ascii=False, default=str)
                    if raw.get("verification") is not None else None,
                    float(raw.get("trust_score", 0.0)), raw.get("failure_reason"),
                    json.dumps(raw.get("evidence_refs", []), ensure_ascii=False),
                    int(raw.get("retrieved_count", 0)), int(raw.get("successful_reuse_count", 0)),
                    json.dumps(raw.get("metadata", {}), ensure_ascii=False, default=str),
                    str(raw.get("created_at") or _now()), str(raw.get("updated_at") or _now()),
                ),
            )
        return case

    def get_case(self, case_id: str) -> RepairCase | None:
        with _connect() as conn:
            return _decode_case(conn.execute("SELECT * FROM repair_cases WHERE case_id=?", (case_id,)).fetchone())

    def list_cases(self, *, cwe: str | None = None, language: str | None = None,
                   outcome: str | None = None, limit: int = 200) -> list[RepairCase]:
        clauses: list[str] = []
        params: list[Any] = []
        for field, value in (("cwe", cwe), ("language", language), ("outcome", outcome)):
            if value:
                clauses.append(f"{field} = ?")
                params.append(value)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        with _connect() as conn:
            rows = conn.execute(
                f"SELECT * FROM repair_cases {where} ORDER BY created_at DESC LIMIT ?",
                (*params, max(1, min(limit, 1000))),
            ).fetchall()
        return [case for row in rows if (case := _decode_case(row)) is not None]

    def add_event(self, event: CaseEvent) -> CaseEvent:
        raw = event.model_dump(mode="json")
        with _connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO case_events (event_id,case_id,event_type,scan_id,metadata_json,created_at) VALUES (?,?,?,?,?,?)",
                (raw["event_id"], raw["case_id"], raw["event_type"], raw.get("scan_id"),
                 json.dumps(raw.get("metadata", {}), ensure_ascii=False, default=str),
                 str(raw.get("created_at") or _now())),
            )
        return event

    def list_events(self, *, case_id: str | None = None, event_type: str | None = None,
                    limit: int = 200) -> list[CaseEvent]:
        clauses: list[str] = []
        params: list[Any] = []
        if case_id:
            clauses.append("case_id = ?"); params.append(case_id)
        if event_type:
            clauses.append("event_type = ?"); params.append(event_type)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        with _connect() as conn:
            rows = conn.execute(
                f"SELECT * FROM case_events {where} ORDER BY created_at DESC LIMIT ?",
                (*params, max(1, min(limit, 1000))),
            ).fetchall()
        result: list[CaseEvent] = []
        for row in rows:
            raw = dict(row)
            raw["metadata"] = json.loads(raw.pop("metadata_json") or "{}")
            result.append(CaseEvent(**raw))
        return result

    def _increment(self, case_id: str, field: str) -> None:
        if field not in {"retrieved_count", "successful_reuse_count"}:
            raise ValueError("unsupported repair-case counter")
        with _connect() as conn:
            conn.execute(
                f"UPDATE repair_cases SET {field}={field}+1, updated_at=? WHERE case_id=?",
                (_now(), case_id),
            )

    def mark_retrieved(self, case_id: str, *, scan_id: str | None = None,
                       similarity: float | None = None, metadata: dict[str, Any] | None = None) -> None:
        self._increment(case_id, "retrieved_count")
        event_metadata = dict(metadata or {})
        if similarity is not None:
            event_metadata["similarity"] = round(float(similarity), 4)
        self.add_event(CaseEvent(case_id=case_id, event_type="CASE_RETRIEVED",
                                 scan_id=scan_id, metadata=event_metadata))

    def mark_reuse_result(self, case_id: str, *, success: bool, scan_id: str | None = None,
                          metadata: dict[str, Any] | None = None) -> None:
        if success:
            self._increment(case_id, "successful_reuse_count")
        self.add_event(CaseEvent(
            case_id=case_id,
            event_type="CASE_REUSED_SUCCESS" if success else "CASE_REUSED_FAILURE",
            scan_id=scan_id,
            metadata=metadata or {},
        ))

    def reset_demo_cases(self) -> int:
        with _connect() as conn:
            rows = conn.execute("SELECT case_id, metadata_json FROM repair_cases").fetchall()
            ids = []
            for row in rows:
                try:
                    metadata = json.loads(row["metadata_json"] or "{}")
                except json.JSONDecodeError:
                    continue
                if metadata.get("demo") is True:
                    ids.append(row["case_id"])
            if ids:
                conn.executemany("DELETE FROM repair_cases WHERE case_id=?", [(case_id,) for case_id in ids])
        return len(ids)
