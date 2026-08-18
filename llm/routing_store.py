"""SQLite persistence for auditable model-routing decisions."""
from __future__ import annotations

import json
import os
from pathlib import Path
import sqlite3

from llm.routing_models import RoutingDecision

_ROOT = Path(__file__).resolve().parent.parent
_DEFAULT_DB = _ROOT / "data" / "vulnpatch.db"
_SCHEMA = """
CREATE TABLE IF NOT EXISTS routing_decisions (
    decision_id TEXT PRIMARY KEY,
    scan_id TEXT,
    finding_id TEXT,
    decision_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_routing_decisions_scan_id ON routing_decisions(scan_id);
CREATE INDEX IF NOT EXISTS idx_routing_decisions_created_at ON routing_decisions(created_at);
"""


def _db_path() -> Path:
    configured = os.getenv("VULNPATCH_DB_PATH")
    path = Path(configured).expanduser() if configured else _DEFAULT_DB
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(_db_path())
    conn.row_factory = sqlite3.Row
    conn.executescript(_SCHEMA)
    return conn


class RoutingDecisionStore:
    def __init__(self) -> None:
        with _connect():
            pass

    def save(self, decision: RoutingDecision, *, scan_id: str | None = None) -> RoutingDecision:
        raw = decision.model_dump(mode="json")
        with _connect() as conn:
            conn.execute(
                """INSERT INTO routing_decisions(decision_id, scan_id, finding_id, decision_json, created_at)
                   VALUES (?, ?, ?, ?, ?)
                   ON CONFLICT(decision_id) DO UPDATE SET
                     scan_id=excluded.scan_id, finding_id=excluded.finding_id,
                     decision_json=excluded.decision_json, created_at=excluded.created_at""",
                (
                    decision.decision_id,
                    scan_id,
                    decision.context.finding_id,
                    json.dumps(raw, ensure_ascii=False, default=str),
                    str(raw["created_at"]),
                ),
            )
        return decision

    def list(self, *, limit: int = 100, scan_id: str | None = None) -> list[RoutingDecision]:
        sql = "SELECT decision_json FROM routing_decisions"
        params: list[object] = []
        if scan_id:
            sql += " WHERE scan_id=?"
            params.append(scan_id)
        sql += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)
        with _connect() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [RoutingDecision(**json.loads(row["decision_json"])) for row in rows]
