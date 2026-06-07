"""
Persistent audit state with session management.

Stores scan_id -> AuditResult mappings in a SQLite database so that
scan data survives across server restarts.  Also maintains a "latest"
pointer for backward-compatible routes that don't specify a scan_id.

The public API is identical to the previous in-memory implementation,
ensuring full backward compatibility with all existing consumers
(scan routes, report routes, etc.).
"""

from __future__ import annotations

import json
import logging
import threading
import uuid
from typing import Optional

from audit_core.models import (
    AgentLog,
    AuditResult,
    AuditSummary,
    EvidenceBundle,
    RawFinding,
)

from api import database as db

logger = logging.getLogger(__name__)


class AuditState:
    """
    Thread-safe persistent store for audit results with session management.

    All data is persisted to a SQLite database.  The public interface
    (create_session, get_latest, get_by_id, etc.) is unchanged from the
    previous in-memory version.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        # In-memory cache for the latest scan_id (avoids a DB query on
        # every has_result / get_latest call).
        self._latest_scan_id: str | None = None

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _ensure_db(self) -> None:
        """Make sure the database is initialised."""
        db.init_db()

    @staticmethod
    def _result_to_db(
        result: AuditResult, scan_id: str,
    ) -> None:
        """Serialise an AuditResult into the database."""
        summary_dict = result.summary.model_dump(mode="json")
        findings_dicts = [f.model_dump(mode="json") for f in result.findings]
        evidence_dicts = [e.model_dump(mode="json") for e in result.evidence]
        logs_dicts = [l.model_dump(mode="json") for l in result.agent_logs]

        db.save_full_scan_result(
            scan_id=scan_id,
            summary=summary_dict,
            findings=findings_dicts,
            evidence=evidence_dicts,
            agent_logs=logs_dicts,
            metadata=result.metadata,
        )

    @staticmethod
    def _result_from_db(data: dict) -> AuditResult:
        """Reconstruct an AuditResult from a database record dict."""
        summary = AuditSummary(**data["summary"])
        findings = [RawFinding(**f) for f in data.get("findings", [])]
        evidence = [EvidenceBundle(**e) for e in data.get("evidence", [])]
        agent_logs = [AgentLog(**l) for l in data.get("agent_logs", [])]
        metadata = data.get("metadata", {})
        return AuditResult(
            summary=summary,
            findings=findings,
            evidence=evidence,
            agent_logs=agent_logs,
            metadata=metadata,
        )

    # ------------------------------------------------------------------
    # Public API  (identical to the previous in-memory version)
    # ------------------------------------------------------------------

    @property
    def has_result(self) -> bool:
        """Check if any scan result exists (latest)."""
        with self._lock:
            if self._latest_scan_id is not None:
                return True
            # Fall back to DB in case cache is stale (e.g. after restart)
            self._ensure_db()
            latest = db.get_latest_scan()
            if latest is not None:
                self._latest_scan_id = latest["scan_id"]
                return True
            return False

    def create_session(self, result: AuditResult) -> str:
        """
        Create a new session for the given AuditResult.

        Args:
            result: The audit result to store.

        Returns:
            The generated scan_id (UUID, first 12 chars).
        """
        scan_id = uuid.uuid4().hex[:12]
        with self._lock:
            self._ensure_db()
            self._result_to_db(result, scan_id)
            self._latest_scan_id = scan_id
        return scan_id

    def set_latest(self, result: AuditResult, scan_id: str) -> None:
        """
        Set the latest result and associate it with a scan_id.

        This is used internally by create_session; exposed for testing.

        Args:
            result: The audit result.
            scan_id: The scan session ID.
        """
        with self._lock:
            self._ensure_db()
            self._result_to_db(result, scan_id)
            self._latest_scan_id = scan_id

    def get_latest(self) -> AuditResult:
        """
        Get the most recent audit result.

        Returns:
            The latest AuditResult, or an empty result if none exists.
        """
        with self._lock:
            self._ensure_db()
            # Use cached latest_scan_id if available
            scan_id = self._latest_scan_id
            if scan_id is None:
                latest = db.get_latest_scan()
                if latest is None:
                    return AuditResult(summary=AuditSummary())
                scan_id = latest["scan_id"]
                self._latest_scan_id = scan_id

            data = db.load_full_scan_result(scan_id)
            if data is None:
                return AuditResult(summary=AuditSummary())
            return self._result_from_db(data)

    def get_by_id(self, scan_id: str) -> Optional[AuditResult]:
        """
        Get an audit result by scan_id.

        Args:
            scan_id: The scan session ID.

        Returns:
            The AuditResult if found, otherwise None.
        """
        with self._lock:
            self._ensure_db()
            data = db.load_full_scan_result(scan_id)
            if data is None:
                return None
            return self._result_from_db(data)

    def has_scan(self, scan_id: str) -> bool:
        """
        Check if a scan_id exists.

        Args:
            scan_id: The scan session ID.

        Returns:
            True if the scan_id exists.
        """
        with self._lock:
            self._ensure_db()
            return db.has_scan(scan_id)

    def clear(self) -> None:
        """Clear all stored results and sessions."""
        with self._lock:
            self._ensure_db()
            db.clear_all()
            self._latest_scan_id = None

    def get_scan_ids(self) -> list[str]:
        """
        Get all stored scan_ids.

        Returns:
            List of scan_id strings.
        """
        with self._lock:
            self._ensure_db()
            return db.get_scan_ids()


# Module-level singleton
audit_state = AuditState()
