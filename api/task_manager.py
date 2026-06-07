"""
Background task manager for VulnPatch scan pipeline.

Provides a TaskManager class that runs scans in background threads,
tracks task state, progress, and persists results to SQLite so they
survive server restarts.

Design:
- Uses threading.Thread (no asyncio, no Celery, no Redis)
- Task states: PENDING -> RUNNING -> COMPLETED / FAILED / CANCELLED
- Cancellation via threading.Event checked at pipeline stage boundaries
- Progress tracking (0-100%) updated by the scan worker
- Thread-safe status updates via threading.Lock
- Auto-cleanup of old completed/failed tasks
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
import time
import uuid
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Optional

from api import database as db

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Task state enum
# ---------------------------------------------------------------------------

class TaskState(str, Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


# ---------------------------------------------------------------------------
# Task record
# ---------------------------------------------------------------------------

class TaskInfo:
    """
    In-memory representation of a background task.

    Thread-safe: all mutable fields are protected by the task's own lock.
    """

    def __init__(
        self,
        task_id: str,
        request_data: dict[str, Any],
        cancel_event: threading.Event,
    ) -> None:
        self.task_id = task_id
        self.request_data = request_data
        self.cancel_event = cancel_event

        self.state: TaskState = TaskState.PENDING
        self.progress: int = 0
        self.message: str = ""
        self.error: str | None = None
        self.scan_id: str | None = None
        self.result: dict[str, Any] | None = None
        self.created_at: str = datetime.now(timezone.utc).isoformat()
        self.started_at: str | None = None
        self.completed_at: str | None = None
        self.thread: threading.Thread | None = None

        self._lock = threading.Lock()

    # -- thread-safe property helpers --

    def set_state(self, state: TaskState) -> None:
        with self._lock:
            self.state = state

    def get_state(self) -> TaskState:
        with self._lock:
            return self.state

    def set_progress(self, progress: int, message: str = "") -> None:
        with self._lock:
            self.progress = max(0, min(100, progress))
            if message:
                self.message = message

    def get_progress(self) -> tuple[int, str]:
        with self._lock:
            return self.progress, self.message

    def set_result(self, scan_id: str, result: dict[str, Any]) -> None:
        with self._lock:
            self.scan_id = scan_id
            self.result = result
            self.state = TaskState.COMPLETED
            self.completed_at = datetime.now(timezone.utc).isoformat()

    def set_error(self, error: str) -> None:
        with self._lock:
            self.error = error
            self.state = TaskState.FAILED
            self.completed_at = datetime.now(timezone.utc).isoformat()

    def set_cancelled(self) -> None:
        with self._lock:
            self.state = TaskState.CANCELLED
            self.completed_at = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> dict[str, Any]:
        with self._lock:
            d: dict[str, Any] = {
                "task_id": self.task_id,
                "state": self.state.value,
                "progress": self.progress,
                "message": self.message,
                "created_at": self.created_at,
                "started_at": self.started_at,
                "completed_at": self.completed_at,
                "scan_id": self.scan_id,
            }
            if self.error:
                d["error"] = self.error
            return d


# ---------------------------------------------------------------------------
# Database helpers for task persistence
# ---------------------------------------------------------------------------

_TASKS_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS tasks (
    task_id         TEXT PRIMARY KEY,
    request_json    TEXT NOT NULL DEFAULT '{}',
    state           TEXT NOT NULL DEFAULT 'PENDING',
    progress        INTEGER NOT NULL DEFAULT 0,
    message         TEXT NOT NULL DEFAULT '',
    error           TEXT,
    scan_id         TEXT,
    result_json     TEXT,
    created_at      TEXT NOT NULL,
    started_at      TEXT,
    completed_at    TEXT
);
CREATE INDEX IF NOT EXISTS idx_tasks_state ON tasks(state);
CREATE INDEX IF NOT EXISTS idx_tasks_created ON tasks(created_at);
"""


def _ensure_tasks_table() -> None:
    """Create the tasks table if it does not exist."""
    conn = db._get_connection()
    conn.executescript(_TASKS_TABLE_SQL)
    conn.commit()


def _persist_task(task: TaskInfo) -> None:
    """Persist a task record to SQLite (upsert)."""
    try:
        _ensure_tasks_table()
        conn = db._get_connection()
        with task._lock:
            result_json = json.dumps(task.result, ensure_ascii=False) if task.result else None
            conn.execute(
                """
                INSERT OR REPLACE INTO tasks
                    (task_id, request_json, state, progress, message, error,
                     scan_id, result_json, created_at, started_at, completed_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    task.task_id,
                    json.dumps(task.request_data, ensure_ascii=False),
                    task.state.value,
                    task.progress,
                    task.message,
                    task.error,
                    task.scan_id,
                    result_json,
                    task.created_at,
                    task.started_at,
                    task.completed_at,
                ),
            )
            conn.commit()
    except Exception as exc:
        logger.error("Failed to persist task %s: %s", task.task_id, exc)


def _load_task_from_db(task_id: str) -> Optional[dict[str, Any]]:
    """Load a task record from the database."""
    _ensure_tasks_table()
    conn = db._get_connection()
    row = conn.execute(
        "SELECT * FROM tasks WHERE task_id = ?", (task_id,)
    ).fetchone()
    if row is None:
        return None
    d = dict(row)
    d["request_data"] = json.loads(d.pop("request_json"))
    if d.get("result_json"):
        d["result"] = json.loads(d.pop("result_json"))
    else:
        d.pop("result_json", None)
    return d


def _load_all_tasks_from_db() -> list[dict[str, Any]]:
    """Load all task records from the database, newest first."""
    _ensure_tasks_table()
    conn = db._get_connection()
    rows = conn.execute(
        "SELECT * FROM tasks ORDER BY created_at DESC"
    ).fetchall()
    result = []
    for row in rows:
        d = dict(row)
        d["request_data"] = json.loads(d.pop("request_json"))
        if d.get("result_json"):
            d["result"] = json.loads(d.pop("result_json"))
        else:
            d.pop("result_json", None)
        result.append(d)
    return result


def _delete_task_from_db(task_id: str) -> bool:
    """Delete a task record from the database."""
    _ensure_tasks_table()
    conn = db._get_connection()
    cursor = conn.execute("DELETE FROM tasks WHERE task_id = ?", (task_id,))
    conn.commit()
    return cursor.rowcount > 0


def _cleanup_old_tasks(max_age_hours: int = 24) -> int:
    """
    Delete completed/failed/cancelled tasks older than max_age_hours.

    Returns the number of deleted tasks.
    """
    _ensure_tasks_table()
    conn = db._get_connection()
    cutoff = datetime.now(timezone.utc).isoformat()
    # SQLite doesn't have great datetime math, so we use a simple approach:
    # delete tasks whose completed_at is not NULL and state is terminal.
    cursor = conn.execute(
        """
        DELETE FROM tasks
        WHERE state IN ('COMPLETED', 'FAILED', 'CANCELLED')
          AND completed_at IS NOT NULL
          AND completed_at < datetime(?, ? || ' hours')
        """,
        (cutoff, -max_age_hours),
    )
    conn.commit()
    return cursor.rowcount


# ---------------------------------------------------------------------------
# TaskManager
# ---------------------------------------------------------------------------

class TaskManager:
    """
    Manages background scan tasks using threading.

    Responsibilities:
    - Create and track background scan tasks
    - Persist task state to SQLite
    - Support task cancellation
    - Track progress (0-100%)
    - Auto-cleanup of old tasks
    - Thread-safe status queries
    """

    def __init__(
        self,
        scan_executor: Callable[[dict[str, Any], threading.Event, Callable[[int, str], None]], tuple[str, dict[str, Any]]],
        max_concurrent: int = 4,
        cleanup_interval: int = 3600,
        max_task_age_hours: int = 24,
    ) -> None:
        """
        Initialize the TaskManager.

        Args:
            scan_executor: A callable that performs the actual scan.
                Signature: (request_data, cancel_event, progress_callback) -> (scan_id, result_dict)
            max_concurrent: Maximum number of concurrent scan threads.
            cleanup_interval: Seconds between auto-cleanup runs.
            max_task_age_hours: Age threshold for auto-cleanup of terminal tasks.
        """
        self._scan_executor = scan_executor
        self._max_concurrent = max_concurrent
        self._cleanup_interval = cleanup_interval
        self._max_task_age_hours = max_task_age_hours

        # Active tasks (in-memory, keyed by task_id)
        self._tasks: dict[str, TaskInfo] = {}
        self._lock = threading.Lock()

        # Semaphore to limit concurrency
        self._semaphore = threading.Semaphore(max_concurrent)

        # Ensure DB table exists
        _ensure_tasks_table()

        # Start cleanup thread
        self._cleanup_stop = threading.Event()
        self._cleanup_thread = threading.Thread(
            target=self._cleanup_loop,
            daemon=True,
            name="task-cleanup",
        )
        self._cleanup_thread.start()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def submit_task(self, request_data: dict[str, Any]) -> TaskInfo:
        """
        Submit a new scan task for background execution.

        Args:
            request_data: The scan request parameters (input_type, code, etc.)

        Returns:
            TaskInfo for the newly created task (state=PENDING).

        Raises:
            RuntimeError: If the task queue is full.
        """
        task_id = uuid.uuid4().hex[:12]
        cancel_event = threading.Event()

        task = TaskInfo(
            task_id=task_id,
            request_data=request_data,
            cancel_event=cancel_event,
        )

        with self._lock:
            self._tasks[task_id] = task

        # Persist initial state
        _persist_task(task)

        # Start background thread
        thread = threading.Thread(
            target=self._run_task,
            args=(task,),
            daemon=True,
            name=f"scan-task-{task_id}",
        )
        task.thread = thread
        thread.start()

        logger.info("Submitted task %s (input_type=%s)", task_id, request_data.get("input_type"))
        return task

    def get_task(self, task_id: str) -> Optional[dict[str, Any]]:
        """
        Get task status and result.

        Checks in-memory first, then falls back to database for
        tasks from previous server restarts.

        Args:
            task_id: The task identifier.

        Returns:
            Task dict with state, progress, result, etc., or None if not found.
        """
        with self._lock:
            if task_id in self._tasks:
                return self._tasks[task_id].to_dict()

        # Fall back to database
        return _load_task_from_db(task_id)

    def list_tasks(self) -> list[dict[str, Any]]:
        """
        List all tasks, newest first.

        Merges in-memory active tasks with persisted tasks from the database.

        Returns:
            List of task dicts.
        """
        with self._lock:
            active = {
                tid: task.to_dict()
                for tid, task in self._tasks.items()
            }

        # Load persisted tasks
        persisted = _load_all_tasks_from_db()

        # Merge: use in-memory version for active tasks (more up-to-date)
        persisted_map = {t["task_id"]: t for t in persisted}
        persisted_map.update(active)

        # Sort by created_at descending
        merged = sorted(
            persisted_map.values(),
            key=lambda t: t.get("created_at", ""),
            reverse=True,
        )
        return merged

    def cancel_task(self, task_id: str) -> bool:
        """
        Request cancellation of a running task.

        Sets the cancel event so the scan worker can detect it at the
        next stage boundary. The task state will transition to CANCELLED.

        Args:
            task_id: The task identifier.

        Returns:
            True if the task was found and cancellation was requested.
        """
        with self._lock:
            task = self._tasks.get(task_id)

        if task is None:
            # Check DB for persisted task
            db_task = _load_task_from_db(task_id)
            if db_task and db_task.get("state") in (
                TaskState.PENDING.value, TaskState.RUNNING.value,
            ):
                # Can't cancel a persisted task that has no active thread
                # Mark it as cancelled in DB
                _ensure_tasks_table()
                conn = db._get_connection()
                conn.execute(
                    "UPDATE tasks SET state = 'CANCELLED', completed_at = ? WHERE task_id = ?",
                    (datetime.now(timezone.utc).isoformat(), task_id),
                )
                conn.commit()
                return True
            return False

        state = task.get_state()
        if state in (TaskState.PENDING, TaskState.RUNNING):
            task.cancel_event.set()
            logger.info("Cancellation requested for task %s", task_id)
            return True

        return False

    def shutdown(self) -> None:
        """
        Gracefully shut down the task manager.

        Stops the cleanup thread and cancels all running tasks.
        """
        logger.info("Shutting down TaskManager")

        # Stop cleanup thread
        self._cleanup_stop.set()

        # Cancel all active tasks
        with self._lock:
            for task in self._tasks.values():
                task.cancel_event.set()

        # Wait for cleanup thread
        self._cleanup_thread.join(timeout=5)

        logger.info("TaskManager shutdown complete")

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _run_task(self, task: TaskInfo) -> None:
        """
        Worker that executes a scan task in a background thread.

        Acquires the concurrency semaphore, runs the scan executor,
        and persists the result.
        """
        # Acquire semaphore (limits concurrency)
        acquired = self._semaphore.acquire(timeout=0)
        if not acquired:
            task.set_error("Task queue is full. Please try again later.")
            _persist_task(task)
            return

        try:
            # Transition to RUNNING
            task.set_state(TaskState.RUNNING)
            task.started_at = datetime.now(timezone.utc).isoformat()
            _persist_task(task)

            # Check if already cancelled before starting
            if task.cancel_event.is_set():
                task.set_cancelled()
                _persist_task(task)
                return

            # Define progress callback
            def progress_cb(progress: int, message: str = "") -> None:
                task.set_progress(progress, message)
                # Periodically persist progress (not every call to avoid DB thrashing)
                if progress % 10 == 0 or progress == 100:
                    _persist_task(task)

            # Execute the scan
            scan_id, result_dict = self._scan_executor(
                task.request_data,
                task.cancel_event,
                progress_cb,
            )

            # Check if cancelled during execution
            if task.cancel_event.is_set():
                task.set_cancelled()
                _persist_task(task)
                return

            # Store result
            task.set_result(scan_id, result_dict)
            _persist_task(task)

            logger.info("Task %s completed (scan_id=%s)", task.task_id, scan_id)

        except Exception as exc:
            logger.error("Task %s failed: %s", task.task_id, exc, exc_info=True)
            if task.cancel_event.is_set():
                task.set_cancelled()
            else:
                task.set_error(str(exc))
            _persist_task(task)

        finally:
            self._semaphore.release()

    def _cleanup_loop(self) -> None:
        """Periodically clean up old terminal tasks."""
        while not self._cleanup_stop.wait(timeout=self._cleanup_interval):
            try:
                count = _cleanup_old_tasks(self._max_task_age_hours)
                if count > 0:
                    logger.info("Cleaned up %d old tasks", count)

                # Also clean up in-memory tasks that are terminal
                with self._lock:
                    to_remove = [
                        tid for tid, task in self._tasks.items()
                        if task.get_state() in (
                            TaskState.COMPLETED, TaskState.FAILED, TaskState.CANCELLED,
                        )
                    ]
                    for tid in to_remove:
                        del self._tasks[tid]
                if to_remove:
                    logger.debug("Removed %d terminal tasks from memory", len(to_remove))

            except Exception as exc:
                logger.error("Task cleanup failed: %s", exc)


# ---------------------------------------------------------------------------
# Default scan executor (bridges TaskManager -> AuditOrchestrator)
# ---------------------------------------------------------------------------

def default_scan_executor(
    request_data: dict[str, Any],
    cancel_event: threading.Event,
    progress_callback: Callable[[int, str], None],
) -> tuple[str, dict[str, Any]]:
    """
    Default scan executor that runs the orchestrator.scan() in a thread.

    This is the bridge between the TaskManager and the existing
    AuditOrchestrator pipeline.

    Args:
        request_data: Dict with keys: input_type, code, repo_path, repo_url, language
        cancel_event: Threading event to check for cancellation
        progress_callback: Callback to report progress (0-100)

    Returns:
        Tuple of (scan_id, result_dict)
    """
    from audit_core.orchestrator import AuditOrchestrator
    from api.state import audit_state

    # Lazily create orchestrator (each thread gets its own)
    import os as _os

    orchestrator = AuditOrchestrator(
        llm_config={
            "provider": "openai",
            "model": _os.getenv("OPENAI_MODEL"),
            "base_url": _os.getenv("OPENAI_BASE_URL"),
        },
    )

    input_type = request_data.get("input_type")
    code = request_data.get("code")
    repo_path = request_data.get("repo_path")
    repo_url = request_data.get("repo_url")
    language = request_data.get("language")
    if language == "auto":
        language = None

    # Stage 1: Validate (0-10%)
    progress_callback(5, "Validating input...")
    if input_type not in ("code", "path", "github"):
        raise ValueError(f"Invalid input_type: {input_type}")

    if cancel_event.is_set():
        raise InterruptedError("Task cancelled")

    # Stage 2: Load code units (10-30%)
    progress_callback(15, "Loading code units...")

    if cancel_event.is_set():
        raise InterruptedError("Task cancelled")

    # Stage 3: Run scan (30-80%)
    progress_callback(30, "Running audit pipeline...")
    result = orchestrator.scan(
        input_type=input_type,
        code=code,
        repo_path=repo_path,
        repo_url=repo_url,
        language=language,
    )

    # Evaluate CVE candidates
    try:
        from cve_candidate.evaluator import CveCandidateEvaluator
        cve_evaluator = CveCandidateEvaluator()
        cve_results = cve_evaluator.evaluate_batch(result.findings)
        result.cve_candidates = [r.model_dump(mode="json") for r in cve_results]
    except Exception:
        pass  # CVE evaluation is optional, don't fail the scan

    progress_callback(80, "Scan complete, storing results...")

    if cancel_event.is_set():
        raise InterruptedError("Task cancelled")

    # Stage 4: Persist (80-95%)
    scan_id = audit_state.create_session(result)
    progress_callback(95, "Results stored")

    # Stage 5: Build response (95-100%)
    response_data = {
        "scan_id": scan_id,
        "summary": result.summary.model_dump(mode="json"),
        "findings": [f.model_dump(mode="json") for f in result.findings],
        "evidence": [e.model_dump(mode="json") for e in result.evidence],
        "agent_logs": [l.model_dump(mode="json") for l in result.agent_logs],
        "cve_candidates": [c.model_dump(mode="json") for c in getattr(result, 'cve_candidates', [])],
    }
    progress_callback(100, "Done")

    return scan_id, response_data


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_task_manager: TaskManager | None = None
_task_manager_lock = threading.Lock()


def get_task_manager() -> TaskManager:
    """
    Get or create the global TaskManager singleton.

    Thread-safe initialization.
    """
    global _task_manager
    if _task_manager is None:
        with _task_manager_lock:
            if _task_manager is None:
                _task_manager = TaskManager(
                    scan_executor=default_scan_executor,
                    max_concurrent=4,
                    cleanup_interval=3600,
                    max_task_age_hours=24,
                )
    return _task_manager
