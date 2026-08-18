"""Persistent repair-case models used by the self-evolving case library."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal
import uuid

from pydantic import BaseModel, Field


CaseOutcome = Literal["POSITIVE", "NEGATIVE"]
CheckStatus = Literal["pass", "fail", "skipped"]


def _case_id() -> str:
    return f"CASE-{datetime.now(timezone.utc):%Y%m%d}-{uuid.uuid4().hex[:6].upper()}"


def _event_id() -> str:
    return f"event-{uuid.uuid4().hex[:10]}"


class VerificationCheck(BaseModel):
    name: str
    status: CheckStatus
    passed: bool
    details: str = ""
    input: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class VerificationResult(BaseModel):
    verification_id: str = Field(default_factory=lambda: f"verify-{uuid.uuid4().hex[:10]}")
    passed: bool
    checks: list[VerificationCheck] = Field(default_factory=list)
    required_checks: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: dict[str, Any] = Field(default_factory=dict)


class RepairCase(BaseModel):
    case_id: str = Field(default_factory=_case_id)
    cwe: str | None = None
    vulnerability_type: str = "unknown"
    language: str = "unknown"
    framework: str = "generic"
    source_finding_id: str | None = None
    source_scan_id: str | None = None
    outcome: CaseOutcome
    strategy: str
    original_code: str = ""
    patched_code: str = ""
    verification: VerificationResult | None = None
    trust_score: float = Field(default=0.0, ge=0.0, le=1.0)
    failure_reason: str | None = None
    evidence_refs: list[str] = Field(default_factory=list)
    retrieved_count: int = 0
    successful_reuse_count: int = 0
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class CaseEvent(BaseModel):
    event_id: str = Field(default_factory=_event_id)
    case_id: str
    event_type: Literal[
        "CASE_CREATED",
        "CASE_PROMOTED",
        "CASE_RETRIEVED",
        "CASE_REUSED_SUCCESS",
        "CASE_REUSED_FAILURE",
    ]
    scan_id: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class CaseMatch(BaseModel):
    case: RepairCase
    similarity: float = Field(ge=0.0, le=1.0)
    reasons: list[str] = Field(default_factory=list)
