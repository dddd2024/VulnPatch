"""Typed models for autonomous multi-model routing.

The routing layer deliberately emits a complete, serialisable decision record.
The frontend and evidence chain consume this record directly, so model selection
is inspectable rather than hidden in ad-hoc ``if`` statements.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal
import uuid

from pydantic import BaseModel, Field


HealthState = Literal["healthy", "degraded", "unavailable"]
Sensitivity = Literal["public", "internal", "confidential"]
Complexity = Literal["low", "medium", "high"]


def _id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:10]}"


class RoutingContext(BaseModel):
    """Security-task features used by the model router."""

    finding_id: str | None = None
    cwe: str | None = None
    vulnerability_type: str = "unknown"
    language: str = "unknown"
    complexity: Complexity = "medium"
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    sensitivity: Sensitivity = "public"
    file_count: int = Field(default=1, ge=1)
    cross_file: bool = False
    required_capabilities: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class ModelProfile(BaseModel):
    provider: str
    model: str | None = None
    local: bool = False
    enabled: bool = True
    capability: float = Field(default=0.5, ge=0.0, le=1.0)
    cost: float = Field(default=0.5, ge=0.0, le=1.0)
    latency: float = Field(default=0.5, ge=0.0, le=1.0)
    capabilities: list[str] = Field(default_factory=list)


class RoutingCandidate(BaseModel):
    provider: str
    model: str | None = None
    local: bool = False
    available: bool = True
    allowed: bool = True
    health: HealthState = "healthy"
    score: float = Field(default=0.0, ge=0.0, le=1.0)
    reasons: list[str] = Field(default_factory=list)


class RoutingDecision(BaseModel):
    decision_id: str = Field(default_factory=lambda: _id("route"))
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    context: RoutingContext
    selected_provider: str
    selected_model: str | None = None
    candidates: list[RoutingCandidate] = Field(default_factory=list)
    reason_codes: list[str] = Field(default_factory=list)
    fallback_chain: list[str] = Field(default_factory=list)
    execution_path: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
