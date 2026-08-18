"""
API request/response schemas.

Defines Pydantic models for API requests and responses.
"""

from pydantic import BaseModel, Field
from typing import Literal, Optional


class ScanRequest(BaseModel):
    """Request model for /scan endpoint."""
    input_type: Literal["code", "path", "github"] = Field(
        ..., description="Type of input: 'code', 'path', or 'github'"
    )
    code: Optional[str] = None
    repo_path: Optional[str] = None
    repo_url: Optional[str] = None
    language: str = "auto"


class ScanResponse(BaseModel):
    """Response model for /scan endpoint."""
    scan_id: str = Field(..., description="Unique identifier for this scan session")
    summary: dict
    findings: list[dict]
    evidence: list[dict]
    agent_logs: list[dict]
    cve_candidates: list[dict] = Field(default_factory=list, description="CVE candidate assessments")


class HealthResponse(BaseModel):
    """Response model for /health endpoint."""


class CompetitionDemoRequest(BaseModel):
    """Run one auditable competition showcase scenario."""
    scenario: Literal["simple_sql", "path_evolution", "similar_path"] = "path_evolution"
    sensitivity: Literal["public", "internal", "confidential"] = "public"
    mode: Literal["live", "replay"] = "live"
    repair_variant: Literal["auto", "safe", "weak"] = "auto"
    simulate_provider_failure: bool = False


class CompetitionDemoResponse(BaseModel):
    run_id: str
    scenario: str
    mode: str
    finding: dict
    routing_decision: dict
    historical_matches: list[dict]
    patch: dict
    verification: dict
    evolved_case: dict
    case_stats: dict
    events: list[dict]
