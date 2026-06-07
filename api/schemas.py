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
  