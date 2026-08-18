"""
Pydantic models for CVE Candidate evaluation.

Defines the data structures used throughout the CVE candidacy
assessment pipeline, including check results, duplicate check
results, and the final candidate assessment.
"""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field


class CveCheckResult(BaseModel):
    """Result of a single CVE criterion check."""

    model_config = {"frozen": False}

    name: str
    passed: bool
    description: str
    evidence: list[str] = Field(default_factory=list)
    missing_evidence: list[str] = Field(default_factory=list)
    notes: str = ""


class DuplicateCheckResult(BaseModel):
    """Result of duplicate checking against CVE databases."""

    model_config = {"frozen": False}

    possible_duplicates: list[dict] = Field(default_factory=list)
    checked_sources: list[str] = Field(default_factory=lambda: [
        "NVD",
        "GitHub Advisory Database",
        "MITRE CVE",
        "project issues",
        "project pull requests",
        "release notes",
        "security advisories",
    ])
    duplicate_risk: str = "low"  # low / medium / high
    notes: str = ""


class CveCandidateResult(BaseModel):
    """Complete CVE candidate assessment result."""

    model_config = {"frozen": False}

    cve_candidate: bool = False
    confidence: str = "low"  # high / medium / low
    reason: str = ""
    affected_project: str = ""
    affected_component: str = ""
    affected_versions: str = ""
    affected_file: str = ""
    affected_function: str = ""
    entry_point: str = ""
    security_impact: str = ""
    attack_preconditions: str = ""
    cwe: str = ""
    cvss_vector: str = ""
    cvss_score: float = 0.0
    exploitability_notes: str = ""
    evidence: list[str] = Field(default_factory=list)
    missing_evidence: list[str] = Field(default_factory=list)
    checks: list[CveCheckResult] = []
    duplicate_check: Optional[DuplicateCheckResult] = None
    recommended_next_steps: list[str] = Field(default_factory=list)
    title: str = ""
    cwe_ids: list[str] = Field(default_factory=list)
    security_sensitive_flow: bool = False
    has_reachable_entry: bool = False
    has_fix: bool = False
    has_poc: bool = False
