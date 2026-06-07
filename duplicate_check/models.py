"""
Data models for duplicate checking.
"""

from pydantic import BaseModel, Field


class DuplicateRecord(BaseModel):
    """A potential duplicate vulnerability record."""
    source: str = Field(..., description="Source where the duplicate was found")
    id: str = Field(default="", description="ID of the existing record (CVE, GHSA, etc.)")
    title: str = Field(default="", description="Title of the existing record")
    url: str = Field(default="", description="URL of the existing record")
    similarity: str = Field(default="unknown", description="Similarity: high/medium/low/unknown")
    notes: str = Field(default="", description="Notes about the similarity")
    model_config = {"frozen": False}


class DuplicateCheckResult(BaseModel):
    """Result of duplicate checking for a vulnerability."""
    possible_duplicates: list[DuplicateRecord] = Field(default_factory=list)
    checked_sources: list[str] = Field(default_factory=lambda: [
        "NVD",
        "GitHub Advisory Database",
        "MITRE CVE",
        "project issues",
        "project pull requests",
        "release notes",
        "security advisories",
    ])
    duplicate_risk: str = Field(default="low", description="low/medium/high")
    notes: str = Field(default="")
    search_keywords: list[str] = Field(default_factory=list)
    model_config = {"frozen": False}
