"""
Data models for supply chain security analysis.

Defines Pydantic models for dependencies, vulnerabilities, SBOM,
supply chain findings, and attack indicators.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field


def _gen_id() -> str:
    return str(uuid.uuid4())[:8]


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class Ecosystem(str, Enum):
    """Package ecosystem / language."""
    PYTHON = "python"
    JAVASCRIPT = "javascript"
    TYPESCRIPT = "typescript"
    JAVA = "java"
    DOTNET = "dotnet"
    GO = "go"
    RUST = "rust"
    PHP = "php"
    RUBY = "ruby"
    C = "c"
    CPP = "cpp"
    UNKNOWN = "unknown"


class DependencyScope(str, Enum):
    """Dependency installation scope."""
    PRODUCTION = "production"
    DEVELOPMENT = "development"
    OPTIONAL = "optional"
    TEST = "test"
    PEER = "peer"
    BUNDLED = "bundled"
    UNKNOWN = "unknown"


class SeverityLevel(str, Enum):
    """Vulnerability severity."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    UNKNOWN = "unknown"


class AttackType(str, Enum):
    """Types of supply chain attacks."""
    TYPOSQUATTING = "typosquatting"
    DEPENDENCY_CONFUSION = "dependency_confusion"
    MALICIOUS_PACKAGE = "malicious_package"
    COMPROMISED_MAINTAINER = "compromised_maintainer"
    STAR_JACKING = "star_jacking"
    BRAND_JACKING = "brand_jacking"
    PUBLISHED_AFTER_CLONE = "published_after_clone"
    SUSPICIOUS_VERSION = "suspicious_version"
    SUSPICIOUS_METADATA = "suspicious_metadata"
    UNKNOWN = "unknown"


class LicenseRisk(str, Enum):
    """License risk level."""
    PERMISSIVE = "permissive"
    WEAK_COPYLEFT = "weak_copyleft"
    STRONG_COPYLEFT = "strong_copyleft"
    PROPRIETARY = "proprietary"
    UNKNOWN = "unknown"


# ---------------------------------------------------------------------------
# Dependency Models
# ---------------------------------------------------------------------------

class Dependency(BaseModel):
    """A single dependency (package / library)."""
    model_config = ConfigDict(frozen=False)

    id: str = Field(default_factory=_gen_id)
    name: str = Field(..., description="Package name (e.g. 'requests', 'lodash')")
    version: Optional[str] = Field(default=None, description="Version constraint or pinned version")
    resolved_version: Optional[str] = Field(default=None, description="Resolved / installed version")
    ecosystem: Ecosystem = Field(default=Ecosystem.UNKNOWN)
    scope: DependencyScope = Field(default=DependencyScope.UNKNOWN)
    is_direct: bool = Field(default=True, description="Direct dependency vs transitive")
    is_dev: bool = Field(default=False, description="Dev-only dependency")
    source_file: str = Field(default="", description="Dependency file path")
    line_number: int = Field(default=0, description="Line number in dependency file")
    aliases: List[str] = Field(default_factory=list, description="Alternative package names")
    license_name: Optional[str] = Field(default=None, description="SPDX license identifier")
    license_risk: LicenseRisk = Field(default=LicenseRisk.UNKNOWN)
    description: Optional[str] = Field(default=None)
    homepage: Optional[str] = Field(default=None)
    repository: Optional[str] = Field(default=None)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class DependencyFile(BaseModel):
    """A parsed dependency / lock file."""
    model_config = ConfigDict(frozen=False)

    id: str = Field(default_factory=_gen_id)
    path: str = Field(..., description="File path relative to project root")
    ecosystem: Ecosystem = Field(default=Ecosystem.UNKNOWN)
    file_type: str = Field(default="", description="e.g. 'requirements.txt', 'package.json'")
    is_lockfile: bool = Field(default=False, description="Whether this is a lockfile (exact versions)")
    dependencies: List[Dependency] = Field(default_factory=list)
    parse_errors: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Vulnerability Models
# ---------------------------------------------------------------------------

class VulnerabilityInfo(BaseModel):
    """Information about a known vulnerability."""
    model_config = ConfigDict(frozen=False)

    cve_id: Optional[str] = Field(default=None, description="CVE identifier (e.g. CVE-2023-44487)")
    vuln_id: Optional[str] = Field(default=None, description="Alternative vulnerability ID (GHSA, etc.)")
    title: str = Field(default="")
    description: str = Field(default="")
    severity: SeverityLevel = Field(default=SeverityLevel.UNKNOWN)
    cvss_score: Optional[float] = Field(default=None)
    cvss_vector: Optional[str] = Field(default=None)
    cwe_ids: List[str] = Field(default_factory=list)
    affected_versions: Optional[str] = Field(default=None, description="Version range string")
    patched_versions: Optional[str] = Field(default=None, description="Version range that fixes the vuln")
    references: List[str] = Field(default_factory=list)
    published_date: Optional[str] = Field(default=None)
    source: str = Field(default="", description="Data source (NVD, OSV, GitHub Advisory, etc.)")
    metadata: Dict[str, Any] = Field(default_factory=dict)


class CVEMatch(BaseModel):
    """A match between a dependency and a known vulnerability."""
    model_config = ConfigDict(frozen=False)

    id: str = Field(default_factory=_gen_id)
    dependency: Dependency = Field(...)
    vulnerability: VulnerabilityInfo = Field(...)
    is_affected: bool = Field(default=True, description="Whether the resolved version is affected")
    confidence: str = Field(default="medium", description="Match confidence: high, medium, low")
    match_reason: str = Field(default="", description="Explanation of why this matches")
    remediation: str = Field(default="", description="Suggested fix (e.g. 'upgrade to >= 2.31.0')")


# ---------------------------------------------------------------------------
# SBOM Models
# ---------------------------------------------------------------------------

class SBOMComponent(BaseModel):
    """A single component in the SBOM."""
    model_config = ConfigDict(frozen=False)

    type: str = Field(default="library", description="Component type (library, framework, etc.)")
    name: str = Field(...)
    version: str = Field(default="")
    purl: Optional[str] = Field(default=None, description="Package URL (purl)")
    ecosystem: Ecosystem = Field(default=Ecosystem.UNKNOWN)
    scope: DependencyScope = Field(default=DependencyScope.PRODUCTION)
    license_name: Optional[str] = Field(default=None)
    description: Optional[str] = Field(default=None)
    homepage: Optional[str] = Field(default=None)
    cpe: Optional[str] = Field(default=None, description="CPE identifier")
    hashes: Dict[str, str] = Field(default_factory=dict, description="Algorithm -> hash value")
    dependencies: List[str] = Field(default_factory=list, description="Dependency component refs")
    metadata: Dict[str, Any] = Field(default_factory=dict)


class SBOMDocument(BaseModel):
    """A complete Software Bill of Materials document."""
    model_config = ConfigDict(frozen=False)

    id: str = Field(default_factory=_gen_id)
    format_name: str = Field(default="CycloneDX", description="SBOM format: CycloneDX, SPDX")
    format_version: str = Field(default="1.5")
    name: str = Field(default="", description="Project / product name")
    version: str = Field(default="0.0.0")
    components: List[SBOMComponent] = Field(default_factory=list)
    total_components: int = Field(default=0)
    total_vulnerable: int = Field(default=0)
    generated_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    tool_name: str = Field(default="VulnPatch SupplyChain Analyzer")
    tool_version: str = Field(default="1.0.0")
    metadata: Dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Attack Detection Models
# ---------------------------------------------------------------------------

class AttackIndicator(BaseModel):
    """An indicator of a potential supply chain attack."""
    model_config = ConfigDict(frozen=False)

    id: str = Field(default_factory=_gen_id)
    attack_type: AttackType = Field(default=AttackType.UNKNOWN)
    dependency: Dependency = Field(...)
    severity: SeverityLevel = Field(default=SeverityLevel.MEDIUM)
    title: str = Field(default="")
    description: str = Field(default="")
    evidence: List[str] = Field(default_factory=list, description="Evidence strings")
    recommendation: str = Field(default="")
    confidence: str = Field(default="medium")
    metadata: Dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Aggregate Result Models
# ---------------------------------------------------------------------------

class SupplyChainFinding(BaseModel):
    """A finding from supply chain analysis (vulnerability or attack indicator)."""
    model_config = ConfigDict(frozen=False)

    id: str = Field(default_factory=_gen_id)
    rule_id: str = Field(..., description="Rule / check that produced this finding")
    type: str = Field(..., description="Finding type: 'cve_vulnerability', 'attack_indicator', 'license_risk'")
    cwe: Optional[str] = Field(default=None)
    severity: str = Field(default="UNKNOWN")
    confidence: str = Field(default="medium")
    file_path: str = Field(default="")
    start_line: int = Field(default=0)
    end_line: int = Field(default=0)
    message: str = Field(default="")
    engine: str = Field(default="supply_chain", description="Analyzer name")
    evidence: Dict[str, Any] = Field(default_factory=dict)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class SupplyChainScanResult(BaseModel):
    """Complete result of a supply chain security scan."""
    model_config = ConfigDict(frozen=False)

    id: str = Field(default_factory=_gen_id)
    scanned_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    dependency_files: List[DependencyFile] = Field(default_factory=list)
    total_dependencies: int = Field(default=0)
    total_direct: int = Field(default=0)
    total_transitive: int = Field(default=0)
    ecosystems: List[str] = Field(default_factory=list)
    cve_matches: List[CVEMatch] = Field(default_factory=list)
    attack_indicators: List[AttackIndicator] = Field(default_factory=list)
    findings: List[SupplyChainFinding] = Field(default_factory=list)
    sbom: Optional[SBOMDocument] = Field(default=None)
    summary: Dict[str, Any] = Field(default_factory=dict)
    metadata: Dict[str, Any] = Field(default_factory=dict)
