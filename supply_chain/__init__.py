"""
Supply Chain Security Module for VulnPatch.

Provides comprehensive third-party library and supply chain security analysis:
- Dependency file parsing (requirements.txt, package.json, pom.xml, etc.)
- CVE vulnerability matching against known databases
- SBOM (Software Bill of Materials) generation (CycloneDX / SPDX)
- Supply chain attack detection (typosquatting, dependency confusion, etc.)
"""

from supply_chain.models import (
    Dependency,
    DependencyFile,
    VulnerabilityInfo,
    CVEMatch,
    SBOMDocument,
    SBOMComponent,
    SupplyChainFinding,
    SupplyChainScanResult,
    AttackIndicator,
    AttackType,
    SeverityLevel,
    DependencyScope,
    Ecosystem,
)
from supply_chain.dep_parser import DependencyParser
from supply_chain.cve_matcher import CVEMatcher
from supply_chain.sbom_generator import SBOMGenerator
from supply_chain.attack_detector import SupplyChainAttackDetector

__all__ = [
    "Dependency",
    "DependencyFile",
    "VulnerabilityInfo",
    "CVEMatch",
    "SBOMDocument",
    "SBOMComponent",
    "SupplyChainFinding",
    "SupplyChainScanResult",
    "AttackIndicator",
    "AttackType",
    "SeverityLevel",
    "DependencyScope",
    "Ecosystem",
    "DependencyParser",
    "CVEMatcher",
    "SBOMGenerator",
    "SupplyChainAttackDetector",
]
