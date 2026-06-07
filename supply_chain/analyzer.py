"""
Supply Chain Analyzer - integrates into VulnPatch analyzer framework.

Scans project dependency files for:
- Known vulnerabilities (CVE matching via OSV/NVD)
- Supply chain attack indicators (typosquatting, dependency confusion, etc.)
- License risk assessment
- Generates SBOM documents

This analyzer is special: it doesn't analyze source code but dependency files.
It scans the project directory for dependency files and processes them.
"""

import asyncio
import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from analyzers.base import BaseAnalyzer
from audit_core.models import CodeUnit, RawFinding
from supply_chain.models import (
    AttackIndicator, AttackType, CVEMatch, Dependency, DependencyFile,
    Ecosystem, SeverityLevel, SupplyChainFinding, SupplyChainScanResult,
)
from supply_chain.dep_parser import DependencyParser
from supply_chain.cve_matcher import CVEMatcher
from supply_chain.attack_detector import SupplyChainAttackDetector
from supply_chain.sbom_generator import SBOMGenerator

logger = logging.getLogger(__name__)


class SupplyChainAnalyzer(BaseAnalyzer):
    """Analyzer for supply chain security.

    Unlike other analyzers that operate on source code CodeUnits,
    this analyzer scans dependency files in the project directory.

    Configuration (environment variables):
    - SUPPLY_CHAIN_ENABLED: Enable/disable (default: "true")
    - SUPPLY_CHAIN_CVE_MATCH: Enable CVE matching (default: "true")
    - SUPPLY_CHAIN_ATTACK_DETECT: Enable attack detection (default: "true")
    - SUPPLY_CHAIN_SBOM_GENERATE: Enable SBOM generation (default: "true")
    - SUPPLY_CHAIN_PROJECT_DIR: Override project directory for dependency scanning
    """

    name = "supply_chain"
    supported_languages = [
        "python", "javascript", "typescript", "java", "go",
        "rust", "php", "ruby", "cpp", "c", "csharp",
    ]

    def __init__(self) -> None:
        self._enabled = os.getenv("SUPPLY_CHAIN_ENABLED", "true").lower() == "true"
        self._cve_match_enabled = os.getenv("SUPPLY_CHAIN_CVE_MATCH", "true").lower() == "true"
        self._attack_detect_enabled = os.getenv("SUPPLY_CHAIN_ATTACK_DETECT", "true").lower() == "true"
        self._sbom_generate_enabled = os.getenv("SUPPLY_CHAIN_SBOM_GENERATE", "true").lower() == "true"
        self._project_dir: Optional[str] = os.getenv("SUPPLY_CHAIN_PROJECT_DIR")

        self._parser = DependencyParser()
        self._cve_matcher = CVEMatcher()
        self._attack_detector = SupplyChainAttackDetector()
        self._sbom_generator = SBOMGenerator()

        # Store last scan result for retrieval
        self._last_scan_result: Optional[SupplyChainScanResult] = None

    def is_available(self) -> bool:
        return self._enabled

    def analyze(self, code_units: list[CodeUnit]) -> list[RawFinding]:
        """Analyze dependency files found in the project.

        This method:
        1. Determines the project directory from code_units metadata
        2. Scans for dependency files
        3. Runs CVE matching, attack detection, and SBOM generation
        4. Converts results to RawFinding objects for the standard pipeline
        """
        if not self._enabled:
            return []

        findings: list[RawFinding] = []

        # Determine project directory
        project_dir = self._resolve_project_dir(code_units)
        if not project_dir or not Path(project_dir).exists():
            logger.info("No project directory found for supply chain analysis")
            return []

        try:
            # Parse dependency files
            dep_files = self._parser.scan_project(project_dir)
            if not dep_files:
                logger.info("No dependency files found in %s", project_dir)
                return []

            logger.info(
                "Found %d dependency files in %s",
                len(dep_files), project_dir,
            )

            # Collect all dependencies
            all_deps = self._collect_dependencies(dep_files)

            # Run CVE matching
            if self._cve_match_enabled and all_deps:
                cve_findings = self._run_cve_matching(all_deps, dep_files)
                findings.extend(cve_findings)

            # Run attack detection
            if self._attack_detect_enabled:
                attack_findings = self._run_attack_detection(dep_files)
                findings.extend(attack_findings)

            # Generate SBOM
            sbom = None
            if self._sbom_generate_enabled and dep_files:
                sbom = self._sbom_generator.generate(dep_files)

            # Build scan result
            self._last_scan_result = self._build_scan_result(
                dep_files, findings, sbom
            )

            logger.info(
                "Supply chain analysis complete: %d findings",
                len(findings),
            )

        except Exception as e:
            logger.error("Supply chain analysis failed: %s", e, exc_info=True)

        return findings

    def _resolve_project_dir(self, code_units: list[CodeUnit]) -> Optional[str]:
        """Resolve project directory from code units."""
        if self._project_dir:
            return self._project_dir

        for unit in code_units:
            abs_path = unit.metadata.get("absolute_path", "")
            if abs_path:
                parent = str(Path(abs_path).parent)
                if Path(parent).exists():
                    return parent

        # Try current working directory
        cwd = os.getcwd()
        if Path(cwd).exists():
            return cwd

        return None

    def _collect_dependencies(
        self, dep_files: List[DependencyFile]
    ) -> List[Dependency]:
        """Collect all dependencies from parsed files."""
        deps = []
        seen = set()
        for df in dep_files:
            for dep in df.dependencies:
                key = (dep.name, dep.ecosystem, dep.version)
                if key not in seen:
                    seen.add(key)
                    deps.append(dep)
        return deps

    def _run_cve_matching(
        self, deps: List[Dependency], dep_files: List[DependencyFile]
    ) -> List[RawFinding]:
        """Run CVE matching and convert to RawFindings."""
        findings = []
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                # We're inside an async context, create a new thread
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                    future = pool.submit(
                        asyncio.run,
                        self._cve_matcher.match_dependencies(deps)
                    )
                    matches = future.result(timeout=120)
            else:
                matches = loop.run_until_complete(
                    self._cve_matcher.match_dependencies(deps)
                )
        except Exception as e:
            logger.warning("CVE matching failed: %s", e)
            matches = []

        for match in matches:
            finding = self._cve_match_to_finding(match)
            findings.append(finding)

        return findings

    def _run_attack_detection(
        self, dep_files: List[DependencyFile]
    ) -> List[RawFinding]:
        """Run attack detection and convert to RawFindings."""
        findings = []
        indicators = self._attack_detector.scan(dep_files)

        for indicator in indicators:
            finding = self._attack_indicator_to_finding(indicator)
            findings.append(finding)

        return findings

    def _cve_match_to_finding(self, match: CVEMatch) -> RawFinding:
        """Convert a CVEMatch to a RawFinding."""
        vuln = match.vulnerability
        dep = match.dependency

        severity_map = {
            SeverityLevel.CRITICAL: "ERROR",
            SeverityLevel.HIGH: "ERROR",
            SeverityLevel.MEDIUM: "WARN",
            SeverityLevel.LOW: "INFO",
            SeverityLevel.INFO: "INFO",
            SeverityLevel.UNKNOWN: "WARN",
        }

        return RawFinding(
            rule_id=f"SCA-CVE-{vuln.cve_id or vuln.vuln_id or 'UNKNOWN'}",
            type=f"Known Vulnerability: {vuln.title or vuln.cve_id or 'Unknown'}",
            cwe=vuln.cwe_ids[0] if vuln.cwe_ids else None,
            severity=severity_map.get(vuln.severity, "WARN"),
            confidence=match.confidence,
            file_path=dep.source_file or "dependency-manifest",
            start_line=dep.line_number or 1,
            end_line=dep.line_number or 1,
            message=(
                f"Dependency '{dep.name}' ({dep.resolved_version or dep.version}) "
                f"has known vulnerability {vuln.cve_id or vuln.vuln_id or ''}: "
                f"{vuln.description[:200]}"
            ),
            engine="supply_chain",
            evidence={
                "dependency_name": dep.name,
                "dependency_version": dep.resolved_version or dep.version,
                "dependency_ecosystem": dep.ecosystem.value,
                "cve_id": vuln.cve_id,
                "vuln_id": vuln.vuln_id,
                "cvss_score": vuln.cvss_score,
                "cvss_vector": vuln.cvss_vector,
                "affected_versions": vuln.affected_versions,
                "patched_versions": vuln.patched_versions,
                "remediation": match.remediation,
                "match_confidence": match.confidence,
                "match_reason": match.match_reason,
                "references": vuln.references,
            },
            metadata={
                "category": "supply_chain",
                "subcategory": "cve_vulnerability",
                "is_affected": match.is_affected,
            },
        )

    def _attack_indicator_to_finding(
        self, indicator: AttackIndicator
    ) -> RawFinding:
        """Convert an AttackIndicator to a RawFinding."""
        severity_map = {
            SeverityLevel.CRITICAL: "ERROR",
            SeverityLevel.HIGH: "ERROR",
            SeverityLevel.MEDIUM: "WARN",
            SeverityLevel.LOW: "INFO",
            SeverityLevel.INFO: "INFO",
            SeverityLevel.UNKNOWN: "WARN",
        }

        return RawFinding(
            rule_id=f"SCA-ATTACK-{indicator.attack_type.value}",
            type=f"Supply Chain Attack: {indicator.title}",
            cwe="CWE-1357" if indicator.attack_type == AttackType.TYPOSQUATTING else
                 "CWE-829" if indicator.attack_type == AttackType.DEPENDENCY_CONFUSION else
                 "CWE-506" if indicator.attack_type == AttackType.MALICIOUS_PACKAGE else None,
            severity=severity_map.get(indicator.severity, "WARN"),
            confidence=indicator.confidence,
            file_path=indicator.dependency.source_file or "dependency-manifest",
            start_line=indicator.dependency.line_number or 1,
            end_line=indicator.dependency.line_number or 1,
            message=indicator.description,
            engine="supply_chain",
            evidence={
                "attack_type": indicator.attack_type.value,
                "dependency_name": indicator.dependency.name,
                "dependency_version": indicator.dependency.version,
                "evidence": indicator.evidence,
                "recommendation": indicator.recommendation,
            },
            metadata={
                "category": "supply_chain",
                "subcategory": "attack_indicator",
            },
        )

    def _build_scan_result(
        self,
        dep_files: List[DependencyFile],
        findings: List[RawFinding],
        sbom: Any,
    ) -> SupplyChainScanResult:
        """Build the complete scan result."""
        all_deps = self._collect_dependencies(dep_files)
        ecosystems = list(set(
            dep.ecosystem.value
            for dep in all_deps
            if dep.ecosystem != Ecosystem.UNKNOWN
        ))

        return SupplyChainScanResult(
            dependency_files=dep_files,
            total_dependencies=len(all_deps),
            total_direct=sum(1 for d in all_deps if d.is_direct),
            total_transitive=sum(1 for d in all_deps if not d.is_direct),
            ecosystems=ecosystems,
            findings=[],
            sbom=sbom,
            summary={
                "total_findings": len(findings),
                "cve_findings": sum(1 for f in findings if f.metadata.get("subcategory") == "cve_vulnerability"),
                "attack_findings": sum(1 for f in findings if f.metadata.get("subcategory") == "attack_indicator"),
                "dependency_files_scanned": len(dep_files),
            },
        )

    def get_last_scan_result(self) -> Optional[SupplyChainScanResult]:
        """Get the result of the most recent scan."""
        return self._last_scan_result
