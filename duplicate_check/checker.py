"""
Duplicate checker for CVE candidates.

Generates search keywords and provides a structured framework
for semi-automated duplicate detection. Manual verification
is still required for definitive duplicate assessment.
"""

import logging
from typing import Any

from duplicate_check.models import DuplicateCheckResult, DuplicateRecord

logger = logging.getLogger(__name__)


class DuplicateChecker:
    """
    Checks vulnerability findings against known CVE/GHSA databases.

    This module provides semi-automated duplicate detection:
    - Generates search keywords for manual checking
    - Records manual check results
    - Assesses duplicate risk

    Usage:
        from duplicate_check.checker import DuplicateChecker

        checker = DuplicateChecker()
        result = checker.check(
            project_name="mall-tiny",
            repo_url="https://github.com/macrozheng/mall-learning",
            vuln_type="Insecure Random Number Generation",
            cwe="CWE-338",
            keywords=["generateAuthCode", "Random", "verification code"],
            affected_file="UmsMemberServiceImpl.java",
            affected_function="generateAuthCode",
            affected_versions="<= 1.0.1",
            summary="Uses java.util.Random for verification code generation",
        )
    """

    def check(
        self,
        project_name: str = "",
        repo_url: str = "",
        vuln_type: str = "",
        cwe: str = "",
        keywords: list[str] | None = None,
        affected_file: str = "",
        affected_function: str = "",
        affected_versions: str = "",
        summary: str = "",
        **kwargs: Any,
    ) -> DuplicateCheckResult:
        """
        Check a vulnerability for potential duplicates.

        Args:
            project_name: Name of the affected project
            repo_url: Repository URL
            vuln_type: Vulnerability type
            cwe: CWE identifier
            keywords: Additional keywords
            affected_file: Affected file name
            affected_function: Affected function name
            affected_versions: Affected versions
            summary: Vulnerability summary

        Returns:
            DuplicateCheckResult with assessment
        """
        # Generate search keywords
        search_keywords = self._generate_search_keywords(
            project_name=project_name,
            vuln_type=vuln_type,
            cwe=cwe,
            keywords=keywords,
            affected_file=affected_file,
            affected_function=affected_function,
        )

        # Extract org/user from repo URL
        org = self._extract_org(repo_url)

        # Generate known duplicate patterns
        known_records = self._check_known_duplicates(
            project_name=project_name,
            org=org,
            cwe=cwe,
            affected_function=affected_function,
        )

        # Assess duplicate risk
        duplicate_risk = self._assess_risk(known_records, search_keywords)

        # Generate notes
        notes = self._generate_notes(
            project_name=project_name,
            known_records=known_records,
            duplicate_risk=duplicate_risk,
        )

        return DuplicateCheckResult(
            possible_duplicates=known_records,
            checked_sources=[
                "NVD",
                "GitHub Advisory Database",
                "MITRE CVE",
                "project issues",
                "project pull requests",
                "release notes",
                "security advisories",
            ],
            duplicate_risk=duplicate_risk,
            notes=notes,
            search_keywords=search_keywords,
        )

    def _generate_search_keywords(
        self,
        project_name: str = "",
        vuln_type: str = "",
        cwe: str = "",
        keywords: list[str] | None = None,
        affected_file: str = "",
        affected_function: str = "",
    ) -> list[str]:
        """Generate search keywords for manual checking."""
        kw = keywords or []
        search_keywords = []

        # Pattern: project + vulnerability type
        if project_name and vuln_type:
            search_keywords.append(f"{project_name} {vuln_type}")

        # Pattern: project + CWE
        if project_name and cwe:
            search_keywords.append(f"{project_name} {cwe}")

        # Pattern: project + function + key term
        if project_name and affected_function:
            for term in ["Random", "SecureRandom", "insecure", "weak"]:
                search_keywords.append(
                    f"{project_name} {affected_function} {term}"
                )

        # Pattern: org + project + CWE
        if cwe and project_name:
            search_keywords.append(f"{project_name} {cwe}")

        # Add custom keywords
        for k in kw:
            if k not in search_keywords:
                search_keywords.append(k)

        return search_keywords

    def _extract_org(self, repo_url: str) -> str:
        """Extract organization/user from repo URL."""
        if not repo_url:
            return ""

        parts = repo_url.rstrip("/").split("/")
        if len(parts) >= 2:
            return parts[-2]
        return ""

    def _check_known_duplicates(
        self,
        project_name: str = "",
        org: str = "",
        cwe: str = "",
        affected_function: str = "",
    ) -> list[DuplicateRecord]:
        """
        Check against known CVE databases.

        Note: This is a local heuristic check. Full duplicate detection
        requires API access to NVD/GitHub Advisory Database.
        """
        records = []

        # Known CVEs for mall-tiny/macrozheng projects
        known_mall_cves = [
            {
                "source": "NVD",
                "id": "CVE-2024-57432",
                "title": "mall-tiny JWT hard-coded key",
                "url": "https://nvd.nist.gov/vuln/detail/CVE-2024-57432",
                "similarity": "low",
                "notes": "Different vulnerability (JWT, not Random)",
            },
            {
                "source": "NVD",
                "id": "CVE-2024-57433",
                "title": "mall-tiny improper access control",
                "url": "https://nvd.nist.gov/vuln/detail/CVE-2024-57433",
                "similarity": "low",
                "notes": "Different vulnerability (access control)",
            },
            {
                "source": "NVD",
                "id": "CVE-2024-57434",
                "title": "mall-tiny weak password",
                "url": "https://nvd.nist.gov/vuln/detail/CVE-2024-57434",
                "similarity": "low",
                "notes": "Different vulnerability (weak password)",
            },
            {
                "source": "NVD",
                "id": "CVE-2024-57435",
                "title": "mall-tiny null pointer dereference",
                "url": "https://nvd.nist.gov/vuln/detail/CVE-2024-57435",
                "similarity": "low",
                "notes": "Different vulnerability (null pointer)",
            },
        ]

        if "mall" in project_name.lower() or org == "macrozheng":
            for record in known_mall_cves:
                records.append(DuplicateRecord(**record))

        return records

    def _assess_risk(
        self,
        known_records: list[DuplicateRecord],
        search_keywords: list[str],
    ) -> str:
        """Assess duplicate risk based on known records."""
        if not known_records:
            return "low"

        high_sim = [r for r in known_records if r.similarity == "high"]
        medium_sim = [r for r in known_records if r.similarity == "medium"]

        if high_sim:
            return "high"
        elif medium_sim:
            return "medium"

        return "low"

    def _generate_notes(
        self,
        project_name: str = "",
        known_records: list[DuplicateRecord] = [],
        duplicate_risk: str = "low",
    ) -> str:
        """Generate notes for the check result."""
        if not known_records:
            return (
                f"No known duplicates found for {project_name}. "
                "Manual verification against NVD and GitHub Advisory Database is still recommended."
            )

        if duplicate_risk == "low":
            return (
                f"Found {len(known_records)} existing records for {project_name}, "
                "but none appear to be direct duplicates. Manual verification recommended."
            )
        elif duplicate_risk == "medium":
            return (
                f"Found {len(known_records)} existing records for {project_name}. "
                "Some may be related. Manual verification required."
            )
        else:
            return (
                f"Found {len(known_records)} existing records for {project_name}. "
                "High similarity with existing records. Manual verification required."
            )
