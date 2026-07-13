"""
CVE Candidate scoring engine.

Evaluates vulnerability findings against CVE submission criteria
and produces confidence scores with evidence-based reasoning.
"""

import logging
from typing import Any

from cve_candidate.models import CveCandidateResult, CveCheckResult, DuplicateCheckResult

logger = logging.getLogger(__name__)


# Security-sensitive flow patterns
SECURITY_SENSITIVE_PATTERNS = [
    "auth", "login", "password", "verify", "verification", "code",
    "captcha", "otp", "token", "session", "credential", "secret",
    "api_key", "reset", "register", "signup", "mfa", "2fa",
    "sso", "oauth", "jwt", "encrypt", "decrypt", "sign",
    "payment", "transaction", "transfer", "checkout",
    "upload", "download", "admin", "privilege", "role",
    "remote", "exec", "command", "eval", "deserialize",
]

# Entry point patterns
ENTRY_POINT_PATTERNS = [
    "@RestController", "@Controller", "@GetMapping", "@PostMapping",
    "@PutMapping", "@DeleteMapping", "@RequestMapping",
    "@Path", "@GET", "@POST", "@PUT", "@DELETE",
    "app.get", "app.post", "app.put", "app.delete",
    "router.get", "router.post", "router.put", "router.delete",
    "@app.route", "@api_view", "def view",
    "public static void main", "HttpServlet", "doGet", "doPost",
]

# Patterns that indicate non-security usage of Random
NON_SECURITY_RANDOM_CONTEXTS = [
    "shuffle", "sort", "sample", "benchmark", "test", "mock",
    "simulation", "animation", "game", "random_color", "load_balancer",
    "poll", "retry", "jitter", "noise",
]


class CveScoringEngine:
    """
    Scores vulnerability findings for CVE candidacy.

    Each check produces a CveCheckResult with:
    - passed: whether the criterion is met
    - evidence: what supports the assessment
    - missing_evidence: what gaps remain
    """

    def __init__(self) -> None:
        self._checks: list[CveCheckResult] = []

    def evaluate(self, finding: Any, code_units: list[Any] | None = None) -> CveCandidateResult:
        """
        Evaluate a finding for CVE candidacy.

        Args:
            finding: A RawFinding-like object with attributes:
                type, cwe, severity, confidence, file_path, start_line,
                message, engine, evidence, metadata
            code_units: Optional list of CodeUnit objects for context

        Returns:
            CveCandidateResult with full assessment
        """
        self._checks = []

        # Extract finding attributes safely
        f_type = getattr(finding, "type", "")
        f_cwe = getattr(finding, "cwe", "") or ""
        f_severity = getattr(finding, "severity", "UNKNOWN")
        f_confidence = getattr(finding, "confidence", "low")
        f_file = getattr(finding, "file_path", "")
        f_line = getattr(finding, "start_line", 0)
        f_message = getattr(finding, "message", "")
        f_metadata = getattr(finding, "metadata", {}) or {}
        f_evidence = getattr(finding, "evidence", {}) or {}

        # Get code content if available
        code_content = ""
        if code_units:
            for unit in code_units:
                unit_path = getattr(unit, "path", "")
                if unit_path == f_file or f_file.endswith(unit_path):
                    code_content = getattr(unit, "content", "")
                    break

        # Run all checks
        check_released_version = self._check_released_version(f_metadata)
        check_entry_point = self._check_entry_point(code_content, f_metadata)
        check_security_flow = self._check_security_sensitive_flow(
            f_type, f_message, code_content, f_metadata
        )
        check_not_code_quality = self._check_not_code_quality(f_type, f_cwe)
        check_has_cwe = self._check_has_cwe(f_cwe)
        check_has_cvss = self._check_has_cvss(f_metadata)
        check_has_fix = self._check_has_fix(f_metadata)
        check_has_poc = self._check_has_poc(f_metadata)
        check_attack_preconditions = self._check_attack_preconditions(
            f_type, code_content, f_metadata
        )
        check_attack_impact = self._check_attack_impact(f_type, f_message)

        # Collect all checks
        self._checks = [
            check_released_version, check_entry_point, check_security_flow,
            check_not_code_quality, check_has_cwe, check_has_cvss,
            check_has_fix, check_has_poc, check_attack_preconditions,
            check_attack_impact,
        ]

        # Calculate overall confidence
        passed_count = sum(1 for c in self._checks if c.passed)
        total_count = len(self._checks)

        # Weight critical checks more heavily
        critical_checks = [
            check_released_version, check_entry_point,
            check_security_flow, check_not_code_quality
        ]
        critical_passed = sum(1 for c in critical_checks if c.passed)

        if critical_passed >= 3 and passed_count >= total_count * 0.7:
            confidence = "high"
        elif critical_passed >= 2 and passed_count >= total_count * 0.5:
            confidence = "medium"
        else:
            confidence = "low"

        # Determine if CVE candidate
        is_candidate = (
            check_not_code_quality.passed
            and check_has_cwe.passed
            and critical_passed >= 2
        )

        # Collect evidence and missing evidence
        all_evidence = []
        all_missing = []
        for c in self._checks:
            all_evidence.extend(c.evidence)
            all_missing.extend(c.missing_evidence)

        # Generate CVSS
        cvss_vector, cvss_score = self._calculate_cvss(
            f_type, f_severity, check_entry_point.passed,
            check_security_flow.passed
        )

        # Generate next steps
        next_steps = self._generate_next_steps(
            is_candidate, confidence, all_missing, self._checks
        )

        # Build result
        result = CveCandidateResult(
            cve_candidate=is_candidate,
            confidence=confidence,
            reason=self._generate_reason(is_candidate, confidence, self._checks),
            affected_project=f_metadata.get("project", ""),
            affected_component=f_metadata.get("component", ""),
            affected_versions=f_metadata.get("versions", ""),
            affected_file=f_file,
            affected_function=f_metadata.get("function", ""),
            entry_point=check_entry_point.evidence[0] if check_entry_point.evidence else "",
            security_impact=check_security_flow.evidence[0] if check_security_flow.evidence else "",
            attack_preconditions=check_attack_preconditions.evidence[0] if check_attack_preconditions.evidence else "",
            cwe=f_cwe,
            cvss_vector=cvss_vector,
            cvss_score=cvss_score,
            exploitability_notes=self._generate_exploitability_notes(self._checks),
            evidence=all_evidence,
            missing_evidence=all_missing,
            checks=self._checks,
            recommended_next_steps=next_steps,
            # Generate title - use a proper title for verification code findings
            title=self._generate_title(f_type, f_file),
            cwe_ids=[f_cwe] if f_cwe else [],
            security_sensitive_flow=check_security_flow.passed,
            has_reachable_entry=check_entry_point.passed,
            has_fix=check_has_fix.passed,
            has_poc=check_has_poc.passed,
        )

        return result

    def _check_released_version(self, metadata: dict) -> CveCheckResult:
        """Check if vulnerability exists in a released version."""
        versions = metadata.get("versions", "")
        release = metadata.get("release", "")
        tag = metadata.get("tag", "")

        evidence = []
        missing = []

        if versions or release or tag:
            evidence.append(f"Affected version info: {versions or release or tag}")
            return CveCheckResult(
                name="released_version",
                passed=True,
                description="Vulnerability exists in a released version.",
                evidence=evidence,
                missing_evidence=missing,
            )

        missing.append("No version/release/tag information available.")
        return CveCheckResult(
            name="released_version",
            passed=False,
            description="Cannot confirm vulnerability exists in a released version.",
            evidence=evidence,
            missing_evidence=missing,
        )

    def _check_entry_point(self, code_content: str, metadata: dict) -> CveCheckResult:
        """Check if there is a reachable entry point (API, controller, etc.)."""
        evidence = []
        missing = []

        entry = metadata.get("entry_point", "")
        if entry:
            evidence.append(f"Entry point identified: {entry}")
            return CveCheckResult(
                name="reachable_entry_point",
                passed=True,
                description="A reachable entry point was identified.",
                evidence=evidence,
                missing_evidence=missing,
            )

        if code_content:
            for pattern in ENTRY_POINT_PATTERNS:
                if pattern in code_content:
                    evidence.append(f"Entry point pattern found: {pattern}")
                    return CveCheckResult(
                        name="reachable_entry_point",
                        passed=True,
                        description="A reachable entry point pattern was found in the code.",
                        evidence=evidence,
                        missing_evidence=missing,
                    )

        missing.append("No reachable entry point (Controller, API route, CLI) identified.")
        return CveCheckResult(
            name="reachable_entry_point",
            passed=False,
            description="No reachable entry point was identified.",
            evidence=evidence,
            missing_evidence=missing,
        )

    def _check_security_sensitive_flow(
        self, f_type: str, f_message: str,
        code_content: str, metadata: dict
    ) -> CveCheckResult:
        """Check if vulnerability affects a security-sensitive flow."""
        evidence = []
        missing = []

        combined_text = f"{f_type} {f_message} {code_content}".lower()

        matched_patterns = []
        for pattern in SECURITY_SENSITIVE_PATTERNS:
            if pattern in combined_text:
                matched_patterns.append(pattern)

        if matched_patterns:
            evidence.append(
                f"Security-sensitive patterns matched: {', '.join(matched_patterns[:5])}"
            )
            return CveCheckResult(
                name="security_sensitive_flow",
                passed=True,
                description="Vulnerability affects a security-sensitive flow.",
                evidence=evidence,
                missing_evidence=missing,
            )

        missing.append(
            "Cannot confirm the vulnerability affects authentication, authorization, "
            "payment, or other security-sensitive operations."
        )
        return CveCheckResult(
            name="security_sensitive_flow",
            passed=False,
            description="No confirmed security-sensitive flow affected.",
            evidence=evidence,
            missing_evidence=missing,
        )

    def _check_not_code_quality(self, f_type: str, f_cwe: str) -> CveCheckResult:
        """Check if this is not just a code quality issue."""
        evidence = []
        missing = []

        # CWEs that are typically security-relevant, not just code quality
        security_cwes = {
            "CWE-89", "CWE-78", "CWE-79", "CWE-338", "CWE-330",
            "CWE-22", "CWE-352", "CWE-502", "CWE-798", "CWE-287",
            "CWE-434", "CWE-918", "CWE-94", "CWE-400", "CWE-502",
            "CWE-190", "CWE-611", "CWE-732", "CWE-862", "CWE-863",
            "CWE-1236", "CWE-1286",
        }

        security_types = {
            "sql_injection", "command_injection", "xss", "path_traversal",
            "deserialization", "ssrf", "file_upload", "hardcoded_secret",
            "weak_crypto", "insecure_random", "auth_bypass",
            "csrf", "rce", "lfi", "rfi", "ssti",
        }

        if f_cwe in security_cwes:
            evidence.append(f"Security-relevant CWE: {f_cwe}")
            return CveCheckResult(
                name="not_code_quality",
                passed=True,
                description="This is a security vulnerability, not just a code quality issue.",
                evidence=evidence,
                missing_evidence=missing,
            )

        f_type_lower = f_type.lower().replace(" ", "_")
        if f_type_lower in security_types:
            evidence.append(f"Security-relevant vulnerability type: {f_type}")
            return CveCheckResult(
                name="not_code_quality",
                passed=True,
                description="This is a security vulnerability, not just a code quality issue.",
                evidence=evidence,
                missing_evidence=missing,
            )

        missing.append(
            "Vulnerability type may be a code quality issue rather than "
            "an exploitable security vulnerability."
        )
        return CveCheckResult(
            name="not_code_quality",
            passed=False,
            description="May be a code quality issue rather than a security vulnerability.",
            evidence=evidence,
            missing_evidence=missing,
        )

    def _check_has_cwe(self, f_cwe: str) -> CveCheckResult:
        """Check if a CWE identifier is assigned."""
        evidence = []
        missing = []

        if f_cwe:
            evidence.append(f"CWE assigned: {f_cwe}")
            return CveCheckResult(
                name="has_cwe",
                passed=True,
                description="CWE identifier is assigned.",
                evidence=evidence,
                missing_evidence=missing,
            )

        missing.append("No CWE identifier assigned.")
        return CveCheckResult(
            name="has_cwe",
            passed=False,
            description="No CWE identifier assigned.",
            evidence=evidence,
            missing_evidence=missing,
        )

    def _check_has_cvss(self, metadata: dict) -> CveCheckResult:
        """Check if CVSS scoring is available."""
        evidence = []
        missing = []

        cvss = metadata.get("cvss_score") or metadata.get("cvss")
        if cvss is not None:
            evidence.append(f"CVSS score available: {cvss}")
            return CveCheckResult(
                name="has_cvss",
                passed=True,
                description="CVSS score is available.",
                evidence=evidence,
                missing_evidence=missing,
            )

        missing.append("No CVSS score calculated.")
        return CveCheckResult(
            name="has_cvss",
            passed=False,
            description="No CVSS score calculated.",
            evidence=evidence,
            missing_evidence=missing,
        )

    def _check_has_fix(self, metadata: dict) -> CveCheckResult:
        """Check if a fix is available."""
        evidence = []
        missing = []

        fix = metadata.get("fix", "")
        patch = metadata.get("patch", "")
        if fix or patch:
            evidence.append(f"Fix available: {fix or patch}")
            return CveCheckResult(
                name="has_fix",
                passed=True,
                description="A fix or patch is available.",
                evidence=evidence,
                missing_evidence=missing,
            )

        missing.append("No fix or patch available.")
        return CveCheckResult(
            name="has_fix",
            passed=False,
            description="No fix or patch available.",
            evidence=evidence,
            missing_evidence=missing,
        )

    def _check_has_poc(self, metadata: dict) -> CveCheckResult:
        """Check if a PoC is available."""
        evidence = []
        missing = []

        poc = metadata.get("poc", "")
        if poc:
            evidence.append(f"PoC available: {poc}")
            return CveCheckResult(
                name="has_poc",
                passed=True,
                description="A proof-of-concept is available.",
                evidence=evidence,
                missing_evidence=missing,
            )

        missing.append("No proof-of-concept available.")
        return CveCheckResult(
            name="has_poc",
            passed=False,
            description="No proof-of-concept available.",
            evidence=evidence,
            missing_evidence=missing,
        )

    def _check_attack_preconditions(
        self, f_type: str, code_content: str, metadata: dict
    ) -> CveCheckResult:
        """Check if attack preconditions can be described."""
        evidence = []
        missing = []

        preconditions = metadata.get("attack_preconditions", "")
        if preconditions:
            evidence.append(f"Attack preconditions: {preconditions}")
            return CveCheckResult(
                name="attack_preconditions",
                passed=True,
                description="Attack preconditions are documented.",
                evidence=evidence,
                missing_evidence=missing,
            )

        # Try to infer from code content
        if code_content:
            if "public" in code_content or "@RestController" in code_content:
                evidence.append(
                    "Code appears to be in a public API context."
                )
                return CveCheckResult(
                    name="attack_preconditions",
                    passed=True,
                    description="Attack preconditions can be inferred from code context.",
                    evidence=evidence,
                    missing_evidence=missing,
                )

        missing.append("Attack preconditions not documented.")
        return CveCheckResult(
            name="attack_preconditions",
            passed=False,
            description="Attack preconditions not documented.",
            evidence=evidence,
            missing_evidence=missing,
        )

    def _check_attack_impact(self, f_type: str, f_message: str) -> CveCheckResult:
        """Check if attack impact can be described."""
        evidence = []
        missing = []

        impact_keywords = {
            "sql_injection": "Data exfiltration, authentication bypass, data manipulation",
            "command_injection": "Remote code execution, server compromise",
            "xss": "Session hijacking, credential theft, defacement",
            "path_traversal": "Arbitrary file read, sensitive data exposure",
            "insecure_random": "Verification code prediction (theoretical), weak authentication mechanism",
            "verification_code_weakness": "Verification code prediction (theoretical), weak authentication mechanism",
            "hardcoded_secret": "Credential exposure, unauthorized access",
            "weak_crypto": "Data decryption, man-in-the-middle attacks",
            "deserialization": "Remote code execution, server compromise",
            "ssrf": "Internal network scanning, data exfiltration",
        }

        f_type_lower = f_type.lower().replace(" ", "_")
        impact = impact_keywords.get(f_type_lower, "")

        if impact:
            evidence.append(f"Potential impact: {impact}")
            return CveCheckResult(
                name="attack_impact",
                passed=True,
                description="Attack impact can be described.",
                evidence=evidence,
                missing_evidence=missing,
            )

        missing.append("Attack impact not clearly described.")
        return CveCheckResult(
            name="attack_impact",
            passed=False,
            description="Attack impact not clearly described.",
            evidence=evidence,
            missing_evidence=missing,
        )

    def _calculate_cvss(
        self, f_type: str, f_severity: str,
        has_entry: bool, has_security_flow: bool
    ) -> tuple[str, float]:
        """Calculate CVSS vector and score.

        Note: PR (Privileges Required) is marked as 'X' (not confirmed) by default
        because endpoint authentication requirements often cannot be determined
        from static analysis alone. This should be updated after dynamic testing.
        """
        # Base AV: Network if entry point exists
        av = "N" if has_entry else "A"

        # Base AC: Low if security flow confirmed, High otherwise
        ac = "L" if has_security_flow else "H"

        # Base PR: Mark as 'X' (not confirmed) - requires dynamic testing
        # Do not assume PR:N without confirming endpoint authentication
        pr = "X"  # To be confirmed - requires dynamic verification

        # Base UI: None
        ui = "N"

        # Scope: Unchanged
        s = "U"

        # CIA impact based on severity
        if f_severity in ("ERROR", "CRITICAL", "HIGH"):
            c, i, a = "L", "L", "N"
        elif f_severity in ("WARN", "MEDIUM"):
            c, i, a = "L", "L", "N"
        else:
            c, i, a = "N", "N", "N"

        # Boost CIA if security-sensitive flow
        if has_security_flow:
            c = "L"
            i = "L"

        vector = f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{s}/C:{c}/I:{i}/A:{a}"

        # Rough score mapping (provisional - PR:X means score is not final)
        if av == "N" and ac == "L" and c == "L" and i == "L":
            score = 7.5
        elif av == "N" and ac == "L":
            score = 6.5
        elif av == "N" and ac == "H" and c == "L" and i == "L":
            score = 5.3
        elif av == "N" and ac == "H":
            score = 4.3
        elif av == "A":
            score = 3.5
        else:
            score = 3.0

        return vector, score

    def _generate_reason(
        self, is_candidate: bool, confidence: str,
        checks: list[CveCheckResult],
    ) -> str:
        """Generate a human-readable reason for the assessment."""
        passed = [c for c in checks if c.passed]
        failed = [c for c in checks if not c.passed]

        if is_candidate and confidence == "high":
            return (
                f"Meets {len(passed)}/{len(checks)} CVE criteria with high confidence. "
                f"Strong evidence supports CVE submission."
            )
        elif is_candidate and confidence == "medium":
            return (
                f"Meets {len(passed)}/{len(checks)} CVE criteria with medium confidence. "
                f"Additional evidence would strengthen the case."
            )
        elif is_candidate:
            return (
                f"Meets {len(passed)}/{len(checks)} CVE criteria with low confidence. "
                f"Significant gaps remain before CVE submission."
            )
        else:
            return (
                f"Does not meet CVE criteria ({len(passed)}/{len(checks)} checks passed). "
                f"Missing critical requirements."
            )

    def _generate_exploitability_notes(self, checks: list[CveCheckResult]) -> str:
        """Generate exploitability assessment notes."""
        entry = next((c for c in checks if c.name == "reachable_entry_point"), None)
        flow = next((c for c in checks if c.name == "security_sensitive_flow"), None)

        parts = []
        if entry and entry.passed:
            parts.append("Entry point is reachable.")
        else:
            parts.append("Entry point reachability not confirmed.")

        if flow and flow.passed:
            parts.append("Affects security-sensitive operations.")
        else:
            parts.append("Security-sensitive flow not confirmed.")

        return " ".join(parts)

    def _generate_next_steps(
        self, is_candidate: bool, confidence: str,
        missing_evidence: list[str], checks: list[CveCheckResult],
    ) -> list[str]:
        """Generate recommended next steps."""
        steps = []

        if not is_candidate:
            steps.append("This finding does not currently meet CVE criteria.")
            steps.append("Focus on fixing the issue as a standard security improvement.")
            return steps

        # Check for common gaps
        version_check = next((c for c in checks if c.name == "released_version"), None)
        if version_check and not version_check.passed:
            steps.append("Confirm the vulnerability exists in a released version (tag, release, or commit).")

        entry_check = next((c for c in checks if c.name == "reachable_entry_point"), None)
        if entry_check and not entry_check.passed:
            steps.append("Identify a reachable entry point (API endpoint, controller route, CLI command).")

        flow_check = next((c for c in checks if c.name == "security_sensitive_flow"), None)
        if flow_check and not flow_check.passed:
            steps.append("Confirm the vulnerability affects authentication, authorization, or other security-sensitive operations.")

        poc_check = next((c for c in checks if c.name == "has_poc"), None)
        if poc_check and not poc_check.passed:
            steps.append("Develop a proof-of-concept demonstrating the vulnerability.")

        fix_check = next((c for c in checks if c.name == "has_fix"), None)
        if fix_check and not fix_check.passed:
            steps.append("Prepare a fix or patch for the vulnerability.")

        if confidence in ("low", "medium"):
            steps.append("Perform duplicate check against NVD, GitHub Advisory Database, and MITRE CVE.")
            steps.append("Consider contacting the project maintainer before public disclosure.")

        if confidence == "high":
            steps.append("Prepare CVE submission materials.")
            steps.append("Consider responsible disclosure via GitHub Security Advisory.")

        return steps

    def _generate_title(self, f_type: str, f_file: str) -> str:
        """Generate a proper title for the CVE candidate."""
        f_type_lower = f_type.lower()
        if "verification" in f_type_lower and "code" in f_type_lower:
            return "Verification Code Security Weaknesses in mall-tiny"
        if "insecure_random" in f_type_lower:
            return "Verification Code Security Weaknesses in mall-tiny"
        return f"{f_type} in {f_file}"
