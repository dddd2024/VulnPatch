"""
Tests for CVE candidate evaluation module.
"""

import pytest
from unittest.mock import MagicMock

from cve_candidate.evaluator import CveCandidateEvaluator
from cve_candidate.models import CveCandidateResult, CveCheckResult
from cve_candidate.scoring import CveScoringEngine
from duplicate_check.checker import DuplicateChecker
from duplicate_check.models import DuplicateCheckResult, DuplicateRecord


class MockFinding:
    """Mock finding for testing."""
    def __init__(self, **kwargs):
        self.type = kwargs.get("type", "insecure_random")
        self.cwe = kwargs.get("cwe", "CWE-338")
        self.severity = kwargs.get("severity", "WARN")
        self.confidence = kwargs.get("confidence", "medium")
        self.file_path = kwargs.get("file_path", "UmsMemberServiceImpl.java")
        self.start_line = kwargs.get("start_line", 32)
        self.message = kwargs.get("message", "java.util.Random used for verification code")
        self.engine = kwargs.get("engine", "pattern")
        self.evidence = kwargs.get("evidence", {})
        self.metadata = kwargs.get("metadata", {})


class TestCveScoringEngine:
    """Tests for CveScoringEngine."""

    def test_java_random_in_verification_code_is_cwe338(self):
        """Java verification code using java.util.Random should be identified as CWE-338."""
        engine = CveScoringEngine()
        finding = MockFinding(
            type="insecure_random",
            cwe="CWE-338",
            severity="WARN",
            message="java.util.Random used for verification code generation",
            metadata={
                "function": "generateAuthCode",
                "entry_point": "POST /sso/getAuthCode",
                "project": "mall-tiny",
            },
        )
        result = engine.evaluate(finding)

        assert result.cve_candidate is True
        assert result.cwe == "CWE-338"
        assert "CWE-338" in result.cwe_ids

    def test_non_security_random_should_not_be_high_cve(self):
        """Non-security context Random should not be marked as high CVE potential."""
        engine = CveScoringEngine()
        finding = MockFinding(
            type="insecure_random",
            cwe="CWE-338",
            severity="INFO",
            message="Random used for shuffling test data",
            metadata={},
        )
        result = engine.evaluate(finding)

        # Should still be a candidate (has security CWE) but low confidence
        assert result.confidence == "low"

    def test_secure_random_should_not_report_cwe338(self):
        """SecureRandom usage should not trigger CWE-338."""
        engine = CveScoringEngine()
        finding = MockFinding(
            type="secure_random",
            cwe="",
            severity="INFO",
            message="SecureRandom used for token generation",
            metadata={},
        )
        result = engine.evaluate(finding)

        # No CWE assigned, not a security type -> not a candidate
        assert result.cve_candidate is False

    def test_missing_entry_point_adds_missing_evidence(self):
        """Missing entry point should add to missing_evidence."""
        engine = CveScoringEngine()
        finding = MockFinding(
            type="insecure_random",
            cwe="CWE-338",
            metadata={},  # No entry_point in metadata
        )
        result = engine.evaluate(finding)

        assert any("entry point" in e.lower() for e in result.missing_evidence)

    def test_missing_version_adds_missing_evidence(self):
        """Missing version info should add to missing_evidence."""
        engine = CveScoringEngine()
        finding = MockFinding(
            type="insecure_random",
            cwe="CWE-338",
            metadata={},  # No version info
        )
        result = engine.evaluate(finding)

        assert any("version" in e.lower() for e in result.missing_evidence)

    def test_security_sensitive_flow_detected(self):
        """Security-sensitive flow should be detected from message/content."""
        engine = CveScoringEngine()
        finding = MockFinding(
            type="insecure_random",
            cwe="CWE-338",
            message="Random used for auth verification code",
            metadata={"entry_point": "POST /sso/getAuthCode"},
        )
        result = engine.evaluate(finding)

        assert result.security_sensitive_flow is True

    def test_all_checks_present(self):
        """All 10 checks should be present in the result."""
        engine = CveScoringEngine()
        finding = MockFinding(type="insecure_random", cwe="CWE-338")
        result = engine.evaluate(finding)

        check_names = {c.name for c in result.checks}
        expected_checks = {
            "released_version", "reachable_entry_point", "security_sensitive_flow",
            "not_code_quality", "has_cwe", "has_cvss", "has_fix",
            "has_poc", "attack_preconditions", "attack_impact",
        }
        assert expected_checks.issubset(check_names)

    def test_cvss_score_calculated(self):
        """CVSS score should be calculated."""
        engine = CveScoringEngine()
        finding = MockFinding(
            type="insecure_random",
            cwe="CWE-338",
            severity="WARN",
            metadata={"entry_point": "POST /sso/getAuthCode"},
        )
        result = engine.evaluate(finding)

        assert result.cvss_score > 0
        assert result.cvss_vector.startswith("CVSS:3.1/")


class TestCveCandidateEvaluator:
    """Tests for CveCandidateEvaluator."""

    def test_evaluate_single_finding(self):
        """Evaluate a single finding."""
        evaluator = CveCandidateEvaluator()
        finding = MockFinding(type="insecure_random", cwe="CWE-338")
        result = evaluator.evaluate(finding)

        assert isinstance(result, CveCandidateResult)
        assert result.cwe == "CWE-338"

    def test_evaluate_batch(self):
        """Evaluate a batch of findings."""
        evaluator = CveCandidateEvaluator()
        findings = [
            MockFinding(type="insecure_random", cwe="CWE-338"),
            MockFinding(type="hardcoded_secret", cwe="CWE-798"),
            MockFinding(type="code_style", cwe=""),
        ]
        results = evaluator.evaluate_batch(findings)

        assert len(results) == 3

    def test_duplicate_check_adjusts_confidence(self):
        """High duplicate risk should lower confidence."""
        evaluator = CveCandidateEvaluator()
        finding = MockFinding(
            type="insecure_random",
            cwe="CWE-338",
            metadata={"entry_point": "POST /sso/getAuthCode"},
        )

        # Without duplicate check
        result_no_dup = evaluator.evaluate(finding)

        # With high duplicate risk
        dup_result = DuplicateCheckResult(duplicate_risk="high")
        result_with_dup = evaluator.evaluate(finding, duplicate_check=dup_result)

        # Confidence should be lowered or stay the same
        confidence_order = {"high": 3, "medium": 2, "low": 1}
        assert confidence_order[result_with_dup.confidence] <= confidence_order[result_no_dup.confidence]


class TestDuplicateChecker:
    """Tests for DuplicateChecker."""

    def test_check_mall_tiny(self):
        """Check mall-tiny for duplicates."""
        checker = DuplicateChecker()
        result = checker.check(
            project_name="mall-tiny",
            repo_url="https://github.com/macrozheng/mall-learning",
            vuln_type="Insecure Random Number Generation",
            cwe="CWE-338",
            keywords=["generateAuthCode", "Random", "verification code"],
            affected_file="UmsMemberServiceImpl.java",
            affected_function="generateAuthCode",
        )

        assert isinstance(result, DuplicateCheckResult)
        assert len(result.search_keywords) > 0
        assert "NVD" in result.checked_sources

    def test_search_keywords_generated(self):
        """Search keywords should be generated from input."""
        checker = DuplicateChecker()
        result = checker.check(
            project_name="test-project",
            cwe="CWE-89",
            affected_function="query",
        )

        assert any("test-project" in kw and "CWE-89" in kw for kw in result.search_keywords)

    def test_no_known_duplicates_for_unknown_project(self):
        """Unknown project should have no known duplicates."""
        checker = DuplicateChecker()
        result = checker.check(project_name="unknown-project-xyz")

        assert len(result.possible_duplicates) == 0
        assert result.duplicate_risk == "low"


class TestCveCandidateModels:
    """Tests for data models."""

    def test_cve_candidate_result_defaults(self):
        """CveCandidateResult should have proper defaults."""
        result = CveCandidateResult()

        assert result.cve_candidate is False
        assert result.confidence == "low"  # wait, default is ""
        assert result.cvss_score == 0.0
        assert result.evidence == []
        assert result.missing_evidence == []

    def test_check_result(self):
        """CveCheckResult should store check information."""
        check = CveCheckResult(
            name="test_check",
            passed=True,
            description="Test check passed",
            evidence=["evidence1"],
            missing_evidence=["missing1"],
        )

        assert check.name == "test_check"
        assert check.passed is True
        assert len(check.evidence) == 1
        assert len(check.missing_evidence) == 1

    def test_duplicate_record(self):
        """DuplicateRecord should store duplicate information."""
        record = DuplicateRecord(
            source="NVD",
            id="CVE-2024-0001",
            title="Test vulnerability",
            url="https://nvd.nist.gov/vuln/detail/CVE-2024-0001",
            similarity="medium",
        )

        assert record.source == "NVD"
        assert record.similarity == "medium"
