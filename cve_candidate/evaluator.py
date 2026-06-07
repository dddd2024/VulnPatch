"""
CVE Candidate evaluator - main entry point for CVE candidacy assessment.

Orchestrates scoring, duplicate checking, and evidence chain building
to produce a comprehensive CveCandidateResult.
"""

import logging
from typing import Any, Optional

from cve_candidate.models import CveCandidateResult, DuplicateCheckResult
from cve_candidate.scoring import CveScoringEngine

logger = logging.getLogger(__name__)


class CveCandidateEvaluator:
    """
    Evaluates vulnerability findings for CVE candidacy.

    Usage:
        from cve_candidate.evaluator import CveCandidateEvaluator

        evaluator = CveCandidateEvaluator()
        result = evaluator.evaluate(finding, code_units=code_units)

        if result.cve_candidate:
            print(f"CVE candidate (confidence={result.confidence})")
            print(f"Missing evidence: {result.missing_evidence}")
    """

    def __init__(self) -> None:
        self._scoring_engine = CveScoringEngine()

    def evaluate(
        self,
        finding: Any,
        code_units: list[Any] | None = None,
        duplicate_check: Optional[DuplicateCheckResult] = None,
    ) -> CveCandidateResult:
        """
        Evaluate a finding for CVE candidacy.

        Args:
            finding: A RawFinding or similar object
            code_units: Optional code units for context
            duplicate_check: Optional pre-computed duplicate check result

        Returns:
            CveCandidateResult with full assessment
        """
        # Run scoring engine
        result = self._scoring_engine.evaluate(finding, code_units)

        # Attach duplicate check if provided
        if duplicate_check is not None:
            result.duplicate_check = duplicate_check

            # Adjust confidence based on duplicate risk
            if duplicate_check.duplicate_risk == "high":
                if result.confidence == "high":
                    result.confidence = "medium"
                    result.reason += " Duplicate risk is high."
                elif result.confidence == "medium":
                    result.confidence = "low"
                    result.reason += " Duplicate risk is high."
            elif duplicate_check.duplicate_risk == "medium":
                if result.confidence == "high":
                    result.confidence = "medium"
                    result.reason += " Possible duplicate exists."

        return result

    def evaluate_batch(
        self,
        findings: list[Any],
        code_units: list[Any] | None = None,
    ) -> list[CveCandidateResult]:
        """
        Evaluate multiple findings for CVE candidacy.

        Args:
            findings: List of RawFinding or similar objects
            code_units: Optional code units for context

        Returns:
            List of CveCandidateResult
        """
        results = []
        for finding in findings:
            result = self.evaluate(finding, code_units)
            results.append(result)
        return results
