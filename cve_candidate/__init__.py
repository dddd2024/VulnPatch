"""
CVE Candidate evaluation module for VulnPatch.

Provides automated assessment of whether a vulnerability finding
meets CVE submission criteria, including evidence chain analysis,
confidence scoring, and gap identification.
"""

from cve_candidate.evaluator import CveCandidateEvaluator
from cve_candidate.models import CveCandidateResult, CveCheckResult
from cve_candidate.scoring import CveScoringEngine

__all__ = [
    "CveCandidateEvaluator",
    "CveCandidateResult",
    "CveCheckResult",
    "CveScoringEngine",
]
