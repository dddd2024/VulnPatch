"""
Duplicate checking module for VulnPatch CVE candidates.

Provides semi-automated duplicate detection against public vulnerability
databases (NVD, GitHub Advisory Database, MITRE CVE) to avoid
submitting duplicate CVE reports.
"""

from duplicate_check.checker import DuplicateChecker
from duplicate_check.models import DuplicateCheckResult, DuplicateRecord

__all__ = [
    "DuplicateChecker",
    "DuplicateCheckResult",
    "DuplicateRecord",
]
