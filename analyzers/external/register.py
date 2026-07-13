"""
Registration entry point for external tool analyzers.

Registers Semgrep, Bandit, and ESLint Security analyzers into the registry.
Each tool is only registered if it is available on the system.
"""

import logging

from audit_core.registry import AnalyzerRegistry

logger = logging.getLogger(__name__)


def register_analyzers(registry: AnalyzerRegistry) -> None:
    """
    Register all external tool analyzers.

    Each analyzer checks tool availability at registration time.
    If a tool is not installed, it is still registered but will
    gracefully skip during analysis (no crash).

    Args:
        registry: The AnalyzerRegistry instance to populate.
    """
    from analyzers.external.semgrep_analyzer import SemgrepAnalyzer
    from analyzers.external.bandit_analyzer import BanditAnalyzer
    from analyzers.external.eslint_analyzer import ESLintSecurityAnalyzer

    # Semgrep - multi-language static analysis
    semgrep = SemgrepAnalyzer()
    registry.register(semgrep)
    if semgrep.is_available():
        logger.info("Registered Semgrep analyzer (available)")
    else:
        logger.info("Registered Semgrep analyzer (not installed, will skip)")

    # Bandit - Python security linter
    bandit = BanditAnalyzer()
    registry.register(bandit)
    if bandit.is_available():
        logger.info("Registered Bandit analyzer (available)")
    else:
        logger.info("Registered Bandit analyzer (not installed, will skip)")

    # ESLint Security - JavaScript/TypeScript security rules
    eslint = ESLintSecurityAnalyzer()
    registry.register(eslint)
    if eslint.is_available():
        logger.info("Registered ESLint Security analyzer (available)")
    else:
        logger.info("Registered ESLint Security analyzer (not installed, will skip)")
