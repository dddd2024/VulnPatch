"""
Registration entry point for supply chain analyzer.
"""

import logging

from audit_core.registry import AnalyzerRegistry

logger = logging.getLogger(__name__)


def register_analyzers(registry: AnalyzerRegistry) -> None:
    """Register the supply chain analyzer into the registry.

    Args:
        registry: The AnalyzerRegistry instance to populate.
    """
    from supply_chain.analyzer import SupplyChainAnalyzer

    analyzer = SupplyChainAnalyzer()
    registry.register(analyzer)

    if analyzer.is_available():
        logger.info("Registered SupplyChain analyzer (enabled)")
    else:
        logger.info("Registered SupplyChain analyzer (disabled)")
