"""
Java analyzers registration.

Registers all Java analyzers (JavaPatternAnalyzer)
into the provided AnalyzerRegistry.
"""

from __future__ import annotations

from audit_core.registry import AnalyzerRegistry


def register_analyzers(registry: AnalyzerRegistry) -> None:
    """
    Register Java analyzers into the given registry.

    Args:
        registry: The AnalyzerRegistry instance to register analyzers into.
    """
    from analyzers.java.java_pattern_analyzer import JavaPatternAnalyzer

    registry.register(JavaPatternAnalyzer())
