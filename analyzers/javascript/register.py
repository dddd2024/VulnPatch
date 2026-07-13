"""
JavaScript/TypeScript analyzers registration.

Registers all JavaScript/TypeScript analyzers (JSPatternAnalyzer)
into the provided AnalyzerRegistry.
"""

from __future__ import annotations

from audit_core.registry import AnalyzerRegistry


def register_analyzers(registry: AnalyzerRegistry) -> None:
    """
    Register JavaScript/TypeScript analyzers into the given registry.

    Args:
        registry: The AnalyzerRegistry instance to register analyzers into.
    """
    from analyzers.javascript.js_pattern_analyzer import JSPatternAnalyzer

    registry.register(JSPatternAnalyzer())
