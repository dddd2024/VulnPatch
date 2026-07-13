"""
C/C++ analyzers registration.

Registers all C/C++ analyzers (CPatternAnalyzer)
into the provided AnalyzerRegistry.
"""

from __future__ import annotations

from audit_core.registry import AnalyzerRegistry


def register_analyzers(registry: AnalyzerRegistry) -> None:
    """
    Register C/C++ analyzers into the given registry.

    Args:
        registry: The AnalyzerRegistry instance to register analyzers into.
    """
    from analyzers.c_cpp.c_pattern_analyzer import CPatternAnalyzer

    registry.register(CPatternAnalyzer())
