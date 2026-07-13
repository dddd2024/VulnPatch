"""
Register built-in analyzers into the registry.

Each language sub-module's register.py provides a register_analyzers() function
that registers its analyzers. This module aggregates them all.
"""

from __future__ import annotations

from analyzers.base import BaseAnalyzer
from audit_core.registry import AnalyzerRegistry


def register_builtin_analyzers(registry: AnalyzerRegistry) -> None:
    """
    Register all built-in analyzers.

    Args:
        registry: The AnalyzerRegistry to register analyzers into.
    """
    # Pattern analyzer (通用，支持多语言)
    try:
        from analyzers.pattern_analyzer import PatternAnalyzer
        registry.register(PatternAnalyzer())
    except Exception as e:
        import logging
        logging.getLogger(__name__).warning("Failed to register PatternAnalyzer: %s", e)

    # C/C++ analyzers
    try:
        from analyzers.c_cpp.register import register_analyzers as register_c_cpp
        register_c_cpp(registry)
    except Exception:
        pass

    # Java analyzers
    try:
        from analyzers.java.register import register_analyzers as register_java
        register_java(registry)
    except Exception:
        pass

    # JavaScript analyzers
    try:
        from analyzers.javascript.register import register_analyzers as register_js
        register_js(registry)
    except Exception:
        pass

    # External analyzers
    try:
        from analyzers.external.register import register_analyzers as register_external
        register_external(registry)
    except Exception:
        pass
