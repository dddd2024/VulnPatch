"""Canonical JavaScript analyzer entry point.

The implementation is retained in the historical backup module for backward
compatibility; this module restores the public import path expected by the
registry and external integrations.
"""
from analyzers.javascript.js_pattern_analyzer_backup import JSPatternAnalyzer

__all__ = ["JSPatternAnalyzer"]
