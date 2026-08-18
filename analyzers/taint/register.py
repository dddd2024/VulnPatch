"""Registration hook for TaintAnalyzer."""
from audit_core.registry import AnalyzerRegistry

def register_analyzers(registry: AnalyzerRegistry) -> None:
    from analyzers.taint.taint_engine import TaintAnalyzer
    registry.register(TaintAnalyzer())
