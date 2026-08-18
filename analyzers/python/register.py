"""Registration hook for PythonAnalyzer."""
from audit_core.registry import AnalyzerRegistry

def register_analyzers(registry: AnalyzerRegistry) -> None:
    from analyzers.python.python_analyzer import PythonAnalyzer
    registry.register(PythonAnalyzer())
