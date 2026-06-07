"""
AST-based analyzer for detecting vulnerabilities.

Uses Abstract Syntax Tree analysis to detect security issues.
Currently a skeleton implementation - full AST analysis to be added later.
"""

from audit_core.models import CodeUnit, RawFinding
from analyzers.base import BaseAnalyzer


class ASTAnalyzer(BaseAnalyzer):
    """
    Analyzer that uses AST parsing to detect vulnerabilities.
    
    This is currently a skeleton implementation that returns empty results.
    Full AST-based detection will be implemented in a future stage.
    
    Note: This analyzer does NOT call LLMs. It only performs static AST analysis.
    """
    
    name = "ast"
    supported_languages = ["python"]  # Can be extended to other languages
    
    def analyze(self, code_units: list[CodeUnit]) -> list[RawFinding]:
        """
        Analyze code units using AST parsing.
        
        Args:
            code_units: List of code units to analyze
            
        Returns:
            List of RawFinding objects (currently empty)
            
        TODO: Implement full AST-based vulnerability detection
        """
        findings = []
        
        for unit in code_units:
            # Skip non-Python files
            if unit.language != "python":
                continue
            
            # TODO: Implement AST analysis
            # For now, return empty list as placeholder
            pass
        
        return findings
    
    def _analyze_python_ast(self, unit: CodeUnit) -> list[RawFinding]:
        """
        Analyze Python code using AST.
        
        Args:
            unit: Code unit to analyze
            
        Returns:
            List of findings
            
        TODO: Implement Python AST analysis
        """
        # Placeholder for future implementation
        return []
