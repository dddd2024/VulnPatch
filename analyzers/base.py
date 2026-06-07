"""
Base analyzer interface for all static analysis engines.

All analyzers must inherit from BaseAnalyzer and implement the analyze method.
"""

from abc import ABC, abstractmethod
from audit_core.models import CodeUnit, RawFinding


class BaseAnalyzer(ABC):
    """
    Abstract base class for all analyzers.
    
    Analyzers perform static analysis on code units and produce RawFinding objects.
    They do NOT call LLMs directly - that is the responsibility of Agents.
    
    Attributes:
        name: Unique name of the analyzer
        supported_languages: List of languages this analyzer supports
    """
    
    name: str = "base"
    supported_languages: list[str] = []
    
    @abstractmethod
    def analyze(self, code_units: list[CodeUnit]) -> list[RawFinding]:
        """
        Analyze code units and return findings.
        
        Args:
            code_units: List of code units to analyze
            
        Returns:
            List of RawFinding objects representing detected vulnerabilities
        """
        pass
    
    def supports_language(self, language: str) -> bool:
        """
        Check if this analyzer supports a given language.
        
        Args:
            language: Programming language to check
            
        Returns:
            True if the language is supported
        """
        return language.lower() in [lang.lower() for lang in self.supported_languages]
