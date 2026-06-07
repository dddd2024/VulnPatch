"""
Tests for audit_core module.

Tests the core data models and orchestration logic.
"""

import pytest
from audit_core.models import CodeUnit, RawFinding, AuditResult, AuditSummary
from audit_core.registry import AnalyzerRegistry, build_default_registry
from audit_core.result_merger import merge_findings
from audit_core.scoring import score_finding
from audit_core.orchestrator import AuditOrchestrator
from analyzers.pattern_analyzer import PatternAnalyzer


class TestCodeUnit:
    """Tests for CodeUnit model."""
    
    def test_create_code_unit(self):
        """Test creating a CodeUnit."""
        unit = CodeUnit(
            path="test.py",
            language="python",
            content="def hello(): pass",
            start_line=1,
            end_line=3
        )
        assert unit.path == "test.py"
        assert unit.language == "python"
        assert unit.content == "def hello(): pass"
        assert unit.start_line == 1
        assert unit.end_line == 3
        assert unit.id is not None


class TestRawFinding:
    """Tests for RawFinding model."""
    
    def test_create_finding(self):
        """Test creating a RawFinding."""
        finding = RawFinding(
            rule_id="TEST_001",
            type="SQL Injection",
            severity="ERROR",
            confidence="high",
            file_path="test.py",
            start_line=10,
            message="Possible SQL injection",
            engine="pattern"
        )
        assert finding.rule_id == "TEST_001"
        assert finding.type == "SQL Injection"
        assert finding.severity == "ERROR"
        assert finding.confidence == "high"
        assert finding.id is not None


class TestAnalyzerRegistry:
    """Tests for AnalyzerRegistry."""
    
    def test_register_analyzer(self):
        """Test registering an analyzer."""
        registry = AnalyzerRegistry()
        analyzer = PatternAnalyzer()
        registry.register(analyzer)
        
        assert registry.get("pattern") is not None
        assert len(registry.get_analyzers()) == 1
    
    def test_get_analyzers_for_language(self):
        """Test getting analyzers for a specific language."""
        registry = AnalyzerRegistry()
        analyzer = PatternAnalyzer()
        registry.register(analyzer)
        
        python_analyzers = registry.get_analyzers_for_language("python")
        assert len(python_analyzers) == 1
        
        rust_analyzers = registry.get_analyzers_for_language("rust")
        assert len(rust_analyzers) == 0


class TestResultMerger:
    """Tests for result merger."""
    
    def test_merge_duplicate_findings(self):
        """Test merging duplicate findings."""
        finding1 = RawFinding(
            rule_id="SQL_001",
            type="SQL Injection",
            severity="ERROR",
            confidence="high",
            file_path="test.py",
            start_line=10,
            message="SQL injection",
            engine="pattern"
        )
        finding2 = RawFinding(
            rule_id="SQL_001",
            type="SQL Injection",
            severity="WARN",
            confidence="medium",
            file_path="test.py",
            start_line=10,
            message="SQL injection",
            engine="ast"
        )
        
        merged = merge_findings([finding1, finding2])
        assert len(merged) == 1
        assert merged[0].severity == "ERROR"  # Higher severity kept
        assert merged[0].confidence == "high"  # Higher confidence kept


class TestScoring:
    """Tests for scoring module."""
    
    def test_score_finding(self):
        """Test scoring a finding."""
        finding = RawFinding(
            rule_id="TEST_001",
            type="SQL Injection",
            severity="ERROR",
            confidence="high",
            file_path="test.py",
            start_line=10,
            message="SQL injection",
            engine="pattern"
        )
        
        score = score_finding(finding)
        assert "risk_score" in score
        assert "severity_score" in score
        assert "confidence_score" in score
        assert score["risk_score"] > 0


class TestAuditOrchestrator:
    """Tests for AuditOrchestrator."""
    
    def test_scan_code(self):
        """Test scanning a code snippet."""
        orchestrator = AuditOrchestrator()
        
        code = """
def get_user(user_id):
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
"""
        result = orchestrator.scan_code(code, language="python")
        
        assert isinstance(result, AuditResult)
        assert result.summary.total_code_units == 1
        assert result.summary.total_findings >= 0
    
    def test_scan_empty_code(self):
        """Test scanning empty code."""
        orchestrator = AuditOrchestrator()
        result = orchestrator.scan_code("", language="python")
        
        assert isinstance(result, AuditResult)
        assert result.summary.total_code_units == 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
