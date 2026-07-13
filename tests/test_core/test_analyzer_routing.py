"""
Tests for analyzer language-based routing in AuditOrchestrator.

These tests verify that:
1. Analyzers are routed by CodeUnit.language
2. Each analyzer only receives code_units of supported languages
3. Unknown language code_units are skipped
4. Analyzer failures don't crash the scan
5. Multiple languages are handled correctly
"""

import pytest
from unittest.mock import Mock, patch, MagicMock

from audit_core.orchestrator import AuditOrchestrator
from audit_core.models import CodeUnit, RawFinding, AuditResult
from audit_core.registry import AnalyzerRegistry
from analyzers.base import BaseAnalyzer


class MockPythonAnalyzer(BaseAnalyzer):
    """Mock analyzer that only supports Python."""

    name = "mock_python"
    supported_languages = ["python"]

    def analyze(self, code_units):
        return [
            RawFinding(
                rule_id="PYTHON-001",
                type="test_python",
                severity="INFO",
                file_path=unit.path,
                start_line=1,
                message="Python finding",
                engine="mock_python"
            )
            for unit in code_units
        ]


class MockJavaScriptAnalyzer(BaseAnalyzer):
    """Mock analyzer that only supports JavaScript."""

    name = "mock_javascript"
    supported_languages = ["javascript", "js"]

    def analyze(self, code_units):
        return [
            RawFinding(
                rule_id="JS-001",
                type="test_js",
                severity="INFO",
                file_path=unit.path,
                start_line=1,
                message="JavaScript finding",
                engine="mock_javascript"
            )
            for unit in code_units
        ]


class MockJavaAnalyzer(BaseAnalyzer):
    """Mock analyzer that only supports Java."""

    name = "mock_java"
    supported_languages = ["java"]

    def analyze(self, code_units):
        return [
            RawFinding(
                rule_id="JAVA-001",
                type="test_java",
                severity="INFO",
                file_path=unit.path,
                start_line=1,
                message="Java finding",
                engine="mock_java"
            )
            for unit in code_units
        ]


class FailingAnalyzer(BaseAnalyzer):
    """Mock analyzer that always fails."""

    name = "failing_analyzer"
    supported_languages = ["python"]

    def analyze(self, code_units):
        raise RuntimeError("Analyzer intentionally failed")


class TestGroupCodeUnitsByLanguage:
    """Tests for _group_code_units_by_language method."""

    def test_groups_python_code_units(self):
        """Test that Python code units are grouped correctly."""
        orchestrator = AuditOrchestrator()

        code_units = [
            CodeUnit(path="a.py", language="python", content="code1"),
            CodeUnit(path="b.py", language="python", content="code2"),
        ]

        groups = orchestrator._group_code_units_by_language(code_units)

        assert "python" in groups
        assert len(groups["python"]) == 2
        assert groups["python"][0].path == "a.py"
        assert groups["python"][1].path == "b.py"

    def test_groups_multiple_languages(self):
        """Test that multiple languages are grouped separately."""
        orchestrator = AuditOrchestrator()

        code_units = [
            CodeUnit(path="a.py", language="python", content="code"),
            CodeUnit(path="b.js", language="javascript", content="code"),
            CodeUnit(path="c.java", language="java", content="code"),
        ]

        groups = orchestrator._group_code_units_by_language(code_units)

        assert len(groups) == 3
        assert "python" in groups
        assert "javascript" in groups
        assert "java" in groups
        assert len(groups["python"]) == 1
        assert len(groups["javascript"]) == 1
        assert len(groups["java"]) == 1

    def test_groups_unknown_language(self):
        """Test that unknown language is grouped as 'unknown'."""
        orchestrator = AuditOrchestrator()

        code_units = [
            CodeUnit(path="a.txt", language="unknown", content="text"),
            CodeUnit(path="b.xyz", language="unknown", content="xyz"),
        ]

        groups = orchestrator._group_code_units_by_language(code_units)

        assert "unknown" in groups
        assert len(groups["unknown"]) == 2

    def test_normalizes_language_case(self):
        """Test that language names are normalized to lowercase."""
        orchestrator = AuditOrchestrator()

        code_units = [
            CodeUnit(path="a.py", language="Python", content="code"),
            CodeUnit(path="b.py", language="PYTHON", content="code"),
        ]

        groups = orchestrator._group_code_units_by_language(code_units)

        assert "python" in groups  # lowercase
        assert len(groups["python"]) == 2


class TestRunAnalyzersLanguageRouting:
    """Tests for _run_analyzers language routing."""

    def test_python_analyzer_only_receives_python_units(self):
        """Test that Python analyzer only receives Python code units."""
        registry = AnalyzerRegistry()
        registry.register(MockPythonAnalyzer())
        registry.register(MockJavaScriptAnalyzer())

        orchestrator = AuditOrchestrator(registry=registry, use_pipeline=False)

        code_units = [
            CodeUnit(path="a.py", language="python", content="code"),
            CodeUnit(path="b.js", language="javascript", content="code"),
        ]

        findings, metadata = orchestrator._run_analyzers(code_units)

        # Only Python findings should be present
        python_findings = [f for f in findings if f.engine == "mock_python"]
        js_findings = [f for f in findings if f.engine == "mock_javascript"]

        assert len(python_findings) == 1
        assert len(js_findings) == 1

        # Verify analyzer runs
        assert len(metadata["analyzer_runs"]) == 2

    def test_javascript_analyzer_only_receives_javascript_units(self):
        """Test that JavaScript analyzer only receives JavaScript code units."""
        registry = AnalyzerRegistry()
        registry.register(MockJavaScriptAnalyzer())
        registry.register(MockPythonAnalyzer())

        orchestrator = AuditOrchestrator(registry=registry)

        code_units = [
            CodeUnit(path="a.js", language="javascript", content="code"),
            CodeUnit(path="b.py", language="python", content="code"),
        ]

        findings, metadata = orchestrator._run_analyzers(code_units)

        js_findings = [f for f in findings if f.engine == "mock_javascript"]
        python_findings = [f for f in findings if f.engine == "mock_python"]

        assert len(js_findings) == 1
        assert len(python_findings) == 1

    def test_unknown_language_is_skipped(self):
        """Test that unknown language code units are skipped."""
        registry = AnalyzerRegistry()
        registry.register(MockPythonAnalyzer())

        orchestrator = AuditOrchestrator(registry=registry, use_pipeline=False)

        code_units = [
            CodeUnit(path="a.py", language="python", content="code"),
            CodeUnit(path="b.txt", language="unknown", content="text"),
        ]

        findings, metadata = orchestrator._run_analyzers(code_units)

        # Only Python finding should be present
        assert len(findings) == 1
        assert findings[0].engine == "mock_python"

        # Unknown language should be recorded as skipped
        assert len(metadata["skipped_languages"]) == 1
        assert metadata["skipped_languages"][0]["language"] == "unknown"

    def test_no_analyzer_for_language_is_skipped(self):
        """Test that languages without analyzers are skipped."""
        registry = AnalyzerRegistry()
        registry.register(MockPythonAnalyzer())

        orchestrator = AuditOrchestrator(registry=registry)

        code_units = [
            CodeUnit(path="a.py", language="python", content="code"),
            CodeUnit(path="b.rs", language="rust", content="code"),  # No Rust analyzer
        ]

        findings, metadata = orchestrator._run_analyzers(code_units)

        # Only Python finding should be present
        assert len(findings) == 1

        # Rust should be recorded as skipped
        assert len(metadata["skipped_languages"]) == 1
        assert metadata["skipped_languages"][0]["language"] == "rust"

    def test_multiple_languages_routed_correctly(self):
        """Test that multiple languages are routed to correct analyzers."""
        registry = AnalyzerRegistry()
        registry.register(MockPythonAnalyzer())
        registry.register(MockJavaScriptAnalyzer())
        registry.register(MockJavaAnalyzer())

        orchestrator = AuditOrchestrator(registry=registry)

        code_units = [
            CodeUnit(path="a.py", language="python", content="code"),
            CodeUnit(path="b.js", language="javascript", content="code"),
            CodeUnit(path="c.java", language="java", content="code"),
        ]

        findings, metadata = orchestrator._run_analyzers(code_units)

        # Each language should have one finding
        assert len(findings) == 3

        python_findings = [f for f in findings if f.engine == "mock_python"]
        js_findings = [f for f in findings if f.engine == "mock_javascript"]
        java_findings = [f for f in findings if f.engine == "mock_java"]

        assert len(python_findings) == 1
        assert len(js_findings) == 1
        assert len(java_findings) == 1


class TestAnalyzerErrorHandling:
    """Tests for analyzer error handling."""

    def test_analyzer_failure_does_not_crash_scan(self):
        """Test that analyzer failure doesn't crash the scan."""
        registry = AnalyzerRegistry()
        registry.register(FailingAnalyzer())
        registry.register(MockJavaScriptAnalyzer())

        orchestrator = AuditOrchestrator(registry=registry)

        code_units = [
            CodeUnit(path="a.py", language="python", content="code"),
            CodeUnit(path="b.js", language="javascript", content="code"),
        ]

        findings, metadata = orchestrator._run_analyzers(code_units)

        # JavaScript analyzer should still produce findings
        assert len(findings) == 1
        assert findings[0].engine == "mock_javascript"

        # Python analyzer failure should be recorded
        assert len(metadata["analyzer_errors"]) == 1
        assert metadata["analyzer_errors"][0]["analyzer_name"] == "failing_analyzer"

    def test_analyzer_error_metadata_contains_details(self):
        """Test that analyzer error metadata contains error details."""
        registry = AnalyzerRegistry()
        registry.register(FailingAnalyzer())

        orchestrator = AuditOrchestrator(registry=registry)

        code_units = [
            CodeUnit(path="a.py", language="python", content="code"),
        ]

        findings, metadata = orchestrator._run_analyzers(code_units)

        assert len(metadata["analyzer_errors"]) == 1
        error = metadata["analyzer_errors"][0]

        assert error["analyzer_name"] == "failing_analyzer"
        assert error["language"] == "python"
        assert error["error_type"] == "RuntimeError"
        assert "intentionally failed" in error["error_message"]

    def test_multiple_analyzer_failures_are_all_recorded(self):
        """Test that multiple analyzer failures are all recorded."""
        class FailingJSAnalyzer(BaseAnalyzer):
            name = "failing_js"
            supported_languages = ["javascript"]

            def analyze(self, code_units):
                raise ValueError("JS analyzer failed")

        registry = AnalyzerRegistry()
        registry.register(FailingAnalyzer())
        registry.register(FailingJSAnalyzer())

        orchestrator = AuditOrchestrator(registry=registry)

        code_units = [
            CodeUnit(path="a.py", language="python", content="code"),
            CodeUnit(path="b.js", language="javascript", content="code"),
        ]

        findings, metadata = orchestrator._run_analyzers(code_units)

        # Both failures should be recorded
        assert len(metadata["analyzer_errors"]) == 2

        error_names = [e["analyzer_name"] for e in metadata["analyzer_errors"]]
        assert "failing_analyzer" in error_names
        assert "failing_js" in error_names


class TestScanCodeIntegration:
    """Integration tests for scan_code with language routing."""

    def test_scan_code_python_routes_correctly(self):
        """Test that scan_code with Python code routes correctly."""
        registry = AnalyzerRegistry()
        registry.register(MockPythonAnalyzer())

        orchestrator = AuditOrchestrator(registry=registry, use_pipeline=False)

        code = "print('hello')"
        result = orchestrator.scan_code(code, language="python")

        assert isinstance(result, AuditResult)
        assert result.summary.total_code_units >= 1

        # Should have Python findings
        python_findings = [f for f in result.findings if f.engine == "mock_python"]
        assert len(python_findings) >= 1

    def test_scan_code_with_unknown_language_does_not_crash(self):
        """Test that scan_code with unknown language doesn't crash."""
        registry = AnalyzerRegistry()
        registry.register(MockPythonAnalyzer())

        orchestrator = AuditOrchestrator(registry=registry)

        code = "some random text"
        result = orchestrator.scan_code(code, language=None)

        assert isinstance(result, AuditResult)
        # Should not crash even with unknown language

    def test_analyzer_metadata_in_audit_result(self):
        """Test that analyzer metadata is included in AuditResult."""
        registry = AnalyzerRegistry()
        registry.register(MockPythonAnalyzer())

        orchestrator = AuditOrchestrator(registry=registry)

        code = "print('hello')"
        result = orchestrator.scan_code(code, language="python")

        assert result.metadata is not None
        assert "analyzer_info" in result.metadata

        analyzer_info = result.metadata["analyzer_info"]
        assert "analyzer_runs" in analyzer_info
        assert "analyzer_errors" in analyzer_info
        assert "skipped_languages" in analyzer_info


class TestAnalyzerRegistryMethods:
    """Tests for AnalyzerRegistry methods used by orchestrator."""

    def test_get_analyzers_for_language_returns_correct_analyzers(self):
        """Test that get_analyzers_for_language returns correct analyzers."""
        registry = AnalyzerRegistry()
        registry.register(MockPythonAnalyzer())
        registry.register(MockJavaScriptAnalyzer())

        python_analyzers = registry.get_analyzers_for_language("python")
        js_analyzers = registry.get_analyzers_for_language("javascript")

        assert len(python_analyzers) == 1
        assert python_analyzers[0].name == "mock_python"

        assert len(js_analyzers) == 1
        assert js_analyzers[0].name == "mock_javascript"

    def test_get_analyzers_for_language_case_insensitive(self):
        """Test that get_analyzers_for_language is case insensitive."""
        registry = AnalyzerRegistry()
        registry.register(MockPythonAnalyzer())

        analyzers_lower = registry.get_analyzers_for_language("python")
        analyzers_upper = registry.get_analyzers_for_language("PYTHON")
        analyzers_mixed = registry.get_analyzers_for_language("Python")

        assert len(analyzers_lower) == 1
        assert len(analyzers_upper) == 1
        assert len(analyzers_mixed) == 1

    def test_get_analyzers_for_language_returns_empty_for_unknown(self):
        """Test that get_analyzers_for_language returns empty for unknown."""
        registry = AnalyzerRegistry()
        registry.register(MockPythonAnalyzer())

        unknown_analyzers = registry.get_analyzers_for_language("unknown")
        rust_analyzers = registry.get_analyzers_for_language("rust")

        assert len(unknown_analyzers) == 0
        assert len(rust_analyzers) == 0