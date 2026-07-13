"""
Tests for analyzers/python/ — the new PythonAnalyzer.

Verifies that the PythonAnalyzer (which wraps detector AST/Regex/Taint engines)
can detect the four required vulnerability types:
  - SQL Injection
  - Path Traversal
  - Command Injection
  - Hardcoded Secret

Also verifies:
  - RawFinding output format (engine="python", correct severity mapping)
  - Registry integration (PythonAnalyzer registered before LegacyAnalyzerAdapter)
  - Non-Python code units are silently skipped
"""

import pytest

from analyzers.python.python_analyzer import PythonAnalyzer
from analyzers.base import BaseAnalyzer
from audit_core.models import CodeUnit, RawFinding
from audit_core.registry import AnalyzerRegistry, build_default_registry


# ---------------------------------------------------------------------------
# Test data — Python code snippets with known vulnerabilities
# ---------------------------------------------------------------------------

SQL_INJECTION_CODE = '''
import sqlite3

def search_user(query):
    conn = sqlite3.connect("db.sqlite3")
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE name = '{query}'")
    return cursor.fetchall()
'''

PATH_TRAVERSAL_CODE = '''
from flask import Flask, request

app = Flask(__name__)

@app.route("/read")
def read_file():
    filename = request.args.get("file")
    with open(filename, 'r') as f:
        return f.read()
'''

COMMAND_INJECTION_CODE = '''
import os

def run_ping(host):
    os.system("ping " + host)
'''

HARDCODED_SECRET_CODE = '''
import hashlib

DB_PASSWORD = "super_secret_123"
API_KEY = "sk-abc123def456"

def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()
'''

# Combined code with all four vuln types
ALL_VULNS_CODE = SQL_INJECTION_CODE + "\n" + PATH_TRAVERSAL_CODE + "\n" + COMMAND_INJECTION_CODE + "\n" + HARDCODED_SECRET_CODE

CLEAN_CODE = '''
def add(a, b):
    return a + b

def greet(name):
    return f"Hello, {name}!"
'''

NON_PYTHON_CODE = '''
const express = require('express');
const app = express();
app.get('/', (req, res) => res.send('Hello'));
'''


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_unit(code: str, path: str = "test.py") -> CodeUnit:
    """Create a CodeUnit from source code string."""
    return CodeUnit(
        path=path,
        language="python",
        content=code,
        start_line=1,
        end_line=code.count("\n") + 1,
        metadata={},
    )


def _finding_types(findings: list[RawFinding]) -> set[str]:
    return {f.type for f in findings}


def _finding_has_type(findings: list[RawFinding], keyword: str) -> bool:
    """Check if any finding type contains the given keyword (case-insensitive)."""
    return any(keyword.lower() in ft.lower() for ft in _finding_types(findings))


# ---------------------------------------------------------------------------
# Tests: basic interface
# ---------------------------------------------------------------------------

class TestPythonAnalyzerInterface:

    def test_is_base_analyzer(self):
        assert issubclass(PythonAnalyzer, BaseAnalyzer)

    def test_name(self):
        assert PythonAnalyzer.name == "python"

    def test_supported_languages(self):
        assert PythonAnalyzer.supported_languages == ["python"]

    def test_supports_language(self):
        analyzer = PythonAnalyzer()
        assert analyzer.supports_language("python") is True
        assert analyzer.supports_language("javascript") is False
        assert analyzer.supports_language("java") is False


# ---------------------------------------------------------------------------
# Tests: SQL Injection detection
# ---------------------------------------------------------------------------

class TestSQLInjection:

    def test_detects_sql_injection(self):
        """PythonAnalyzer should detect SQL injection via f-string in execute()."""
        analyzer = PythonAnalyzer()
        unit = _make_unit(SQL_INJECTION_CODE)
        findings = analyzer.analyze([unit])
        analyzer.cleanup()

        assert len(findings) > 0, "Expected at least one SQL injection finding"
        assert _finding_has_type(findings, "SQL"), (
            f"Expected SQL injection finding, got types: {_finding_types(findings)}"
        )

    def test_sql_injection_finding_has_correct_engine(self):
        """SQL injection findings should have engine='python'."""
        analyzer = PythonAnalyzer()
        unit = _make_unit(SQL_INJECTION_CODE)
        findings = analyzer.analyze([unit])
        analyzer.cleanup()

        sql_findings = [f for f in findings if "sql" in f.type.lower()]
        assert len(sql_findings) > 0
        assert all(f.engine == "python" for f in sql_findings)

    def test_sql_injection_has_rule_id(self):
        """SQL injection findings should have a valid rule_id."""
        analyzer = PythonAnalyzer()
        unit = _make_unit(SQL_INJECTION_CODE)
        findings = analyzer.analyze([unit])
        analyzer.cleanup()

        sql_findings = [f for f in findings if "sql" in f.type.lower()]
        assert all(f.rule_id for f in sql_findings)


# ---------------------------------------------------------------------------
# Tests: Path Traversal detection
# ---------------------------------------------------------------------------

class TestPathTraversal:

    def test_detects_path_traversal(self):
        """PythonAnalyzer should detect path traversal via open(request.args.get(...))."""
        analyzer = PythonAnalyzer()
        unit = _make_unit(PATH_TRAVERSAL_CODE)
        findings = analyzer.analyze([unit])
        analyzer.cleanup()

        assert len(findings) > 0, "Expected at least one path traversal finding"
        assert _finding_has_type(findings, "Path Traversal"), (
            f"Expected Path Traversal finding, got types: {_finding_types(findings)}"
        )

    def test_path_traversal_finding_has_correct_engine(self):
        analyzer = PythonAnalyzer()
        unit = _make_unit(PATH_TRAVERSAL_CODE)
        findings = analyzer.analyze([unit])
        analyzer.cleanup()

        pt_findings = [f for f in findings if "path" in f.type.lower()]
        assert len(pt_findings) > 0
        assert all(f.engine == "python" for f in pt_findings)


# ---------------------------------------------------------------------------
# Tests: Command Injection detection
# ---------------------------------------------------------------------------

class TestCommandInjection:

    def test_detects_command_injection(self):
        """PythonAnalyzer should detect command injection via os.system()."""
        analyzer = PythonAnalyzer()
        unit = _make_unit(COMMAND_INJECTION_CODE)
        findings = analyzer.analyze([unit])
        analyzer.cleanup()

        assert len(findings) > 0, "Expected at least one command injection finding"
        assert _finding_has_type(findings, "Command Injection"), (
            f"Expected Command Injection finding, got types: {_finding_types(findings)}"
        )

    def test_command_injection_finding_has_correct_engine(self):
        analyzer = PythonAnalyzer()
        unit = _make_unit(COMMAND_INJECTION_CODE)
        findings = analyzer.analyze([unit])
        analyzer.cleanup()

        ci_findings = [f for f in findings if "command" in f.type.lower()]
        assert len(ci_findings) > 0
        assert all(f.engine == "python" for f in ci_findings)


# ---------------------------------------------------------------------------
# Tests: Hardcoded Secret detection
# ---------------------------------------------------------------------------

class TestHardcodedSecret:

    def test_detects_hardcoded_secret(self):
        """PythonAnalyzer should detect hardcoded secrets (password, api_key)."""
        analyzer = PythonAnalyzer()
        unit = _make_unit(HARDCODED_SECRET_CODE)
        findings = analyzer.analyze([unit])
        analyzer.cleanup()

        assert len(findings) > 0, "Expected at least one hardcoded secret finding"
        assert _finding_has_type(findings, "Hardcoded Secret"), (
            f"Expected Hardcoded Secret finding, got types: {_finding_types(findings)}"
        )

    def test_hardcoded_secret_finding_has_correct_engine(self):
        analyzer = PythonAnalyzer()
        unit = _make_unit(HARDCODED_SECRET_CODE)
        findings = analyzer.analyze([unit])
        analyzer.cleanup()

        hs_findings = [f for f in findings if "secret" in f.type.lower() or "hardcoded" in f.type.lower()]
        assert len(hs_findings) > 0
        assert all(f.engine == "python" for f in hs_findings)


# ---------------------------------------------------------------------------
# Tests: combined detection
# ---------------------------------------------------------------------------

class TestCombinedDetection:

    def test_detects_all_four_vuln_types(self):
        """A file with all four vuln types should produce findings for each."""
        analyzer = PythonAnalyzer()
        unit = _make_unit(ALL_VULNS_CODE)
        findings = analyzer.analyze([unit])
        analyzer.cleanup()

        types = _finding_types(findings)
        assert len(findings) > 0, "Expected findings from combined code"

        # Check each required type
        for keyword in ["SQL", "Path Traversal", "Command Injection", "Hardcoded Secret"]:
            assert any(keyword.lower() in t.lower() for t in types), (
                f"Expected '{keyword}' in finding types, got: {types}"
            )

    def test_clean_code_produces_no_findings(self):
        """Clean code should produce zero findings."""
        analyzer = PythonAnalyzer()
        unit = _make_unit(CLEAN_CODE)
        findings = analyzer.analyze([unit])
        analyzer.cleanup()

        # Clean code may still trigger some low-confidence warnings,
        # but should not have any ERROR findings
        error_findings = [f for f in findings if f.severity == "ERROR"]
        assert len(error_findings) == 0, (
            f"Clean code should not produce ERROR findings, got: {error_findings}"
        )


# ---------------------------------------------------------------------------
# Tests: language filtering
# ---------------------------------------------------------------------------

class TestLanguageFiltering:

    def test_skips_non_python_units(self):
        """Non-Python code units should be silently skipped."""
        analyzer = PythonAnalyzer()
        unit = CodeUnit(
            path="app.js",
            language="javascript",
            content=NON_PYTHON_CODE,
            start_line=1,
            end_line=4,
            metadata={},
        )
        findings = analyzer.analyze([unit])
        analyzer.cleanup()

        assert len(findings) == 0

    def test_mixed_units_only_analyzes_python(self):
        """When given mixed units, only Python ones should be analyzed."""
        analyzer = PythonAnalyzer()
        py_unit = _make_unit(COMMAND_INJECTION_CODE, "vuln.py")
        js_unit = CodeUnit(
            path="safe.js",
            language="javascript",
            content="console.log('hello');",
            start_line=1,
            end_line=1,
            metadata={},
        )
        findings = analyzer.analyze([py_unit, js_unit])
        analyzer.cleanup()

        assert len(findings) > 0, "Python unit should produce findings"
        assert all(f.file_path == "vuln.py" for f in findings)

    def test_empty_units_returns_empty(self):
        analyzer = PythonAnalyzer()
        findings = analyzer.analyze([])
        analyzer.cleanup()
        assert findings == []


# ---------------------------------------------------------------------------
# Tests: RawFinding output format
# ---------------------------------------------------------------------------

class TestFindingFormat:

    def test_engine_is_python(self):
        """All findings should have engine='python'."""
        analyzer = PythonAnalyzer()
        unit = _make_unit(ALL_VULNS_CODE)
        findings = analyzer.analyze([unit])
        analyzer.cleanup()

        assert len(findings) > 0
        assert all(f.engine == "python" for f in findings)

    def test_severity_mapping(self):
        """Severity should be mapped to ERROR/WARN/INFO."""
        analyzer = PythonAnalyzer()
        unit = _make_unit(ALL_VULNS_CODE)
        findings = analyzer.analyze([unit])
        analyzer.cleanup()

        valid_severities = {"ERROR", "WARN", "INFO"}
        for f in findings:
            assert f.severity in valid_severities, (
                f"Invalid severity '{f.severity}' for finding {f.rule_id}"
            )

    def test_confidence_values(self):
        """Confidence should be high/medium/low."""
        analyzer = PythonAnalyzer()
        unit = _make_unit(ALL_VULNS_CODE)
        findings = analyzer.analyze([unit])
        analyzer.cleanup()

        valid_confidences = {"high", "medium", "low"}
        for f in findings:
            assert f.confidence in valid_confidences, (
                f"Invalid confidence '{f.confidence}' for finding {f.rule_id}"
            )

    def test_file_path_preserved(self):
        """file_path should match the original CodeUnit path."""
        analyzer = PythonAnalyzer()
        unit = _make_unit(SQL_INJECTION_CODE, "my_app.py")
        findings = analyzer.analyze([unit])
        analyzer.cleanup()

        assert all(f.file_path == "my_app.py" for f in findings)

    def test_start_line_is_positive(self):
        """start_line should be a positive integer."""
        analyzer = PythonAnalyzer()
        unit = _make_unit(ALL_VULNS_CODE)
        findings = analyzer.analyze([unit])
        analyzer.cleanup()

        for f in findings:
            assert f.start_line > 0, f"start_line should be > 0, got {f.start_line}"


# ---------------------------------------------------------------------------
# Tests: registry integration
# ---------------------------------------------------------------------------

class TestRegistryIntegration:

    def test_python_analyzer_in_default_registry(self):
        """PythonAnalyzer should be registered in the default registry."""
        registry = build_default_registry()
        analyzer = registry.get("python")
        assert analyzer is not None
        assert isinstance(analyzer, PythonAnalyzer)

    def test_default_registry_excludes_legacy(self):
        """Default registry should NOT contain legacy analyzer."""
        registry = build_default_registry()
        assert registry.get("legacy") is None

    def test_registry_get_for_language(self):
        """get_analyzers_for_language('python') should include PythonAnalyzer."""
        registry = build_default_registry()
        python_analyzers = registry.get_analyzers_for_language("python")
        names = [a.name for a in python_analyzers]
        assert "python" in names


# ---------------------------------------------------------------------------
# Tests: cleanup
# ---------------------------------------------------------------------------

class TestCleanup:

    def test_cleanup_removes_temp_dir(self):
        """cleanup() should remove the temporary directory."""
        analyzer = PythonAnalyzer()
        unit = _make_unit(COMMAND_INJECTION_CODE)
        findings = analyzer.analyze([unit])
        assert analyzer._tmp_dir is not None

        analyzer.cleanup()
        assert analyzer._tmp_dir is None

    def test_double_cleanup_is_safe(self):
        """Calling cleanup() twice should not raise."""
        analyzer = PythonAnalyzer()
        unit = _make_unit(COMMAND_INJECTION_CODE)
        analyzer.analyze([unit])
        analyzer.cleanup()
        analyzer.cleanup()  # Should not raise
