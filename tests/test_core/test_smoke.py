"""
Smoke tests for audit_core module.

Core Orchestrator member is responsible for:
  - audit_core/
  - ingest/
  - governance/
  - contracts/
"""

import pytest


class TestCoreSmoke:
    """Smoke tests for core module — verify basic initialization and data flow."""

    def test_audit_orchestrator_initializes(self):
        """AuditOrchestrator should initialize without errors."""
        from audit_core.orchestrator import AuditOrchestrator
        o = AuditOrchestrator()
        assert o is not None
        assert o.registry is not None

    def test_build_default_registry_returns_analyzers(self):
        """build_default_registry should return a registry with analyzers."""
        from audit_core.registry import build_default_registry
        r = build_default_registry()
        analyzers = r.get_analyzers()
        assert len(analyzers) > 0

    def test_code_unit_model(self):
        """CodeUnit model should be creatable."""
        from audit_core.models import CodeUnit
        unit = CodeUnit(path="test.py", language="python", content="x=1")
        assert unit.path == "test.py"
        assert unit.language == "python"

    def test_raw_finding_model(self):
        """RawFinding model should be creatable."""
        from audit_core.models import RawFinding
        f = RawFinding(
            rule_id="TEST-001",
            type="test",
            severity="ERROR",
            confidence="high",
            file_path="test.py",
            start_line=1,
            message="test finding",
            engine="pattern",
        )
        assert f.severity == "ERROR"

    def test_audit_result_model(self):
        """AuditResult model should be creatable."""
        from audit_core.models import AuditResult, AuditSummary
        result = AuditResult(summary=AuditSummary())
        assert result.summary.total_findings == 0

    def test_result_merger_exists(self):
        """Result merger should be importable."""
        from audit_core.result_merger import merge_findings
        assert callable(merge_findings)

    def test_scoring_module_exists(self):
        """Scoring module should be importable."""
        from audit_core.scoring import score_finding
        assert callable(score_finding)


class TestIngestSmoke:
    """Smoke tests for ingest module."""

    def test_language_router_detects_python(self):
        """Language router should detect Python files."""
        from ingest.language_router import detect_language_by_path
        lang = detect_language_by_path("test.py")
        assert lang == "python"

    def test_language_router_detects_javascript(self):
        """Language router should detect JavaScript files."""
        from ingest.language_router import detect_language_by_path
        lang = detect_language_by_path("app.js")
        assert lang == "javascript"

    def test_code_unit_builder_exists(self):
        """CodeUnit builder should be importable."""
        from ingest.code_unit_builder import build_code_unit_from_file
        assert callable(build_code_unit_from_file)
