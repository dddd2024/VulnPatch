"""
Integration smoke tests — verify the full scan pipeline works end-to-end.

All members should run these tests to ensure cross-module integration.
"""

import pytest


class TestIntegrationSmoke:
    """End-to-end smoke tests for the full audit pipeline."""

    def test_scan_code_simple(self):
        """scan_code should work with simple Python code."""
        from audit_core.orchestrator import AuditOrchestrator

        o = AuditOrchestrator()
        result = o.scan_code("def hello(): pass", language="python")
        assert result is not None
        assert result.summary is not None

    def test_scan_code_returns_all_fields(self):
        """scan_code result should contain all required fields."""
        from audit_core.orchestrator import AuditOrchestrator

        o = AuditOrchestrator()
        result = o.scan_code("def hello(): pass", language="python")

        # Verify summary
        assert hasattr(result.summary, "total_code_units")
        assert hasattr(result.summary, "total_findings")
        assert hasattr(result.summary, "total_evidence_bundles")
        assert hasattr(result.summary, "risk_score")
        assert hasattr(result.summary, "languages")
        assert hasattr(result.summary, "scanned_files")

        # Verify lists
        assert isinstance(result.findings, list)
        assert isinstance(result.evidence, list)
        assert isinstance(result.agent_logs, list)

    def test_scan_code_with_vulnerability(self):
        """scan_code should detect SQL injection."""
        from audit_core.orchestrator import AuditOrchestrator

        o = AuditOrchestrator()
        code = 'def get_user(uid):\n    cursor.execute(f"SELECT * FROM users WHERE id = {uid}")'
        result = o.scan_code(code, language="python")
        assert result.summary.total_findings >= 1

    def test_scan_code_multiple_languages(self):
        """scan_code should work with JavaScript."""
        from audit_core.orchestrator import AuditOrchestrator

        o = AuditOrchestrator()
        result = o.scan_code("var x = 1;", language="javascript")
        assert result.summary.total_code_units == 1

    def test_build_default_registry_complete(self):
        """Default registry should have all expected analyzers."""
        from audit_core.registry import build_default_registry

        r = build_default_registry()
        names = {a.name for a in r.get_analyzers()}

        expected = {
            "python",
            "pattern",
            "ast",
            "js_pattern",
            "java_pattern",
            "c_pattern",
            "taint",
        }
        assert expected.issubset(names), f"Missing: {expected - names}"

    def test_full_pipeline_agents_produce_logs(self):
        """Full pipeline should produce agent logs."""
        from audit_core.orchestrator import AuditOrchestrator

        o = AuditOrchestrator()
        result = o.scan_code("def test(): pass", language="python")
        assert len(result.agent_logs) > 0

        agent_names = {log.agent_name for log in result.agent_logs}
        assert "recon" in agent_names
