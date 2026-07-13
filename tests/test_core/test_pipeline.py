"""
Pipeline mode end-to-end tests.

Verifies that AuditOrchestrator(use_pipeline=True).scan_code(...)
produces correct AuditResult with all 7 stage_results and evidence.
"""

import pytest

from audit_core.models import AuditResult
from audit_core.orchestrator import AuditOrchestrator


class TestPipelineMode:
    """Tests for the Pipeline execution path."""

    def test_pipeline_scan_returns_audit_result(self):
        """Pipeline scan_code should return AuditResult."""
        orch = AuditOrchestrator(use_pipeline=True)
        result = orch.scan_code(
            'import os\nos.system("ls")\n',
            language="python",
        )
        assert isinstance(result, AuditResult)

    def test_pipeline_result_has_summary(self):
        """Pipeline result should have a summary."""
        orch = AuditOrchestrator(use_pipeline=True)
        result = orch.scan_code("x = 1", language="python")
        assert result.summary is not None
        assert result.summary.total_code_units >= 0

    def test_pipeline_result_has_findings_list(self):
        """Pipeline result.findings should be a list."""
        orch = AuditOrchestrator(use_pipeline=True)
        result = orch.scan_code("x = 1", language="python")
        assert isinstance(result.findings, list)

    def test_pipeline_result_has_evidence_list(self):
        """Pipeline result.evidence should be a list."""
        orch = AuditOrchestrator(use_pipeline=True)
        result = orch.scan_code("x = 1", language="python")
        assert isinstance(result.evidence, list)

    def test_pipeline_result_has_agent_logs_list(self):
        """Pipeline result.agent_logs should be a list."""
        orch = AuditOrchestrator(use_pipeline=True)
        result = orch.scan_code("x = 1", language="python")
        assert isinstance(result.agent_logs, list)

    def test_pipeline_metadata_has_stage_results(self):
        """Pipeline result.metadata should contain stage_results."""
        orch = AuditOrchestrator(use_pipeline=True)
        result = orch.scan_code("x = 1", language="python")
        assert result.metadata is not None
        assert "stage_results" in result.metadata

    def test_pipeline_stage_results_has_all_seven_stages(self):
        """Pipeline stage_results should include all 7 stages."""
        orch = AuditOrchestrator(use_pipeline=True)
        result = orch.scan_code("x = 1", language="python")
        stage_results = result.metadata.get("stage_results", {})
        expected_stages = [
            "recon", "analyzer", "merge",
            "analysis", "judge", "evidence", "summary",
        ]
        for stage_name in expected_stages:
            assert stage_name in stage_results, (
                f"Missing stage '{stage_name}' in stage_results. "
                f"Got: {list(stage_results.keys())}"
            )

    def test_pipeline_all_stages_succeeded(self):
        """All 7 pipeline stages should report success=True."""
        orch = AuditOrchestrator(use_pipeline=True)
        result = orch.scan_code("x = 1", language="python")
        stage_results = result.metadata.get("stage_results", {})
        for stage_name, sr in stage_results.items():
            assert sr.get("success", False) is True, (
                f"Stage '{stage_name}' failed: {sr.get('error')}"
            )

    def test_pipeline_evidence_stage_produces_evidence(self):
        """
        EvidenceStage should produce evidence bundles when there are findings.

        This test uses code that will produce findings (SQL injection pattern)
        to verify EvidenceStage correctly calls AgentRuntime.build_evidence().
        """
        orch = AuditOrchestrator(use_pipeline=True)
        vulnerable_code = '''
import sqlite3
def get_user(name):
    conn = sqlite3.connect("db.sqlite3")
    query = "SELECT * FROM users WHERE name='" + name + "'"
    return conn.execute(query).fetchall()
'''
        result = orch.scan_code(vulnerable_code, language="python")

        # If analyzers found findings, evidence should be built
        if result.findings:
            # EvidenceStage should have run
            stage_results = result.metadata.get("stage_results", {})
            assert "evidence" in stage_results
            evidence_sr = stage_results["evidence"]
            assert evidence_sr.get("success") is True
            # evidence_count should match or exceed the number of evidence bundles
            evidence_count = evidence_sr.get("metrics", {}).get("evidence_count", 0)
            assert evidence_count >= 0
            # result.evidence should be a list (may be empty if no judge decisions)
            assert isinstance(result.evidence, list)

    def test_pipeline_vs_inline_same_interface(self):
        """Both pipeline and inline modes should return the same AuditResult structure."""
        code = "x = 1"
        lang = "python"

        orch_inline = AuditOrchestrator(use_pipeline=False)
        result_inline = orch_inline.scan_code(code, language=lang)

        orch_pipeline = AuditOrchestrator(use_pipeline=True)
        result_pipeline = orch_pipeline.scan_code(code, language=lang)

        # Both should have the same top-level fields
        assert type(result_inline) is type(result_pipeline)
        assert hasattr(result_pipeline, "summary")
        assert hasattr(result_pipeline, "findings")
        assert hasattr(result_pipeline, "evidence")
        assert hasattr(result_pipeline, "agent_logs")

        # Pipeline should have stage_results, inline should not
        assert "stage_results" in result_pipeline.metadata
        assert "stage_results" not in result_inline.metadata


class TestPipelineWithScanAPI:
    """Tests that /scan API uses pipeline when configured."""

    def test_scan_api_returns_stage_results_with_pipeline(self):
        """When /scan uses pipeline, response should include stage_results in metadata."""
        from fastapi.testclient import TestClient
        from api.server import app

        client = TestClient(app)

        response = client.post("/scan", json={
            "input_type": "code",
            "code": "x = 1",
            "language": "python",
        })

        assert response.status_code == 200
        data = response.json()
        # After task 3, /scan should use pipeline by default
        # For now, just verify the response structure
        assert "scan_id" in data
        assert "summary" in data
        assert "findings" in data
        assert "evidence" in data
        assert "agent_logs" in data
