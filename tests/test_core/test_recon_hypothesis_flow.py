"""
Tests for recon hypothesis flow: verifying that ReconAgent-generated
AgentHypothesis objects are correctly passed to JudgeAgent.

Bug context:
  ReconAgent writes supporting_evidence_ids=[unit.id] into the model field
  (AgentHypothesis.supporting_evidence_ids), but the old orchestrator logic
  read from h.metadata["supporting_evidence_ids"], so recon hypotheses were
  never forwarded to JudgeAgent.

Fix:
  orchestrator.py now checks code_unit.id in h.supporting_evidence_ids
  (the model field) instead of h.metadata["supporting_evidence_ids"].
"""

import pytest
from unittest.mock import Mock, patch

from audit_core.models import (
    CodeUnit, RawFinding, AgentHypothesis, AgentLog,
    JudgeDecision, EvidenceBundle,
)
from audit_core.orchestrator import AuditOrchestrator
from audit_core.agent_runtime import AgentRuntime
from audit_core.error_policy import AgentExecutionResult


class TestReconHypothesisFlow:
    """Verify recon hypotheses reach JudgeAgent via supporting_evidence_ids field."""

    def _make_judge_result(self, finding):
        """Create a successful AgentExecutionResult for judge."""
        decision = JudgeDecision(
            finding_id=finding.id,
            verdict="confirmed",
            confidence="high",
            risk_score=80,
            reason="test",
        )
        return AgentExecutionResult(
            status="success",
            output=decision,
            logs=[AgentLog(agent_name="judge", stage="judge", message="ok")],
            error=None,
            fallback_used=False,
            stage="judge",
            agent_name="judge",
        )

    def _make_analysis_result(self, finding):
        """Create a successful AgentExecutionResult for analysis."""
        hypothesis = AgentHypothesis(
            agent_name="analysis",
            hypothesis="Analysis hypothesis",
            reasoning_summary="Test",
            confidence="high",
            finding_id=finding.id,
        )
        return AgentExecutionResult(
            status="success",
            output=hypothesis,
            logs=[AgentLog(agent_name="analysis", stage="analysis", message="ok")],
            error=None,
            fallback_used=False,
            stage="analysis",
            agent_name="analysis",
        )

    # ------------------------------------------------------------------
    # Core test: recon hypothesis IS forwarded to JudgeAgent
    # ------------------------------------------------------------------
    def test_recon_hypothesis_reaches_judge_agent(self):
        """ReconAgent hypothesis with matching supporting_evidence_ids should be passed to JudgeAgent."""
        # Create a CodeUnit that scan_code will use
        unit = CodeUnit(path="<snippet>", language="python", content="x=1")
        recon_hypo = AgentHypothesis(
            agent_name="recon",
            hypothesis=f"Attack surfaces identified in {unit.path}",
            vulnerability_type="Attack Surface",
            reasoning_summary="Found request parameters and routes",
            confidence="medium",
            supporting_evidence_ids=[unit.id],  # key: unit.id is in the model field
            metadata={"language": "python"},
        )
        finding = RawFinding(
            rule_id="TEST-001",
            type="sql_injection",
            severity="ERROR",
            file_path="<snippet>",  # matches unit.path so _find_code_unit succeeds
            start_line=10,
            message="Potential SQL injection",
            engine="test",
        )

        captured_hypotheses: list[list[AgentHypothesis]] = []

        def mock_run_judge(self_runtime, agent, finding_arg, hypotheses, evidence_bundle=None):
            captured_hypotheses.append(list(hypotheses))
            return self._make_judge_result(finding_arg)

        orch = AuditOrchestrator(use_pipeline=False)

        # Mock repo_loader to return our controlled unit
        with patch.object(
            orch.repo_loader, "load_code_snippet", return_value=[unit]
        ):
            with patch.object(
                orch.recon_agent, "run", return_value=([recon_hypo], [])
            ):
                with patch.object(
                    orch, "_run_analyzers", return_value=([finding], {"analyzer_runs": [], "analyzer_errors": [], "skipped_languages": []})
                ):
                    with patch.object(
                        AgentRuntime, "run_judge", mock_run_judge
                    ):
                        with patch.object(
                            AgentRuntime, "run_analysis", lambda self_runtime, agent, f, cu: self._make_analysis_result(f)
                        ):
                            with patch.object(
                                AgentRuntime, "build_evidence", lambda self_runtime, **kwargs: (None, [])
                            ):
                                result = orch.scan_code("x=1", language="python")

        # The recon hypothesis must have been passed to judge
        assert len(captured_hypotheses) == 1, "JudgeAgent.run should have been called once"
        judge_hypotheses = captured_hypotheses[0]
        assert any(h.id == recon_hypo.id for h in judge_hypotheses), (
            "ReconAgent hypothesis should be in JudgeAgent input"
        )

    # ------------------------------------------------------------------
    # Negative test: non-matching unit.id should NOT be forwarded
    # ------------------------------------------------------------------
    def test_recon_hypothesis_not_forwarded_for_non_matching_unit(self):
        """ReconAgent hypothesis with non-matching supporting_evidence_ids should NOT be forwarded."""
        # Unit used by scan_code (via repo_loader)
        actual_unit = CodeUnit(path="<snippet>", language="python", content="x=1")
        # Recon hypothesis references a DIFFERENT unit.id
        other_unit = CodeUnit(path="other.py", language="python", content="y=2")
        recon_hypo = AgentHypothesis(
            agent_name="recon",
            hypothesis=f"Attack surfaces identified in {other_unit.path}",
            vulnerability_type="Attack Surface",
            reasoning_summary="Found request parameters",
            confidence="medium",
            supporting_evidence_ids=[other_unit.id],  # different unit.id
            metadata={"language": "python"},
        )
        finding = RawFinding(
            rule_id="TEST-001",
            type="sql_injection",
            severity="ERROR",
            file_path="<snippet>",
            start_line=10,
            message="Potential SQL injection",
            engine="test",
        )

        captured_hypotheses: list[list[AgentHypothesis]] = []

        def mock_run_judge(self_runtime, agent, finding_arg, hypotheses, evidence_bundle=None):
            captured_hypotheses.append(list(hypotheses))
            return self._make_judge_result(finding_arg)

        orch = AuditOrchestrator(use_pipeline=False)

        with patch.object(
            orch.repo_loader, "load_code_snippet", return_value=[actual_unit]
        ):
            with patch.object(
                orch.recon_agent, "run", return_value=([recon_hypo], [])
            ):
                with patch.object(
                    orch, "_run_analyzers", return_value=([finding], {"analyzer_runs": [], "analyzer_errors": [], "skipped_languages": []})
                ):
                    with patch.object(
                        AgentRuntime, "run_judge", mock_run_judge
                    ):
                        with patch.object(
                            AgentRuntime, "run_analysis", lambda self_runtime, agent, f, cu: self._make_analysis_result(f)
                        ):
                            with patch.object(
                                AgentRuntime, "build_evidence", lambda self_runtime, **kwargs: (None, [])
                            ):
                                result = orch.scan_code("x=1", language="python")

        # Recon hypothesis should NOT be in judge input (unit.id doesn't match)
        assert len(captured_hypotheses) == 1
        judge_hypotheses = captured_hypotheses[0]
        assert not any(h.id == recon_hypo.id for h in judge_hypotheses), (
            "ReconAgent hypothesis for a different code unit should NOT be forwarded"
        )

    # ------------------------------------------------------------------
    # Verify we use the model field, NOT metadata
    # ------------------------------------------------------------------
    def test_uses_supporting_evidence_ids_field_not_metadata(self):
        """
        Orchestrator should read from h.supporting_evidence_ids (model field),
        NOT from h.metadata["supporting_evidence_ids"].
        """
        unit = CodeUnit(path="<snippet>", language="python", content="x=1")
        # Hypothesis with unit.id in supporting_evidence_ids field only
        # metadata does NOT contain supporting_evidence_ids
        recon_hypo = AgentHypothesis(
            agent_name="recon",
            hypothesis="Test hypothesis",
            vulnerability_type="Test",
            reasoning_summary="Test",
            confidence="medium",
            supporting_evidence_ids=[unit.id],
            metadata={"language": "python"},  # NO supporting_evidence_ids here
        )
        finding = RawFinding(
            rule_id="TEST-001",
            type="sql_injection",
            severity="ERROR",
            file_path="<snippet>",
            start_line=10,
            message="Potential SQL injection",
            engine="test",
        )

        captured_hypotheses: list[list[AgentHypothesis]] = []

        def mock_run_judge(self_runtime, agent, finding_arg, hypotheses, evidence_bundle=None):
            captured_hypotheses.append(list(hypotheses))
            return self._make_judge_result(finding_arg)

        orch = AuditOrchestrator(use_pipeline=False)

        with patch.object(
            orch.repo_loader, "load_code_snippet", return_value=[unit]
        ):
            with patch.object(
                orch.recon_agent, "run", return_value=([recon_hypo], [])
            ):
                with patch.object(
                    orch, "_run_analyzers", return_value=([finding], {"analyzer_runs": [], "analyzer_errors": [], "skipped_languages": []})
                ):
                    with patch.object(
                        AgentRuntime, "run_judge", mock_run_judge
                    ):
                        with patch.object(
                            AgentRuntime, "run_analysis", lambda self_runtime, agent, f, cu: self._make_analysis_result(f)
                        ):
                            with patch.object(
                                AgentRuntime, "build_evidence", lambda self_runtime, **kwargs: (None, [])
                            ):
                                result = orch.scan_code("x=1", language="python")

        # Recon hypothesis should be forwarded via supporting_evidence_ids field
        assert len(captured_hypotheses) == 1
        judge_hypotheses = captured_hypotheses[0]
        assert any(h.id == recon_hypo.id for h in judge_hypotheses), (
            "Hypothesis should be forwarded via supporting_evidence_ids field, not metadata"
        )

    # ------------------------------------------------------------------
    # scan_code does not crash
    # ------------------------------------------------------------------
    def test_scan_code_does_not_crash_with_recon_hypothesis(self):
        """scan_code should complete without error when recon produces hypotheses."""
        unit = CodeUnit(path="<snippet>", language="python", content="x=1")
        recon_hypo = AgentHypothesis(
            agent_name="recon",
            hypothesis=f"Attack surfaces identified in {unit.path}",
            vulnerability_type="Attack Surface",
            reasoning_summary="Found request parameters",
            confidence="medium",
            supporting_evidence_ids=[unit.id],
            metadata={"language": "python"},
        )

        orch = AuditOrchestrator(use_pipeline=False)

        with patch.object(
            orch.recon_agent, "run", return_value=([recon_hypo], [])
        ):
            result = orch.scan_code("x=1", language="python")

        assert result is not None
        assert result.summary is not None
