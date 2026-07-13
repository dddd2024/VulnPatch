"""
Tests for AgentRuntime interface-type compatibility.

Verifies that AgentRuntime accepts interface base types (ReconAgentBase,
AnalysisAgentBase, JudgeAgentBase) rather than concrete implementations.
"""

import pytest

from audit_core.models import (
    CodeUnit, RawFinding, AgentHypothesis, AgentLog, JudgeDecision,
)
from audit_core.agent_runtime import AgentRuntime
from agents.interfaces import ReconAgentBase, AnalysisAgentBase, JudgeAgentBase


# ---------------------------------------------------------------------------
# Minimal concrete agents that inherit from the interfaces
# ---------------------------------------------------------------------------

class MockReconAgent(ReconAgentBase):
    """Minimal ReconAgentBase implementation for testing."""
    name = "mock_recon"

    def run(self, code_units: list[CodeUnit]) -> tuple[list[AgentHypothesis], list[AgentLog]]:
        hypo = AgentHypothesis(
            agent_name=self.name,
            hypothesis="mock recon hypothesis",
            reasoning_summary="mock",
            confidence="low",
        )
        log = AgentLog(agent_name=self.name, stage="recon", message="ok")
        return [hypo], [log]


class MockAnalysisAgent(AnalysisAgentBase):
    """Minimal AnalysisAgentBase implementation for testing."""
    name = "mock_analysis"

    def run(self, finding: RawFinding, code_unit: CodeUnit | None = None) -> tuple[AgentHypothesis, AgentLog]:
        hypo = AgentHypothesis(
            agent_name=self.name,
            hypothesis="mock analysis hypothesis",
            reasoning_summary="mock",
            confidence="medium",
            finding_id=finding.id,
        )
        log = AgentLog(agent_name=self.name, stage="analysis", message="ok")
        return hypo, log


class MockJudgeAgent(JudgeAgentBase):
    """Minimal JudgeAgentBase implementation for testing."""
    name = "mock_judge"

    def run(self, finding: RawFinding, hypotheses: list[AgentHypothesis], evidence_bundle=None) -> tuple[JudgeDecision, AgentLog]:
        decision = JudgeDecision(
            finding_id=finding.id,
            verdict="suspicious",
            confidence="low",
            risk_score=30,
            reason="mock judge",
        )
        log = AgentLog(agent_name=self.name, stage="judge", message="ok")
        return decision, log


def _make_finding() -> RawFinding:
    return RawFinding(
        rule_id="TEST-001",
        type="sql_injection",
        severity="ERROR",
        file_path="test.py",
        start_line=10,
        message="Test finding",
        engine="test",
    )


class TestRuntimeWithInterfaceTypes:
    """Verify AgentRuntime works with interface base types, not just concrete classes."""

    def test_run_recon_with_interface_type(self):
        """AgentRuntime.run_recon should accept a ReconAgentBase subclass."""
        runtime = AgentRuntime()
        agent = MockReconAgent()
        code_units = [CodeUnit(path="test.py", language="python", content="x=1")]

        result = runtime.run_recon(agent, code_units)

        assert result.status == "success"
        assert isinstance(result.output, list)
        assert len(result.output) == 1
        assert result.output[0].agent_name == "mock_recon"

    def test_run_analysis_with_interface_type(self):
        """AgentRuntime.run_analysis should accept an AnalysisAgentBase subclass."""
        runtime = AgentRuntime()
        agent = MockAnalysisAgent()
        finding = _make_finding()

        result = runtime.run_analysis(agent, finding, None)

        assert result.status == "success"
        assert isinstance(result.output, AgentHypothesis)
        assert result.output.agent_name == "mock_analysis"

    def test_run_judge_with_interface_type(self):
        """AgentRuntime.run_judge should accept a JudgeAgentBase subclass."""
        runtime = AgentRuntime()
        agent = MockJudgeAgent()
        finding = _make_finding()

        result = runtime.run_judge(agent, finding, [])

        assert result.status == "success"
        assert isinstance(result.output, JudgeDecision)
        assert result.output.verdict == "suspicious"

    def test_run_analysis_batch_with_interface_type(self):
        """AgentRuntime.run_analysis_batch should accept an AnalysisAgentBase subclass."""
        runtime = AgentRuntime()
        agent = MockAnalysisAgent()
        findings = [_make_finding()]
        code_units = [CodeUnit(path="test.py", language="python", content="x=1")]

        results = runtime.run_analysis_batch(agent, findings, code_units)

        assert len(results) == 1
        assert results[0].status == "success"

    def test_run_judge_batch_with_interface_type(self):
        """AgentRuntime.run_judge_batch should accept a JudgeAgentBase subclass."""
        runtime = AgentRuntime()
        agent = MockJudgeAgent()
        findings = [_make_finding()]

        results = runtime.run_judge_batch(agent, findings, {})

        assert len(results) == 1
        assert results[0].status == "success"


class TestRuntimeWithConcreteAgents:
    """Verify existing concrete agents still work with AgentRuntime."""

    def test_run_recon_with_concrete_recon_agent(self):
        """AgentRuntime.run_recon should still work with the concrete ReconAgent."""
        from agents.recon_agent import ReconAgent

        runtime = AgentRuntime()
        agent = ReconAgent()
        code_units = [CodeUnit(path="test.py", language="python", content="x=1")]

        result = runtime.run_recon(agent, code_units)

        assert result.status == "success"
        assert isinstance(result.output, list)

    def test_run_analysis_with_concrete_analysis_agent(self):
        """AgentRuntime.run_analysis should still work with the concrete AnalysisAgent."""
        from agents.analysis_agent import AnalysisAgent

        runtime = AgentRuntime()
        agent = AnalysisAgent()
        finding = _make_finding()

        result = runtime.run_analysis(agent, finding, None)

        assert result.status == "success"
        assert isinstance(result.output, AgentHypothesis)

    def test_run_judge_with_concrete_judge_agent(self):
        """AgentRuntime.run_judge should still work with the concrete JudgeAgent."""
        from agents.judge_agent import JudgeAgent

        runtime = AgentRuntime()
        agent = JudgeAgent()
        finding = _make_finding()

        result = runtime.run_judge(agent, finding, [])

        assert result.status == "success"
        assert isinstance(result.output, JudgeDecision)


class TestRuntimeNoConcreteImports:
    """Verify agent_runtime.py no longer imports concrete agent classes."""

    def test_agent_runtime_does_not_import_concrete_agents(self):
        """agent_runtime.py should not import ReconAgent, AnalysisAgent, or JudgeAgent."""
        import audit_core.agent_runtime as mod
        source = open(mod.__file__, encoding="utf-8").read()
        assert "from agents.recon_agent import" not in source
        assert "from agents.analysis_agent import" not in source
        assert "from agents.judge_agent import" not in source

    def test_agent_runtime_imports_interfaces(self):
        """agent_runtime.py should import from agents.interfaces."""
        import audit_core.agent_runtime as mod
        source = open(mod.__file__, encoding="utf-8").read()
        assert "from agents.interfaces import" in source
