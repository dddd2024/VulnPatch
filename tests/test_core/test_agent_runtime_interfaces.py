"""
Tests verifying AgentRuntime depends on interfaces (ReconAgentBase, AnalysisAgentBase,
JudgeAgentBase) rather than concrete implementations (ReconAgent, AnalysisAgent, JudgeAgent).

Defines minimal mock agents inheriting from each interface and confirms AgentRuntime
accepts them without errors.
"""

import pytest

from audit_core.models import (
    CodeUnit, RawFinding, AgentHypothesis, AgentLog, JudgeDecision,
)
from audit_core.agent_runtime import AgentRuntime
from agents.interfaces import ReconAgentBase, AnalysisAgentBase, JudgeAgentBase


# ---------------------------------------------------------------------------
# Minimal mock agents implementing the interfaces
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


# ---------------------------------------------------------------------------
# Tests: AgentRuntime accepts interface implementations
# ---------------------------------------------------------------------------

class TestRuntimeAcceptsInterfaceImplementations:
    """Verify AgentRuntime works with any ReconAgentBase/AnalysisAgentBase/JudgeAgentBase implementation."""

    def test_runtime_accepts_recon_agent_base_implementation(self):
        """run_recon should accept a MockReconAgent (ReconAgentBase subclass)."""
        runtime = AgentRuntime()
        agent = MockReconAgent()
        code_units = [CodeUnit(path="test.py", language="python", content="x=1")]

        result = runtime.run_recon(agent, code_units)

        assert result.status == "success"
        assert isinstance(result.output, list)
        assert all(isinstance(h, AgentHypothesis) for h in result.output)
        assert result.output[0].agent_name == "mock_recon"

    def test_runtime_accepts_analysis_agent_base_implementation(self):
        """run_analysis should accept a MockAnalysisAgent (AnalysisAgentBase subclass)."""
        runtime = AgentRuntime()
        agent = MockAnalysisAgent()
        finding = _make_finding()

        result = runtime.run_analysis(agent, finding, None)

        assert result.status == "success"
        assert isinstance(result.output, AgentHypothesis)
        assert result.output.agent_name == "mock_analysis"

    def test_runtime_accepts_judge_agent_base_implementation(self):
        """run_judge should accept a MockJudgeAgent (JudgeAgentBase subclass)."""
        runtime = AgentRuntime()
        agent = MockJudgeAgent()
        finding = _make_finding()

        result = runtime.run_judge(agent, finding, [])

        assert result.status == "success"
        assert isinstance(result.output, JudgeDecision)
        assert result.output.verdict == "suspicious"


# ---------------------------------------------------------------------------
# Tests: Existing built-in agents still work
# ---------------------------------------------------------------------------

class TestRuntimeStillAcceptsBuiltinAgents:
    """Verify the concrete ReconAgent/AnalysisAgent/JudgeAgent still work with AgentRuntime."""

    def test_runtime_still_accepts_builtin_agents(self):
        """Existing ReconAgent, AnalysisAgent, JudgeAgent should still be callable via AgentRuntime."""
        from agents.recon_agent import ReconAgent
        from agents.analysis_agent import AnalysisAgent
        from agents.judge_agent import JudgeAgent

        runtime = AgentRuntime()
        code_units = [CodeUnit(path="test.py", language="python", content="x=1")]
        finding = _make_finding()

        # Recon
        recon_result = runtime.run_recon(ReconAgent(), code_units)
        assert recon_result.status == "success"
        assert isinstance(recon_result.output, list)

        # Analysis
        analysis_result = runtime.run_analysis(AnalysisAgent(), finding, None)
        assert analysis_result.status == "success"
        assert isinstance(analysis_result.output, AgentHypothesis)

        # Judge
        judge_result = runtime.run_judge(JudgeAgent(), finding, [])
        assert judge_result.status == "success"
        assert isinstance(judge_result.output, JudgeDecision)


# ---------------------------------------------------------------------------
# Tests: Import verification
# ---------------------------------------------------------------------------

class TestRuntimeImportDependencies:
    """Verify agent_runtime.py imports interfaces, not concrete classes."""

    def test_no_concrete_agent_imports(self):
        """agent_runtime.py should not import ReconAgent, AnalysisAgent, or JudgeAgent."""
        import audit_core.agent_runtime as mod
        source = open(mod.__file__, encoding="utf-8").read()
        assert "from agents.recon_agent import" not in source
        assert "from agents.analysis_agent import" not in source
        assert "from agents.judge_agent import" not in source

    def test_interface_imports_present(self):
        """agent_runtime.py should import from agents.interfaces."""
        import audit_core.agent_runtime as mod
        source = open(mod.__file__, encoding="utf-8").read()
        assert "from agents.interfaces import" in source
