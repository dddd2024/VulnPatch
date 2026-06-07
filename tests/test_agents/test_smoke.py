"""
Smoke tests for agents module.

Agent & Knowledge member is responsible for:
  - agents/
  - evidence/
  - knowledge/
"""

import pytest


class TestAgentsSmoke:
    """Smoke tests for agents — verify three agent types work correctly."""

    def test_recon_agent_exists(self):
        """ReconAgent should be importable and instantiable."""
        from agents.recon_agent import ReconAgent
        agent = ReconAgent()
        assert agent.name == "recon"

    def test_recon_agent_run_returns_hypotheses_and_logs(self):
        """ReconAgent.run should return (list[AgentHypothesis], list[AgentLog])."""
        from agents.recon_agent import ReconAgent
        from audit_core.models import CodeUnit

        agent = ReconAgent()
        unit = CodeUnit(path="test.py", language="python", content="x=1")
        hypotheses, logs = agent.run([unit])
        assert isinstance(hypotheses, list)
        assert isinstance(logs, list)

    def test_analysis_agent_exists(self):
        """AnalysisAgent should be importable and instantiable."""
        from agents.analysis_agent import AnalysisAgent
        agent = AnalysisAgent()
        assert agent.name == "analysis"

    def test_analysis_agent_run_returns_hypothesis_and_log(self):
        """AnalysisAgent.run should return (AgentHypothesis, AgentLog)."""
        from agents.analysis_agent import AnalysisAgent
        from audit_core.models import RawFinding

        agent = AnalysisAgent()
        finding = RawFinding(
            rule_id="TEST-001",
            type="sql_injection",
            severity="ERROR",
            confidence="high",
            file_path="test.py",
            start_line=1,
            message="SQL injection found",
            engine="pattern",
        )
        hypothesis, log = agent.run(finding)
        assert hypothesis is not None
        assert log is not None

    def test_analysis_agent_fallback_works(self):
        """AnalysisAgent should work without LLM (fallback mode)."""
        from agents.analysis_agent import AnalysisAgent
        from audit_core.models import RawFinding

        agent = AnalysisAgent(llm_client=None)
        finding = RawFinding(
            rule_id="TEST-001",
            type="xss",
            severity="WARN",
            confidence="medium",
            file_path="test.py",
            start_line=1,
            message="XSS found",
            engine="pattern",
        )
        hypothesis, log = agent.run(finding)
        assert hypothesis.confidence in ("high", "medium", "low")

    def test_judge_agent_exists(self):
        """JudgeAgent should be importable and instantiable."""
        from agents.judge_agent import JudgeAgent
        agent = JudgeAgent()
        assert agent.name == "judge"

    def test_judge_agent_run_returns_decision_and_log(self):
        """JudgeAgent.run should return (JudgeDecision, AgentLog)."""
        from agents.judge_agent import JudgeAgent
        from audit_core.models import RawFinding, AgentHypothesis

        agent = JudgeAgent()
        finding = RawFinding(
            rule_id="TEST-001",
            type="sql_injection",
            severity="ERROR",
            confidence="high",
            file_path="test.py",
            start_line=1,
            message="SQL injection found",
            engine="pattern",
        )
        hypothesis = AgentHypothesis(
            agent_name="analysis",
            hypothesis="SQL injection detected",
            vulnerability_type="SQL Injection",
            reasoning_summary="User input in SQL query",
            confidence="high",
        )
        decision, log = agent.run(finding, [hypothesis])
        assert decision.verdict in ("confirmed", "suspicious", "rejected")
        assert 0 <= decision.risk_score <= 100
        assert decision.confidence in ("high", "medium", "low")

    def test_agents_do_not_import_analyzers(self):
        """Agent module should not import analyzers."""
        import agents.recon_agent as mod
        source = open(mod.__file__, encoding="utf-8").read()
        assert "from analyzers" not in source
        assert "import analyzers" not in source

    def test_strongly_typed_interfaces_exist(self):
        """Strongly-typed agent interfaces should be importable."""
        from agents.interfaces import ReconAgentBase, AnalysisAgentBase, JudgeAgentBase
        assert ReconAgentBase is not None
        assert AnalysisAgentBase is not None
        assert JudgeAgentBase is not None


class TestEvidenceSmoke:
    """Smoke tests for evidence module."""

    def test_evidence_bundle_buildable(self):
        """EvidenceBundle should be creatable."""
        from audit_core.models import EvidenceBundle, RawFinding, CodeUnit

        finding = RawFinding(
            rule_id="TEST-001",
            type="test",
            severity="ERROR",
            confidence="high",
            file_path="test.py",
            start_line=1,
            message="test",
            engine="pattern",
        )
        bundle = EvidenceBundle(finding=finding, code_unit=CodeUnit(
            path="test.py", language="python", content="x=1"
        ))
        assert bundle.finding.rule_id == "TEST-001"

    def test_evidence_builder_importable(self):
        """Evidence builder should be importable."""
        from evidence.evidence_builder import build_evidence_bundle
        assert callable(build_evidence_bundle)


class TestKnowledgeSmoke:
    """Smoke tests for knowledge module."""

    def test_cwe_mapper_importable(self):
        """CWE mapper should be importable."""
        from knowledge.cwe_mapper import map_cwe
        assert callable(map_cwe)

    def test_rag_retriever_importable(self):
        """RAG retriever should be importable."""
        from knowledge.rag_retriever import RagRetriever
        assert RagRetriever is not None

    def test_vuln_graph_importable(self):
        """Vulnerability graph should be importable."""
        from knowledge.vuln_graph import VulnerabilityGraph
        assert VulnerabilityGraph is not None
