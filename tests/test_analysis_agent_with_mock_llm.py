"""
Tests for AnalysisAgent with MockLLMClient.

Verifies:
- AnalysisAgent works without LLM client (fallback)
- AnalysisAgent works with MockLLMClient
- AnalysisAgent generates proper hypotheses and logs
"""

import pytest
from audit_core.models import CodeUnit, RawFinding, AgentHypothesis, AgentLog
from agents.analysis_agent import AnalysisAgent
from llm.mock_client import MockLLMClient


# ---------------------------------------------------------------------------
# Test data
# ---------------------------------------------------------------------------

SQL_FINDING = RawFinding(
    rule_id="TEST_SQL_001",
    type="SQL Injection",
    cwe="CWE-89",
    severity="ERROR",
    confidence="high",
    file_path="test.py",
    start_line=10,
    message="SQL injection detected",
    engine="test",
    evidence={"symbol": "execute"},
)

CMD_FINDING = RawFinding(
    rule_id="TEST_CMD_001",
    type="Command Injection",
    cwe="CWE-78",
    severity="ERROR",
    confidence="high",
    file_path="test.py",
    start_line=20,
    message="Command injection detected",
    engine="test",
    evidence={"symbol": "os.system"},
)

CODE_UNIT = CodeUnit(
    path="test.py",
    language="python",
    content="""
import sqlite3

def search(user_input):
    conn = sqlite3.connect("db.sqlite3")
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE name = '{user_input}'"
    cursor.execute(query)  # Line 10
    return cursor.fetchall()

def run_cmd(user_input):
    os.system(user_input)  # Line 20
""",
    start_line=1,
)


# ---------------------------------------------------------------------------
# Tests: Fallback mode (no LLM)
# ---------------------------------------------------------------------------

class TestAnalysisAgentFallback:

    def test_agent_works_without_llm(self):
        """AnalysisAgent should work without LLM client."""
        agent = AnalysisAgent()
        hypothesis, log = agent.run(SQL_FINDING, CODE_UNIT)
        
        assert isinstance(hypothesis, AgentHypothesis)
        assert isinstance(log, AgentLog)
        assert hypothesis.agent_name == "analysis"

    def test_fallback_uses_cwe_explanation(self):
        """Fallback should use CWE-specific explanation."""
        agent = AnalysisAgent()
        hypothesis, log = agent.run(SQL_FINDING, CODE_UNIT)
        
        # Should contain SQL Injection explanation
        assert "SQL Injection" in hypothesis.reasoning_summary
        assert "test.py" in hypothesis.reasoning_summary

    def test_fallback_for_unknown_cwe(self):
        """Fallback should use generic explanation for unknown CWE."""
        finding = RawFinding(
            rule_id="TEST_001",
            type="Unknown Vulnerability",
            cwe=None,
            severity="ERROR",
            confidence="medium",
            file_path="test.py",
            start_line=1,
            message="Unknown issue",
            engine="test",
        )
        
        agent = AnalysisAgent()
        hypothesis, log = agent.run(finding, CODE_UNIT)
        
        assert "Unknown Vulnerability" in hypothesis.reasoning_summary

    def test_fallback_log_method(self):
        """Log should indicate fallback method."""
        agent = AnalysisAgent()
        hypothesis, log = agent.run(SQL_FINDING, CODE_UNIT)
        
        assert log.metadata.get("analysis_method") == "fallback"
        assert log.metadata.get("llm_provider") is None


# ---------------------------------------------------------------------------
# Tests: LLM mode (with MockLLMClient)
# ---------------------------------------------------------------------------

class TestAnalysisAgentWithMockLLM:

    def test_agent_accepts_llm_client(self):
        """AnalysisAgent should accept LLM client."""
        client = MockLLMClient()
        agent = AnalysisAgent(llm_client=client)
        
        assert agent.get_llm_client() is client

    def test_agent_uses_llm_when_available(self):
        """AnalysisAgent should use LLM when available."""
        client = MockLLMClient()
        agent = AnalysisAgent(llm_client=client)
        
        hypothesis, log = agent.run(SQL_FINDING, CODE_UNIT)
        
        # Should use LLM mode
        assert log.metadata.get("analysis_method") == "llm"
        assert log.metadata.get("llm_provider") == "mock"

    def test_llm_response_in_hypothesis(self):
        """Hypothesis should contain LLM response."""
        client = MockLLMClient()
        agent = AnalysisAgent(llm_client=client)
        
        hypothesis, log = agent.run(SQL_FINDING, CODE_UNIT)
        
        # Mock client returns SQL-related content
        assert "SQL" in hypothesis.reasoning_summary or "Vulnerability Analysis" in hypothesis.reasoning_summary

    def test_llm_client_can_be_changed(self):
        """LLM client can be changed after initialization."""
        agent = AnalysisAgent()
        assert agent.get_llm_client() is None
        
        client = MockLLMClient()
        agent.set_llm_client(client)
        assert agent.get_llm_client() is client
        
        hypothesis, log = agent.run(SQL_FINDING, CODE_UNIT)
        assert log.metadata.get("analysis_method") == "llm"

    def test_llm_fallback_on_failure(self):
        """Should fallback if LLM fails."""
        # Create a client that returns failure
        class FailingMockClient(MockLLMClient):
            def generate(self, prompt, **kwargs):
                return LLMResponse(
                    content="",
                    success=False,
                    error="Mock failure",
                )
        
        from llm.base import LLMResponse
        client = FailingMockClient()
        agent = AnalysisAgent(llm_client=client)
        
        hypothesis, log = agent.run(SQL_FINDING, CODE_UNIT)
        
        # Should still work with fallback
        assert isinstance(hypothesis, AgentHypothesis)
        assert hypothesis.reasoning_summary  # Should have content


# ---------------------------------------------------------------------------
# Tests: Hypothesis and Log structure
# ---------------------------------------------------------------------------

class TestAnalysisAgentOutputStructure:

    def test_hypothesis_has_required_fields(self):
        """Hypothesis should have all required fields."""
        agent = AnalysisAgent()
        hypothesis, log = agent.run(SQL_FINDING, CODE_UNIT)
        
        assert hypothesis.agent_name == "analysis"
        assert hypothesis.finding_id == SQL_FINDING.id
        assert hypothesis.vulnerability_type == SQL_FINDING.type
        assert hypothesis.confidence == SQL_FINDING.confidence
        assert hypothesis.reasoning_summary

    def test_log_has_required_fields(self):
        """Log should have all required fields."""
        agent = AnalysisAgent()
        hypothesis, log = agent.run(SQL_FINDING, CODE_UNIT)
        
        assert log.agent_name == "analysis"
        assert log.stage == "analysis"
        assert log.message
        assert SQL_FINDING.id in log.input_refs

    def test_hypothesis_metadata_contains_analysis_info(self):
        """Hypothesis metadata should contain analysis info."""
        client = MockLLMClient()
        agent = AnalysisAgent(llm_client=client)
        
        hypothesis, log = agent.run(SQL_FINDING, CODE_UNIT)
        
        assert hypothesis.metadata.get("analysis_method") == "llm"
        assert hypothesis.metadata.get("cwe") == SQL_FINDING.cwe


# ---------------------------------------------------------------------------
# Tests: Multiple findings
# ---------------------------------------------------------------------------

class TestAnalysisAgentMultipleFindings:

    def test_agent_can_analyze_multiple_findings(self):
        """Agent should be able to analyze multiple findings."""
        agent = AnalysisAgent()
        
        findings = [SQL_FINDING, CMD_FINDING]
        results = []
        
        for finding in findings:
            hypothesis, log = agent.run(finding, CODE_UNIT)
            results.append((hypothesis, log))
        
        assert len(results) == 2
        
        # Each should have correct finding_id
        for i, (hypothesis, log) in enumerate(results):
            assert hypothesis.finding_id == findings[i].id


# ---------------------------------------------------------------------------
# Tests: RAG Integration
# ---------------------------------------------------------------------------

class TestAnalysisAgentRAGIntegration:
    """Tests for RAG integration in AnalysisAgent."""

    def test_sql_injection_metadata_contains_cwe_id_and_rag_context(self):
        """sql_injection finding should generate metadata with cwe_id and rag_context_count."""
        agent = AnalysisAgent()
        
        # Create a sql_injection finding
        sql_finding = RawFinding(
            rule_id="TEST_SQL_002",
            type="sql_injection",
            cwe="CWE-89",
            severity="ERROR",
            confidence="high",
            file_path="test.py",
            start_line=10,
            message="SQL injection with user input",
            engine="test",
        )
        
        hypothesis, log = agent.run(sql_finding, CODE_UNIT)
        
        # Check metadata contains cwe_id
        assert "cwe_id" in hypothesis.metadata
        assert hypothesis.metadata["cwe_id"] == "CWE-89"
        
        # Check metadata contains rag_context_count
        assert "rag_context_count" in hypothesis.metadata
        assert isinstance(hypothesis.metadata["rag_context_count"], int)
        assert hypothesis.metadata["rag_context_count"] >= 0
        
        # Check metadata contains rag_context_ids
        assert "rag_context_ids" in hypothesis.metadata
        assert isinstance(hypothesis.metadata["rag_context_ids"], list)

    def test_rag_retriever_exception_fallback(self):
        """RagRetriever抛异常时，AnalysisAgent仍然返回AgentHypothesis和AgentLog."""
        
        # Create a mock RAG retriever that raises exception
        class FailingRagRetriever:
            def retrieve(self, query, top_k=3):
                raise Exception("RAG retrieval failed")
        
        # Create agent with failing RAG retriever
        agent = AnalysisAgent(rag_retriever=FailingRagRetriever())
        
        # Should not raise exception
        hypothesis, log = agent.run(SQL_FINDING, CODE_UNIT)
        
        # Should return valid AgentHypothesis
        assert isinstance(hypothesis, AgentHypothesis)
        assert hypothesis.agent_name == "analysis"
        assert hypothesis.finding_id == SQL_FINDING.id
        
        # Should return valid AgentLog
        assert isinstance(log, AgentLog)
        assert log.agent_name == "analysis"
        
        # RAG context should be empty due to fallback
        assert hypothesis.metadata.get("rag_context_count", 0) == 0
        assert hypothesis.metadata.get("rag_context_ids", []) == []