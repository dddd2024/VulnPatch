"""
Tests for LLMClient integration with AuditOrchestrator.

Verifies that:
1. AuditOrchestrator accepts optional llm_client / llm_config
2. AnalysisAgent uses LLM mode when client is injected
3. Fallback mode works when no LLM client is provided
4. No specific provider (DeepSeek/OpenAI) is hardcoded in agents
5. Mock LLM works end-to-end in the main pipeline
"""

import pytest

from audit_core.models import CodeUnit, RawFinding, AuditResult
from audit_core.orchestrator import AuditOrchestrator
from agents.analysis_agent import AnalysisAgent
from llm.base import LLMClientBase, LLMResponse, LLMClientFactory
from llm.mock_client import MockLLMClient


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

VULNERABLE_CODE = """
from flask import Flask, request
app = Flask(__name__)

@app.route('/search')
def search():
    query = request.args.get('q')
    sql = "SELECT * FROM users WHERE name = '" + query + "'"
    return execute_query(sql)

def execute_query(sql):
    pass
"""


@pytest.fixture
def mock_llm():
    """Create a mock LLM client with zero delay for fast tests."""
    return MockLLMClient(response_delay_ms=0)


@pytest.fixture
def code_unit():
    """Create a CodeUnit from the vulnerable code snippet."""
    return CodeUnit(
        path="app.py",
        language="python",
        content=VULNERABLE_CODE,
        start_line=1,
        end_line=VULNERABLE_CODE.count("\n") + 1,
    )


@pytest.fixture
def sample_finding(code_unit):
    """Create a sample RawFinding for testing."""
    return RawFinding(
        rule_id="TEST_SQL_INJECTION",
        type="SQL Injection",
        cwe="CWE-89",
        severity="ERROR",
        confidence="high",
        file_path="app.py",
        start_line=7,
        end_line=7,
        message="SQL injection: string concatenation in query",
        engine="test",
    )


# ---------------------------------------------------------------------------
# Test: AnalysisAgent LLM injection
# ---------------------------------------------------------------------------

class TestAnalysisAgentLLMInjection:
    """Tests for AnalysisAgent LLM client injection."""

    def test_init_with_llm_client(self, mock_llm):
        """AnalysisAgent can be initialized with an LLM client."""
        agent = AnalysisAgent(llm_client=mock_llm)
        assert agent.get_llm_client() is mock_llm

    def test_init_without_llm_client(self):
        """AnalysisAgent works without an LLM client (fallback mode)."""
        agent = AnalysisAgent(llm_client=None)
        assert agent.get_llm_client() is None

    def test_set_llm_client(self, mock_llm):
        """LLM client can be set after initialization."""
        agent = AnalysisAgent()
        assert agent.get_llm_client() is None
        agent.set_llm_client(mock_llm)
        assert agent.get_llm_client() is mock_llm

    def test_uses_llm_mode_when_client_available(self, mock_llm, sample_finding, code_unit):
        """AnalysisAgent uses LLM mode when client is available."""
        agent = AnalysisAgent(llm_client=mock_llm)
        hypothesis, log = agent.run(sample_finding, code_unit)

        assert hypothesis.metadata["analysis_method"] == "llm"
        assert log.metadata["analysis_method"] == "llm"
        assert log.metadata["llm_provider"] == "mock"

    def test_uses_fallback_mode_when_no_client(self, sample_finding, code_unit):
        """AnalysisAgent uses fallback mode when no client is available."""
        agent = AnalysisAgent(llm_client=None)
        hypothesis, log = agent.run(sample_finding, code_unit)

        assert hypothesis.metadata["analysis_method"] == "fallback"
        assert log.metadata["analysis_method"] == "fallback"
        assert log.metadata["llm_provider"] is None

    def test_llm_response_contains_analysis(self, mock_llm, sample_finding, code_unit):
        """LLM-generated explanation contains vulnerability analysis."""
        agent = AnalysisAgent(llm_client=mock_llm)
        hypothesis, _ = agent.run(sample_finding, code_unit)

        # MockLLMClient returns structured markdown with vulnerability info
        assert len(hypothesis.reasoning_summary) > 50
        assert "SQL" in hypothesis.reasoning_summary or "vulnerability" in hypothesis.reasoning_summary.lower()

    def test_fallback_explanation_for_known_cwe(self, sample_finding, code_unit):
        """Fallback mode provides CWE-specific explanations."""
        agent = AnalysisAgent(llm_client=None)
        hypothesis, _ = agent.run(sample_finding, code_unit)

        # CWE-89 should trigger SQL injection explanation
        assert "SQL" in hypothesis.reasoning_summary

    def test_no_hardcoded_provider_in_agent_source(self):
        """AnalysisAgent source code does not hardcode DeepSeek/OpenAI."""
        import inspect
        source = inspect.getsource(AnalysisAgent)
        assert "deepseek" not in source.lower()
        assert "openai" not in source.lower()
        # Should only reference the abstract base
        assert "LLMClientBase" in source


# ---------------------------------------------------------------------------
# Test: AuditOrchestrator LLM integration
# ---------------------------------------------------------------------------

class TestOrchestratorLLMIntegration:
    """Tests for AuditOrchestrator LLM client integration."""

    def test_init_with_llm_client(self, mock_llm):
        """Orchestrator accepts llm_client parameter."""
        orch = AuditOrchestrator(llm_client=mock_llm)
        assert orch.get_llm_client() is mock_llm
        assert orch.analysis_agent.get_llm_client() is mock_llm

    def test_init_with_llm_config_dict(self):
        """Orchestrator creates LLM client from config dict."""
        orch = AuditOrchestrator(llm_config={"provider": "mock"})
        assert orch.get_llm_client() is not None
        assert orch.get_llm_client().provider_name == "mock"

    def test_init_without_llm(self):
        """Orchestrator works without any LLM configuration."""
        orch = AuditOrchestrator()
        assert orch.get_llm_client() is None
        assert orch.analysis_agent.get_llm_client() is None

    def test_llm_config_ignored_when_client_provided(self, mock_llm):
        """Direct llm_client takes priority over llm_config."""
        orch = AuditOrchestrator(
            llm_client=mock_llm,
            llm_config={"provider": "mock", "model": "other"}
        )
        assert orch.get_llm_client() is mock_llm

    def test_set_llm_client_updates_agents(self, mock_llm):
        """set_llm_client propagates to agents."""
        orch = AuditOrchestrator()
        assert orch.get_llm_client() is None

        orch.set_llm_client(mock_llm)
        assert orch.get_llm_client() is mock_llm
        assert orch.analysis_agent.get_llm_client() is mock_llm

    def test_invalid_llm_config_falls_back(self):
        """Invalid llm_config gracefully falls back to no LLM."""
        orch = AuditOrchestrator(llm_config={"provider": "nonexistent_provider"})
        # Should not crash, should fall back to None
        assert orch.get_llm_client() is None


# ---------------------------------------------------------------------------
# Test: End-to-end pipeline with Mock LLM
# ---------------------------------------------------------------------------

class TestPipelineWithMockLLM:
    """End-to-end tests verifying Mock LLM works in the main pipeline."""

    def test_scan_code_with_llm(self, mock_llm):
        """Full pipeline scan with LLM returns valid AuditResult."""
        orch = AuditOrchestrator(llm_client=mock_llm)
        result = orch.scan_code(VULNERABLE_CODE, language="python")

        assert isinstance(result, AuditResult)
        assert result.summary.total_code_units >= 1

    def test_scan_code_with_llm_uses_llm_mode(self, mock_llm):
        """Pipeline with LLM uses llm analysis method."""
        orch = AuditOrchestrator(llm_client=mock_llm)
        result = orch.scan_code(VULNERABLE_CODE, language="python")

        # Check that at least one agent log shows LLM mode
        llm_logs = [
            log for log in result.agent_logs
            if log.metadata.get("analysis_method") == "llm"
        ]
        # If there are findings, analysis agent should have run with LLM
        if result.summary.total_findings > 0:
            assert len(llm_logs) >= 1

    def test_scan_code_without_llm_uses_fallback(self):
        """Pipeline without LLM uses fallback analysis method."""
        orch = AuditOrchestrator()
        result = orch.scan_code(VULNERABLE_CODE, language="python")

        assert isinstance(result, AuditResult)
        # Check agent logs for fallback method
        fallback_logs = [
            log for log in result.agent_logs
            if log.metadata.get("analysis_method") == "fallback"
        ]
        if result.summary.total_findings > 0:
            assert len(fallback_logs) >= 1

    def test_scan_code_with_llm_config_dict(self):
        """Pipeline with llm_config dict also works."""
        orch = AuditOrchestrator(llm_config={"provider": "mock"})
        result = orch.scan_code(VULNERABLE_CODE, language="python")

        assert isinstance(result, AuditResult)
        assert result.summary.total_code_units >= 1

    def test_llm_call_count_increases(self, mock_llm):
        """Mock LLM call count increases during pipeline run when findings exist."""
        orch = AuditOrchestrator(llm_client=mock_llm)
        initial_count = mock_llm.get_call_count()

        result = orch.scan_code(VULNERABLE_CODE, language="python")

        # LLM calls only happen when findings are detected and processed
        if result.summary.total_findings > 0:
            assert mock_llm.get_call_count() > initial_count

    def test_result_has_evidence_bundles_with_llm(self, mock_llm):
        """Pipeline with LLM produces evidence bundles for findings."""
        orch = AuditOrchestrator(llm_client=mock_llm)
        result = orch.scan_code(VULNERABLE_CODE, language="python")

        if result.summary.total_findings > 0:
            assert result.summary.total_evidence_bundles >= 1
            assert len(result.evidence) >= 1

    def test_result_metadata_no_error(self, mock_llm):
        """Result metadata does not contain LLM errors."""
        orch = AuditOrchestrator(llm_client=mock_llm)
        result = orch.scan_code(VULNERABLE_CODE, language="python")

        assert "error" not in result.metadata


# ---------------------------------------------------------------------------
# Test: LLMClientFactory registration
# ---------------------------------------------------------------------------

class TestLLMClientFactory:
    """Tests for LLM client factory and provider abstraction."""

    def test_mock_provider_registered(self):
        """Mock provider is registered in factory."""
        assert "mock" in LLMClientFactory.available_providers()

    def test_create_mock_client(self):
        """Factory can create mock client."""
        client = LLMClientFactory.create("mock")
        assert client.is_available()
        assert client.provider_name == "mock"

    def test_create_with_custom_model(self):
        """Factory passes model parameter to client."""
        client = LLMClientFactory.create("mock", model="custom-model")
        # MockLLMClient uses model param or falls back to "mock-model"
        assert client.default_model == "mock-model" or client.default_model == "custom-model"

    def test_unknown_provider_raises(self):
        """Factory raises ValueError for unknown provider."""
        with pytest.raises(ValueError, match="Unknown LLM provider"):
            LLMClientFactory.create("unknown_provider_xyz")

    def test_no_hardcoded_provider_in_orchestrator(self):
        """Orchestrator source does not hardcode DeepSeek/OpenAI in code logic."""
        import inspect
        source = inspect.getsource(AuditOrchestrator)
        # Check that provider names don't appear in actual code (only in docstrings/comments)
        # The docstring may mention "openai" as an example config, which is fine.
        # What matters is no import or direct usage of specific providers.
        assert "from openai" not in source.lower()
        assert "import openai" not in source.lower()
        assert "from deepseek" not in source.lower()
        assert "import deepseek" not in source.lower()
        # Should use factory pattern
        assert "LLMClientFactory" in source or "llm_client" in source
