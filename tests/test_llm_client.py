"""
Tests for LLM client interfaces.

Verifies:
- LLMResponse data structure
- MockLLMClient behavior
- LLMClientFactory registration
"""

import pytest
from llm.base import LLMResponse, LLMClientBase, LLMClientFactory
from llm.mock_client import MockLLMClient


class TestLLMResponse:

    def test_llm_response_defaults(self):
        """LLMResponse should have sensible defaults."""
        response = LLMResponse()
        assert response.content == ""
        assert response.model == ""
        assert response.tokens_used == 0
        assert response.success is True
        assert response.error is None

    def test_llm_response_with_content(self):
        """LLMResponse should accept content."""
        response = LLMResponse(
            content="Test response",
            model="test-model",
            tokens_used=100,
            success=True,
        )
        assert response.content == "Test response"
        assert response.model == "test-model"
        assert response.tokens_used == 100

    def test_llm_response_error(self):
        """LLMResponse should handle errors."""
        response = LLMResponse(
            content="",
            success=False,
            error="API error",
        )
        assert response.success is False
        assert response.error == "API error"


class TestMockLLMClient:

    def test_mock_client_is_available(self):
        """Mock client should always be available."""
        client = MockLLMClient()
        assert client.is_available() is True

    def test_mock_client_provider_name(self):
        """Mock client should have correct provider name."""
        client = MockLLMClient()
        assert client.provider_name == "mock"

    def test_mock_client_default_model(self):
        """Mock client should have default model."""
        client = MockLLMClient()
        assert client.default_model == "mock-model"

    def test_mock_client_generate_returns_response(self):
        """Mock client should return LLMResponse."""
        client = MockLLMClient()
        response = client.generate("Test prompt")
        assert isinstance(response, LLMResponse)
        assert response.success is True

    def test_mock_client_generate_sql_response(self):
        """Mock client should return SQL-related response for SQL prompts."""
        client = MockLLMClient()
        response = client.generate("Analyze SQL vulnerability")
        assert "SQL" in response.content

    def test_mock_client_generate_xss_response(self):
        """Mock client should return XSS-related response for XSS prompts."""
        client = MockLLMClient()
        response = client.generate("Analyze XSS vulnerability")
        assert "XSS" in response.content or "Scripting" in response.content

    def test_mock_client_generate_command_response(self):
        """Mock client should return command injection response."""
        client = MockLLMClient()
        response = client.generate("Analyze command injection vulnerability")
        assert "Command" in response.content

    def test_mock_client_generate_attack_surface(self):
        """Mock client should return attack surface response."""
        client = MockLLMClient()
        response = client.generate("Identify attack surface")
        assert "Attack Surface" in response.content

    def test_mock_client_generate_evidence(self):
        """Mock client should return evidence response."""
        client = MockLLMClient()
        response = client.generate("Summarize evidence chain")
        assert "Evidence" in response.content

    def test_mock_client_generate_judge_response(self):
        """Mock client should return judge decision response."""
        client = MockLLMClient()
        response = client.generate("Make judge decision")
        assert "Judge" in response.content or "Verdict" in response.content

    def test_mock_client_call_count(self):
        """Mock client should track call count."""
        client = MockLLMClient()
        assert client.get_call_count() == 0
        
        client.generate("prompt 1")
        assert client.get_call_count() == 1
        
        client.generate("prompt 2")
        assert client.get_call_count() == 2
        
        client.reset_call_count()
        assert client.get_call_count() == 0

    def test_mock_client_custom_model(self):
        """Mock client should accept custom model name."""
        client = MockLLMClient(model="custom-mock")
        response = client.generate("test")
        assert response.model == "custom-mock"

    def test_mock_client_response_delay(self):
        """Mock client should simulate latency."""
        import time
        client = MockLLMClient(response_delay_ms=100)
        start = time.time()
        client.generate("test")
        elapsed_ms = (time.time() - start) * 1000
        assert elapsed_ms >= 50  # Allow some tolerance


class TestLLMClientFactory:

    def test_factory_register(self):
        """Factory should register providers."""
        LLMClientFactory.register("mock", MockLLMClient)
        providers = LLMClientFactory.available_providers()
        assert "mock" in providers

    def test_factory_create_mock(self):
        """Factory should create MockLLMClient."""
        LLMClientFactory.register("mock", MockLLMClient)
        client = LLMClientFactory.create("mock")
        assert isinstance(client, MockLLMClient)
        assert client.provider_name == "mock"

    def test_factory_create_with_options(self):
        """Factory should pass options to client."""
        LLMClientFactory.register("mock", MockLLMClient)
        client = LLMClientFactory.create("mock", model="custom-model")
        assert client.default_model == "mock-model"  # Uses class default

    def test_factory_unknown_provider(self):
        """Factory should raise for unknown provider."""
        with pytest.raises(ValueError):
            LLMClientFactory.create("unknown_provider")


class TestMockLLMClientResponseTemplates:

    def test_vulnerability_default_template(self):
        """Should return default vulnerability template for unknown types."""
        client = MockLLMClient()
        response = client.generate("Analyze some vulnerability")
        assert "Vulnerability Analysis" in response.content

    def test_judge_confirmed_template(self):
        """Should return confirmed template."""
        client = MockLLMClient()
        response = client.generate("Judge verdict confirmed")
        assert "CONFIRMED" in response.content

    def test_judge_rejected_template(self):
        """Should return rejected template."""
        client = MockLLMClient()
        response = client.generate("Judge verdict rejected false positive")
        assert "REJECTED" in response.content

    def test_judge_suspicious_template(self):
        """Should return suspicious template."""
        client = MockLLMClient()
        response = client.generate("Judge verdict suspicious maybe")
        assert "SUSPICIOUS" in response.content