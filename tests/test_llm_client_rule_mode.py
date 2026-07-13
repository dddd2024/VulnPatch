import pytest

from llm.client import LLMClient
from llm.exceptions import LLMConfigError, LLMConnectionError


def test_llm_client_rule_mode_rejects_external_calls():
    client = LLMClient(ai_mode="rule")

    with pytest.raises(LLMConfigError, match="rule mode"):
        client.generate_text("hello")


def test_cloud_error_preserves_exception_detail(monkeypatch):
    class FailingOpenAI:
        def __init__(self, **kwargs):
            raise TypeError("Client.__init__() got an unexpected keyword argument 'proxies'")

    monkeypatch.setattr("llm.client.OpenAI", FailingOpenAI)
    monkeypatch.setattr(
        "llm.client.get_cloud_client_kwargs", lambda api_key_override=None: {"api_key": "sk-test"}
    )

    client = LLMClient(ai_mode="cloud", model_name="gpt-4.1")

    with pytest.raises(LLMConnectionError) as exc_info:
        client.generate_text("hello")

    message = str(exc_info.value)
    assert "cloud LLM request failed: TypeError" in message
    assert "unexpected keyword argument 'proxies'" in message


def test_cloud_mode_prefers_configured_api_over_copilot(monkeypatch):
    class FakeMessage:
        content = "api response"

    class FakeChoice:
        message = FakeMessage()

    class FakeResponse:
        choices = [FakeChoice()]

    class FakeCompletions:
        def create(self, **kwargs):
            assert kwargs["model"] == "configured-model"
            return FakeResponse()

    class FakeChat:
        completions = FakeCompletions()

    class FakeOpenAI:
        chat = FakeChat()

        def __init__(self, **kwargs):
            assert kwargs["api_key"] == "sk-test"

    def fail_copilot(self, prompt):
        raise AssertionError("configured API should be used before Copilot fallback")

    monkeypatch.setattr("llm.client.OpenAI", FakeOpenAI)
    monkeypatch.setattr(
        "llm.client.get_cloud_client_kwargs", lambda api_key_override=None: {"api_key": "sk-test"}
    )
    monkeypatch.setattr("llm.client.get_cloud_model", lambda default_model="gpt-4.1": "configured-model")
    monkeypatch.setattr("llm.client.LLMClient._try_copilot_cli", fail_copilot)

    client = LLMClient(ai_mode="cloud")

    assert client.generate_text("hello") == ("api response", "configured-model")
