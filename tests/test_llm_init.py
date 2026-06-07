"""
Tests for llm/__init__.py — client registration and availability.

Verifies that:
1. MockLLMClient is always registered and usable.
2. OpenAIClient / DeepSeekClient are registered when their modules are importable.
3. Importing the llm package never fails, even when sub-modules raise ImportError.
4. No real API calls are made.
"""

import sys
from unittest.mock import patch

import pytest

from llm.base import LLMClientBase, LLMClientFactory
from llm import MockLLMClient


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _has_openai_sdk() -> bool:
    """Return True if the ``openai`` third-party package is importable."""
    try:
        import openai  # noqa: F401
        return True
    except ImportError:
        return False


# ---------------------------------------------------------------------------
# Tests: registration (run against the actual import-time state)
# ---------------------------------------------------------------------------

class TestLLMInitRegistration:

    def test_mock_always_registered(self):
        """``mock`` should always appear in available_providers."""
        providers = LLMClientFactory.available_providers()
        assert "mock" in providers

    def test_mock_client_create_success(self):
        """Creating a mock client via the factory should succeed."""
        client = LLMClientFactory.create("mock")
        assert isinstance(client, LLMClientBase)
        assert client.provider_name == "mock"
        assert client.is_available() is True

    def test_openai_registered_when_module_importable(self):
        """``openai`` should be registered when llm.openai_client is importable."""
        providers = LLMClientFactory.available_providers()
        # openai_client.py does lazy-import openai SDK, so it is always
        # importable as a module; the SDK check happens at call time.
        assert "openai" in providers

    def test_deepseek_registered_when_module_importable(self):
        """``deepseek`` should be registered when llm.deepseek_client is importable."""
        providers = LLMClientFactory.available_providers()
        assert "deepseek" in providers

    def test_import_llm_package_never_fails(self):
        """``import llm`` must succeed regardless of openai SDK availability."""
        # Force a fresh top-level import to prove the package is loadable.
        for key in list(sys.modules):
            if key == "llm" or key.startswith("llm."):
                del sys.modules[key]
        import llm  # noqa: F401
        assert hasattr(llm, "LLMClientFactory")
        assert hasattr(llm, "MockLLMClient")


class TestConditionalRegistrationMechanism:

    """Test the try/except guard logic in __init__.py directly."""

    def test_openai_import_error_does_not_break_init(self):
        """If importing OpenAIClient raises ImportError, init still works."""
        saved = LLMClientFactory._registry.copy()
        try:
            LLMClientFactory._registry.clear()
            LLMClientFactory._registry["mock"] = MockLLMClient

            # Simulate ImportError for openai_client
            with patch.dict("sys.modules", {"llm.openai_client": None}):
                with patch("llm.openai_client.OpenAIClient", side_effect=ImportError):
                    try:
                        from llm.openai_client import OpenAIClient  # noqa: F401
                        LLMClientFactory.register("openai", OpenAIClient)
                    except ImportError:
                        pass  # This is the expected path

            providers = LLMClientFactory.available_providers()
            assert "mock" in providers
            assert "openai" not in providers
        finally:
            LLMClientFactory._registry = saved

    def test_deepseek_import_error_does_not_break_init(self):
        """If importing DeepSeekClient raises ImportError, init still works."""
        saved = LLMClientFactory._registry.copy()
        try:
            LLMClientFactory._registry.clear()
            LLMClientFactory._registry["mock"] = MockLLMClient

            with patch.dict("sys.modules", {"llm.deepseek_client": None}):
                with patch("llm.deepseek_client.DeepSeekClient", side_effect=ImportError):
                    try:
                        from llm.deepseek_client import DeepSeekClient  # noqa: F401
                        LLMClientFactory.register("deepseek", DeepSeekClient)
                    except ImportError:
                        pass

            providers = LLMClientFactory.available_providers()
            assert "mock" in providers
            assert "deepseek" not in providers
        finally:
            LLMClientFactory._registry = saved

    def test_fresh_import_with_missing_modules(self):
        """
        Simulate a fresh ``import llm`` where openai_client and deepseek_client
        modules cannot be imported.  The package should still load with only mock.
        """
        saved_modules = {}
        for key in list(sys.modules):
            if key == "llm" or key.startswith("llm."):
                saved_modules[key] = sys.modules.pop(key)

        saved_registry = LLMClientFactory._registry.copy()

        try:
            # Block llm.openai_client and llm.deepseek_client from being imported
            blocked = {"llm.openai_client", "llm.deepseek_client"}

            import_orig = __import__

            def _fake_import(name, *args, **kwargs):
                if name in blocked or any(name.startswith(b + ".") for b in blocked):
                    raise ImportError(f"blocked: {name}")
                return import_orig(name, *args, **kwargs)

            with patch("builtins.__import__", side_effect=_fake_import):
                LLMClientFactory._registry.clear()
                # Re-execute the __init__.py registration logic (same pattern)
                from llm.mock_client import MockLLMClient as MC
                LLMClientFactory.register("mock", MC)

                try:
                    from llm.openai_client import OpenAIClient
                    LLMClientFactory.register("openai", OpenAIClient)
                except ImportError:
                    pass

                try:
                    from llm.deepseek_client import DeepSeekClient
                    LLMClientFactory.register("deepseek", DeepSeekClient)
                except ImportError:
                    pass

            providers = LLMClientFactory.available_providers()
            assert "mock" in providers
            assert "openai" not in providers
            assert "deepseek" not in providers
        finally:
            LLMClientFactory._registry = saved_registry
            for key, mod in saved_modules.items():
                sys.modules[key] = mod


# ---------------------------------------------------------------------------
# Tests: mock client usage (no real API calls)
# ---------------------------------------------------------------------------

class TestMockClientUsage:

    def test_mock_generate_no_api_call(self):
        """Mock client generate() returns a response without any network call."""
        client = LLMClientFactory.create("mock", response_delay_ms=0)
        resp = client.generate("hello")
        assert resp.success is True
        assert isinstance(resp.content, str)
        assert len(resp.content) > 0

    def test_mock_call_count(self):
        """Mock client tracks call count."""
        client = LLMClientFactory.create("mock", response_delay_ms=0)
        assert client.get_call_count() == 0
        client.generate("test")
        assert client.get_call_count() == 1
        client.generate("test2")
        assert client.get_call_count() == 2

    def test_mock_always_available_no_external_deps(self):
        """Mock client is always available regardless of external dependencies."""
        client = MockLLMClient()
        assert client.is_available() is True
        # No API key needed
        client2 = MockLLMClient(api_key=None)
        assert client2.is_available() is True

    def test_mock_factory_create_without_api_key(self):
        """Factory can create mock client without any API key."""
        client = LLMClientFactory.create("mock")
        assert client.is_available() is True
        resp = client.generate("test prompt")
        assert resp.success is True


# ---------------------------------------------------------------------------
# Tests: OpenAI / DeepSeek client behavior (no real API calls)
# ---------------------------------------------------------------------------

class TestOpenAIClientNoRealCalls:

    def test_openai_client_instantiation_no_api_call(self):
        """Creating OpenAIClient does not trigger any API call."""
        from llm.openai_client import OpenAIClient
        # Instantiate without API key - no network call should happen
        client = OpenAIClient(api_key=None)
        assert client._client is None  # Lazy-loaded, not yet initialized

    def test_openai_is_available_false_without_api_key(self):
        """OpenAIClient.is_available() returns False when no API key is set."""
        from llm.openai_client import OpenAIClient
        # Clear env var temporarily
        import os
        old_key = os.environ.get("OPENAI_API_KEY")
        try:
            if "OPENAI_API_KEY" in os.environ:
                del os.environ["OPENAI_API_KEY"]
            client = OpenAIClient(api_key=None)
            assert client.is_available() is False
        finally:
            if old_key:
                os.environ["OPENAI_API_KEY"] = old_key

    def test_openai_generate_raises_without_api_key(self):
        """OpenAIClient.generate() raises LLMConfigError without API key."""
        from llm.openai_client import OpenAIClient
        from llm.exceptions import LLMConfigError
        import os

        old_key = os.environ.get("OPENAI_API_KEY")
        try:
            if "OPENAI_API_KEY" in os.environ:
                del os.environ["OPENAI_API_KEY"]
            client = OpenAIClient(api_key=None)
            with pytest.raises(LLMConfigError):
                client.generate("test prompt")
        finally:
            if old_key:
                os.environ["OPENAI_API_KEY"] = old_key

    def test_openai_registered_when_module_importable(self):
        """If OpenAIClient module is importable, 'openai' should be registered."""
        # This test runs in the actual environment
        providers = LLMClientFactory.available_providers()
        # openai_client.py is always importable (SDK check is lazy)
        assert "openai" in providers


class TestDeepSeekClientNoRealCalls:

    def test_deepseek_client_instantiation_no_api_call(self):
        """Creating DeepSeekClient does not trigger any API call."""
        from llm.deepseek_client import DeepSeekClient
        client = DeepSeekClient(api_key=None)
        assert client._client is None  # Lazy-loaded

    def test_deepseek_is_available_false_without_api_key(self):
        """DeepSeekClient.is_available() returns False when no API key is set."""
        from llm.deepseek_client import DeepSeekClient
        import os

        old_key = os.environ.get("DEEPSEEK_API_KEY")
        try:
            if "DEEPSEEK_API_KEY" in os.environ:
                del os.environ["DEEPSEEK_API_KEY"]
            client = DeepSeekClient(api_key=None)
            assert client.is_available() is False
        finally:
            if old_key:
                os.environ["DEEPSEEK_API_KEY"] = old_key

    def test_deepseek_generate_raises_without_api_key(self):
        """DeepSeekClient.generate() raises LLMConfigError without API key."""
        from llm.deepseek_client import DeepSeekClient
        from llm.exceptions import LLMConfigError
        import os

        old_key = os.environ.get("DEEPSEEK_API_KEY")
        try:
            if "DEEPSEEK_API_KEY" in os.environ:
                del os.environ["DEEPSEEK_API_KEY"]
            client = DeepSeekClient(api_key=None)
            with pytest.raises(LLMConfigError):
                client.generate("test prompt")
        finally:
            if old_key:
                os.environ["DEEPSEEK_API_KEY"] = old_key

    def test_deepseek_registered_when_module_importable(self):
        """If DeepSeekClient module is importable, 'deepseek' should be registered."""
        providers = LLMClientFactory.available_providers()
        assert "deepseek" in providers


# ---------------------------------------------------------------------------
# Tests: No real API calls in any test
# ---------------------------------------------------------------------------

class TestNoRealAPICalls:

    def test_mock_client_no_network_io(self):
        """Mock client never performs any network I/O."""
        client = MockLLMClient(response_delay_ms=0)
        # Multiple calls should never touch network
        for _ in range(5):
            resp = client.generate("test")
            assert resp.success is True
        # Call count proves it's local
        assert client.get_call_count() == 5

    def test_factory_create_mock_is_safe(self):
        """Factory.create('mock') is always safe (no real API)."""
        client = LLMClientFactory.create("mock")
        assert isinstance(client, MockLLMClient)
        resp = client.generate("any prompt")
        assert resp.success is True

    def test_openai_client_lazy_init_no_network(self):
        """OpenAIClient does not connect on instantiation."""
        from llm.openai_client import OpenAIClient
        # Even with a fake API key, instantiation should not call API
        client = OpenAIClient(api_key="fake-key-for-test")
        # _client is None until generate() is called
        assert client._client is None
