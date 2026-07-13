"""
Unified multi-platform LLM client for VulnPatch.

Supports multiple LLM providers through a single interface:
  - OpenAI (and OpenAI-compatible APIs like DeepSeek, Azure, etc.)
  - Anthropic Claude (via direct HTTP API using httpx)
  - Google Gemini (via direct HTTP API using httpx)
  - Ollama (local models via OpenAI-compatible API)
  - 通义千问 Qwen (Alibaba DashScope)
  - 智谱 GLM (Zhipu AI)
  - Moonshot (Kimi)
  - 豆包 Doubao (ByteDance)
  - Any custom OpenAI-compatible endpoint

Configuration is driven by environment variables:
  LLM_PROVIDER   - "openai" | "anthropic" | "gemini" | "ollama" | "deepseek" |
                   "qwen" | "glm" | "moonshot" | "doubao" (default: "deepseek")
  LLM_API_KEY    - API key for the selected provider
  LLM_BASE_URL   - Custom base URL (for Ollama or API proxies)
  LLM_MODEL      - Model name (default varies by provider)
  LLM_TEMPERATURE - Temperature (default: 0.3)
  LLM_MAX_TOKENS  - Max tokens (default: 4096)

Only requires the ``openai`` and ``httpx`` packages (both already installed).
No additional dependencies are needed.
"""

import json
import os
import random
import time
import logging
from typing import Any, Generator

from llm.base import LLMClientBase, LLMResponse
from llm.exceptions import LLMConfigError, LLMConnectionError, LLMTimeoutError

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Provider metadata
# ---------------------------------------------------------------------------

PROVIDER_DEFAULTS: dict[str, dict[str, Any]] = {
    "openai": {
        "default_model": "gpt-4o-mini",
        "api_base": "https://api.openai.com/v1",
        "key_prefix": "sk-",
        "key_env": "OPENAI_API_KEY",
    },
    "deepseek": {
        "default_model": "deepseek-chat",
        "api_base": "https://api.deepseek.com/v1",
        "key_prefix": "sk-",
        "key_env": "DEEPSEEK_API_KEY",
    },
    "anthropic": {
        "default_model": "claude-sonnet-4-20250514",
        "api_base": "https://api.anthropic.com/v1",
        "key_prefix": "sk-ant-",
        "key_env": "ANTHROPIC_API_KEY",
    },
    "gemini": {
        "default_model": "gemini-2.0-flash",
        "api_base": "https://generativelanguage.googleapis.com/v1beta",
        "key_prefix": "AI",
        "key_env": "GEMINI_API_KEY",
    },
    "ollama": {
        "default_model": "llama3",
        "api_base": "http://localhost:11434/v1",
        "key_prefix": "",  # Ollama typically needs no key
        "key_env": "",      # but we accept OLLAMA_API_KEY if set
    },
    "qwen": {
        "default_model": "qwen-max",
        "api_base": "https://dashscope.aliyuncs.com/compatible-mode/v1",
        "key_prefix": "sk-",
        "key_env": "DASHSCOPE_API_KEY",
    },
    "glm": {
        "default_model": "glm-4",
        "api_base": "https://open.bigmodel.cn/api/paas/v4",
        "key_prefix": "sk-",
        "key_env": "ZHIPU_API_KEY",
    },
    "moonshot": {
        "default_model": "moonshot-v1-8k",
        "api_base": "https://api.moonshot.cn/v1",
        "key_prefix": "sk-",
        "key_env": "MOONSHOT_API_KEY",
    },
    "doubao": {
        "default_model": "doubao-pro-32k",
        "api_base": "https://ark.cn-beijing.volces.com/api/v3",
        "key_prefix": "sk-",
        "key_env": "DOUBAO_API_KEY",
    },
}

# Anthropic API versions we support
ANTHROPIC_API_VERSION = "2023-06-01"

# ---------------------------------------------------------------------------
# Helper: auto-detect provider from API key prefix
# ---------------------------------------------------------------------------

def _detect_provider_from_key(api_key: str) -> str | None:
    """Guess the provider based on the API key prefix."""
    if not api_key:
        return None
    key_lower = api_key.lower()
    if key_lower.startswith("sk-ant-"):
        return "anthropic"
    if key_lower.startswith("ai"):
        return "gemini"
    if key_lower.startswith("sk-"):
        # Could be OpenAI, DeepSeek, or domestic providers -- check env vars
        if os.getenv("DEEPSEEK_API_KEY") == api_key:
            return "deepseek"
        if os.getenv("OPENAI_API_KEY") == api_key:
            return "openai"
        if os.getenv("DASHSCOPE_API_KEY") == api_key:
            return "qwen"
        if os.getenv("ZHIPU_API_KEY") == api_key:
            return "glm"
        if os.getenv("MOONSHOT_API_KEY") == api_key:
            return "moonshot"
        if os.getenv("DOUBAO_API_KEY") == api_key:
            return "doubao"
        return "openai"  # default for sk- prefix
    return None


# ---------------------------------------------------------------------------
# MultiLLMClient
# ---------------------------------------------------------------------------

class MultiLLMClient(LLMClientBase):
    """
    Unified multi-platform LLM client.

    Wraps multiple LLM providers (OpenAI, Anthropic, Gemini, Ollama, etc.)
    behind the same ``LLMClientBase`` interface so that agents can use any
    provider without code changes.

    The client auto-detects the provider from the ``LLM_PROVIDER`` env var
    (or from the API key prefix when ``LLM_PROVIDER`` is not set).

    For providers that expose an OpenAI-compatible chat completions endpoint
    (OpenAI, DeepSeek, Ollama, and any custom proxy), the ``openai`` SDK is
    used.  For Anthropic and Gemini, lightweight ``httpx`` calls are made
    directly so that no extra SDK dependency is required.
    """

    def __init__(
        self,
        provider: str | None = None,
        model: str | None = None,
        api_key: str | None = None,
        base_url: str | None = None,
        temperature: float | None = None,
        max_tokens: int | None = None,
        timeout: float = 120.0,
        max_retries: int = 3,
        **kwargs: Any,
    ) -> None:
        """
        Initialise the multi-platform client.

        Parameters are resolved in this priority order:
          1. Explicit argument
          2. ``LLM_*`` environment variable
          3. Provider-specific default

        Args:
            provider:    LLM provider name (default: ``LLM_PROVIDER`` or ``"deepseek"``)
            model:       Model name (default: ``LLM_MODEL`` or provider default)
            api_key:     API key (default: ``LLM_API_KEY`` or provider-specific env var)
            base_url:    Custom API base URL (default: ``LLM_BASE_URL`` or provider default)
            temperature: Sampling temperature (default: ``LLM_TEMPERATURE`` or 0.3)
            max_tokens:  Max tokens to generate (default: ``LLM_MAX_TOKENS`` or 4096)
            timeout:     HTTP request timeout in seconds (default: 120)
            max_retries: Max retry attempts on transient errors (default: 3)
            **kwargs:    Ignored (for forward-compat)
        """
        # --- Resolve provider ------------------------------------------------
        self._provider = (provider or os.getenv("LLM_PROVIDER") or "").lower()

        # Auto-detect if not explicitly set
        if not self._provider or self._provider == "auto":
            resolved_key = api_key or os.getenv("LLM_API_KEY")
            self._provider = _detect_provider_from_key(resolved_key) or "deepseek"

        if self._provider not in PROVIDER_DEFAULTS:
            # Treat unknown providers as generic OpenAI-compatible endpoints
            logger.info(
                "Unknown provider '%s', treating as OpenAI-compatible.", self._provider
            )

        meta = PROVIDER_DEFAULTS.get(self._provider, {})

        # --- Resolve model ---------------------------------------------------
        self._model = (
            model
            or os.getenv("LLM_MODEL")
            or meta.get("default_model", "gpt-4o-mini")
        )

        # --- Resolve API key -------------------------------------------------
        self._api_key = (
            api_key
            or os.getenv("LLM_API_KEY")
            or os.getenv(meta.get("key_env", ""))
            if meta.get("key_env")
            else api_key or os.getenv("LLM_API_KEY")
        )

        # --- Resolve base URL ------------------------------------------------
        self._base_url = (
            base_url
            or os.getenv("LLM_BASE_URL")
            or meta.get("api_base")
        )

        # --- Resolve generation params ---------------------------------------
        self._temperature = (
            temperature
            if temperature is not None
            else float(os.getenv("LLM_TEMPERATURE", "0.3"))
        )
        self._max_tokens = (
            max_tokens
            if max_tokens is not None
            else int(os.getenv("LLM_MAX_TOKENS", "4096"))
        )

        self._timeout = timeout
        self._max_retries = max_retries

        # Lazy-loaded clients
        self._openai_client = None
        self._http_client = None  # httpx.AsyncClient / Client for Anthropic/Gemini

    # -----------------------------------------------------------------------
    # Internal: lazy-load clients
    # -----------------------------------------------------------------------

    def _get_openai_client(self):
        """Return a cached ``openai.OpenAI`` instance (for OpenAI-compatible providers)."""
        if self._openai_client is None:
            try:
                from openai import OpenAI
            except ImportError:
                raise LLMConfigError(
                    "The 'openai' package is required for OpenAI-compatible providers. "
                    "Install with: pip install openai"
                )

            kwargs: dict[str, Any] = {
                "timeout": self._timeout,
            }
            if self._api_key:
                kwargs["api_key"] = self._api_key
            if self._base_url:
                kwargs["base_url"] = self._base_url

            self._openai_client = OpenAI(**kwargs)
        return self._openai_client

    def _get_http_client(self):
        """Return a cached ``httpx.Client`` for direct HTTP calls (Anthropic / Gemini)."""
        if self._http_client is None:
            try:
                import httpx
            except ImportError:
                raise LLMConfigError(
                    "The 'httpx' package is required for Anthropic/Gemini providers. "
                    "Install with: pip install httpx"
                )
            self._http_client = httpx.Client(timeout=self._timeout)
        return self._http_client

    # -----------------------------------------------------------------------
    # Retry helper
    # -----------------------------------------------------------------------

    @staticmethod
    def _is_retryable(exc: Exception) -> bool:
        """Return True if the exception represents a transient failure."""
        msg = str(exc).lower()
        keywords = [
            "rate limit", "timeout", "connection", "server error",
            "502", "503", "504", "overloaded", "capacity",
            "temporarily unavailable", "too many requests",
        ]
        return any(kw in msg for kw in keywords)

    def _retry_backoff(self, attempt: int) -> float:
        """Exponential backoff with jitter."""
        return min(2 ** attempt + random.uniform(0, 1), 10)

    # -----------------------------------------------------------------------
    # Build messages list (shared across providers)
    # -----------------------------------------------------------------------

    @staticmethod
    def _build_messages(prompt: str, **kwargs: Any) -> list[dict[str, str]]:
        """Build the messages list from prompt and optional system_prompt."""
        messages: list[dict[str, str]] = []
        system_prompt = kwargs.get("system_prompt")
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})
        return messages

    # -----------------------------------------------------------------------
    # generate() -- dispatch to the right backend
    # -----------------------------------------------------------------------

    def generate(self, prompt: str, **kwargs: Any) -> LLMResponse:
        """
        Generate text using the configured LLM provider.

        Supports the same kwargs as DeepSeekClient:
          - temperature, max_tokens, system_prompt

        Returns:
            LLMResponse
        """
        if self._provider in ("anthropic",):
            return self._generate_anthropic(prompt, **kwargs)
        if self._provider in ("gemini",):
            return self._generate_gemini(prompt, **kwargs)
        # OpenAI, DeepSeek, Ollama, and any unknown provider -> OpenAI SDK
        return self._generate_openai_compat(prompt, **kwargs)

    # -----------------------------------------------------------------------
    # OpenAI-compatible backend (openai SDK)
    # -----------------------------------------------------------------------

    def _generate_openai_compat(self, prompt: str, **kwargs: Any) -> LLMResponse:
        """Generate via OpenAI-compatible chat completions API."""
        last_error: Exception | None = None

        for attempt in range(self._max_retries):
            start = time.time()
            try:
                client = self._get_openai_client()
                messages = self._build_messages(prompt, **kwargs)

                options: dict[str, Any] = {
                    "model": self._model,
                    "messages": messages,
                    "temperature": kwargs.get("temperature", self._temperature),
                    "max_tokens": kwargs.get("max_tokens", self._max_tokens),
                }

                response = client.chat.completions.create(**options)

                latency_ms = (time.time() - start) * 1000
                content = response.choices[0].message.content or ""

                return LLMResponse(
                    content=content.strip(),
                    model=response.model or self._model,
                    tokens_used=response.usage.total_tokens if response.usage else 0,
                    latency_ms=latency_ms,
                    metadata={
                        "provider": self._provider,
                        "prompt_tokens": response.usage.prompt_tokens if response.usage else 0,
                        "completion_tokens": response.usage.completion_tokens if response.usage else 0,
                        "attempt": attempt + 1,
                    },
                    success=True,
                    error=None,
                )

            except LLMConfigError:
                raise
            except Exception as exc:
                last_error = exc
                logger.warning(
                    "[%s] API call failed (attempt %d/%d): %s",
                    self._provider, attempt + 1, self._max_retries, exc,
                )
                if not self._is_retryable(exc) or attempt == self._max_retries - 1:
                    break
                time.sleep(self._retry_backoff(attempt))

        return LLMResponse(
            content="",
            model=self._model,
            tokens_used=0,
            latency_ms=0,
            metadata={"provider": self._provider, "attempts": self._max_retries},
            success=False,
            error=str(last_error),
        )

    # -----------------------------------------------------------------------
    # Anthropic backend (httpx direct call)
    # -----------------------------------------------------------------------

    def _generate_anthropic(self, prompt: str, **kwargs: Any) -> LLMResponse:
        """Generate via Anthropic Messages API using httpx."""
        if not self._api_key:
            raise LLMConfigError(
                "Anthropic API key required. Set ANTHROPIC_API_KEY or "
                "LLM_API_KEY environment variable."
            )

        last_error: Exception | None = None

        for attempt in range(self._max_retries):
            start = time.time()
            try:
                client = self._get_http_client()
                messages = self._build_messages(prompt, **kwargs)

                # Anthropic uses a separate system parameter, not a system message
                system_text = kwargs.get("system_prompt", "")
                # Remove system message from messages list
                api_messages = [
                    m for m in messages if m["role"] != "system"
                ]

                payload: dict[str, Any] = {
                    "model": self._model,
                    "messages": api_messages,
                    "max_tokens": kwargs.get("max_tokens", self._max_tokens),
                    "temperature": kwargs.get("temperature", self._temperature),
                }
                if system_text:
                    payload["system"] = system_text

                base = self._base_url.rstrip("/")
                resp = client.post(
                    f"{base}/messages",
                    headers={
                        "x-api-key": self._api_key,
                        "anthropic-version": ANTHROPIC_API_VERSION,
                        "content-type": "application/json",
                    },
                    json=payload,
                )
                resp.raise_for_status()
                data = resp.json()

                latency_ms = (time.time() - start) * 1000

                # Extract text from Anthropic response
                content_parts = []
                input_tokens = data.get("usage", {}).get("input_tokens", 0)
                output_tokens = data.get("usage", {}).get("output_tokens", 0)
                for block in data.get("content", []):
                    if block.get("type") == "text":
                        content_parts.append(block.get("text", ""))

                content = "\n".join(content_parts)

                return LLMResponse(
                    content=content.strip(),
                    model=data.get("model", self._model),
                    tokens_used=input_tokens + output_tokens,
                    latency_ms=latency_ms,
                    metadata={
                        "provider": "anthropic",
                        "prompt_tokens": input_tokens,
                        "completion_tokens": output_tokens,
                        "attempt": attempt + 1,
                    },
                    success=True,
                    error=None,
                )

            except LLMConfigError:
                raise
            except Exception as exc:
                last_error = exc
                logger.warning(
                    "[anthropic] API call failed (attempt %d/%d): %s",
                    attempt + 1, self._max_retries, exc,
                )
                if not self._is_retryable(exc) or attempt == self._max_retries - 1:
                    break
                time.sleep(self._retry_backoff(attempt))

        return LLMResponse(
            content="",
            model=self._model,
            tokens_used=0,
            latency_ms=0,
            metadata={"provider": "anthropic", "attempts": self._max_retries},
            success=False,
            error=str(last_error),
        )

    # -----------------------------------------------------------------------
    # Gemini backend (httpx direct call)
    # -----------------------------------------------------------------------

    def _generate_gemini(self, prompt: str, **kwargs: Any) -> LLMResponse:
        """Generate via Google Gemini API using httpx."""
        if not self._api_key:
            raise LLMConfigError(
                "Gemini API key required. Set GEMINI_API_KEY or "
                "LLM_API_KEY environment variable."
            )

        last_error: Exception | None = None

        for attempt in range(self._max_retries):
            start = time.time()
            try:
                client = self._get_http_client()
                system_text = kwargs.get("system_prompt", "")

                # Build Gemini-style contents
                parts: list[dict[str, Any]] = [{"text": prompt}]
                contents: list[dict[str, Any]] = [{"role": "user", "parts": parts}]

                payload: dict[str, Any] = {
                    "contents": contents,
                    "generationConfig": {
                        "temperature": kwargs.get("temperature", self._temperature),
                        "maxOutputTokens": kwargs.get("max_tokens", self._max_tokens),
                    },
                }
                if system_text:
                    payload["systemInstruction"] = {"parts": [{"text": system_text}]}

                base = self._base_url.rstrip("/")
                url = f"{base}/models/{self._model}:generateContent?key={self._api_key}"

                resp = client.post(
                    url,
                    headers={"content-type": "application/json"},
                    json=payload,
                )
                resp.raise_for_status()
                data = resp.json()

                latency_ms = (time.time() - start) * 1000

                # Extract text from Gemini response
                content_parts = []
                usage_meta = data.get("usageMetadata", {})
                input_tokens = usage_meta.get("promptTokenCount", 0)
                output_tokens = usage_meta.get("candidatesTokenCount", 0)

                for candidate in data.get("candidates", []):
                    for part in candidate.get("content", {}).get("parts", []):
                        if "text" in part:
                            content_parts.append(part["text"])

                content = "\n".join(content_parts)

                return LLMResponse(
                    content=content.strip(),
                    model=self._model,
                    tokens_used=input_tokens + output_tokens,
                    latency_ms=latency_ms,
                    metadata={
                        "provider": "gemini",
                        "prompt_tokens": input_tokens,
                        "completion_tokens": output_tokens,
                        "attempt": attempt + 1,
                    },
                    success=True,
                    error=None,
                )

            except LLMConfigError:
                raise
            except Exception as exc:
                last_error = exc
                logger.warning(
                    "[gemini] API call failed (attempt %d/%d): %s",
                    attempt + 1, self._max_retries, exc,
                )
                if not self._is_retryable(exc) or attempt == self._max_retries - 1:
                    break
                time.sleep(self._retry_backoff(attempt))

        return LLMResponse(
            content="",
            model=self._model,
            tokens_used=0,
            latency_ms=0,
            metadata={"provider": "gemini", "attempts": self._max_retries},
            success=False,
            error=str(last_error),
        )

    # -----------------------------------------------------------------------
    # generate_stream() -- streaming support
    # -----------------------------------------------------------------------

    def generate_stream(self, prompt: str, **kwargs: Any) -> Generator[str, None, None]:
        """
        Stream text generation from the configured LLM provider.

        For OpenAI-compatible providers (OpenAI, DeepSeek, Ollama), native
        streaming via the ``openai`` SDK is used.

        For Anthropic and Gemini, a fallback non-streaming call is made and
        the full response is yielded as a single chunk (since streaming these
        via httpx would require significantly more complex SSE parsing).

        Yields:
            String chunks of generated content
        """
        if self._provider in ("anthropic", "gemini"):
            # Fallback: non-streaming for Anthropic/Gemini
            try:
                response = self.generate(prompt, **kwargs)
                if response.success and response.content:
                    yield response.content
                else:
                    yield f"[Error: {response.error}]"
            except Exception as exc:
                logger.error("[%s] streaming fallback failed: %s", self._provider, exc)
                yield f"[Error: {exc}]"
            return

        # OpenAI-compatible streaming
        try:
            client = self._get_openai_client()
            messages = self._build_messages(prompt, **kwargs)

            options: dict[str, Any] = {
                "model": self._model,
                "messages": messages,
                "stream": True,
                "temperature": kwargs.get("temperature", self._temperature),
                "max_tokens": kwargs.get("max_tokens", self._max_tokens),
            }

            stream = client.chat.completions.create(**options)
            for chunk in stream:
                if chunk.choices and chunk.choices[0].delta.content:
                    yield chunk.choices[0].delta.content

        except Exception as exc:
            logger.error("[%s] streaming failed: %s", self._provider, exc)
            yield f"[Error: {exc}]"

    # -----------------------------------------------------------------------
    # LLMClientBase interface
    # -----------------------------------------------------------------------

    def is_available(self) -> bool:
        """Check if the client is properly configured and ready."""
        # Ollama does not require an API key
        if self._provider == "ollama":
            return bool(self._base_url)
        return bool(self._api_key)

    @property
    def provider_name(self) -> str:
        """Return the configured provider name."""
        return self._provider

    @property
    def default_model(self) -> str:
        """Return the default model for the configured provider."""
        meta = PROVIDER_DEFAULTS.get(self._provider, {})
        return meta.get("default_model", self._model)

    # -----------------------------------------------------------------------
    # Convenience: create from environment only
    # -----------------------------------------------------------------------

    @classmethod
    def from_env(cls, **overrides: Any) -> "MultiLLMClient":
        """
        Create a MultiLLMClient entirely from environment variables,
        with optional overrides.

        This is the recommended way to instantiate the client when
        configuration comes from the environment.

        Usage::

            client = MultiLLMClient.from_env()
            response = client.generate("Hello", system_prompt="You are helpful.")

        Args:
            **overrides: Any parameter accepted by ``__init__``

        Returns:
            Configured MultiLLMClient instance
        """
        return cls(**overrides)


# ---------------------------------------------------------------------------
# Anthropic streaming support (SSE via httpx)
# ---------------------------------------------------------------------------

class _AnthropicStreamAdapter:
    """
    Helper that streams Anthropic responses via SSE.

    Used internally by ``MultiLLMClient.generate_stream`` when the provider
    is "anthropic".  Parses the server-sent events and yields text deltas.
    """

    @staticmethod
    def stream(
        client: Any,
        base_url: str,
        api_key: str,
        model: str,
        messages: list[dict[str, str]],
        system_text: str,
        max_tokens: int,
        temperature: float,
    ) -> Generator[str, None, None]:
        """Stream from Anthropic Messages API using SSE."""
        payload: dict[str, Any] = {
            "model": model,
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "stream": True,
        }
        if system_text:
            payload["system"] = system_text

        base = base_url.rstrip("/")
        try:
            with client.stream(
                "POST",
                f"{base}/messages",
                headers={
                    "x-api-key": api_key,
                    "anthropic-version": ANTHROPIC_API_VERSION,
                    "content-type": "application/json",
                },
                json=payload,
            ) as resp:
                resp.raise_for_status()
                for line in resp.iter_lines():
                    if not line or not line.startswith("data: "):
                        continue
                    data_str = line[6:]  # strip "data: "
                    if data_str.strip() == "[DONE]":
                        break
                    try:
                        event = json.loads(data_str)
                        event_type = event.get("type", "")
                        if event_type == "content_block_delta":
                            delta = event.get("delta", {})
                            if delta.get("type") == "text_delta":
                                text = delta.get("text", "")
                                if text:
                                    yield text
                    except (json.JSONDecodeError, KeyError):
                        continue
        except Exception as exc:
            yield f"[Error: {exc}]"
