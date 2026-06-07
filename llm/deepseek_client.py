"""
DeepSeek LLM client implementation.

Provides integration with DeepSeek's API for vulnerability analysis.
Enhanced with streaming, retry, and SSE support.
"""

import os
import time
import logging
from typing import Any, Generator

from llm.base import LLMClientBase, LLMResponse
from llm.exceptions import LLMConfigError, LLMConnectionError, LLMTimeoutError

logger = logging.getLogger(__name__)


class DeepSeekClient(LLMClientBase):
    """
    DeepSeek LLM client.
    
    Uses DeepSeek's OpenAI-compatible API for text generation.
    Requires DEEPSEEK_API_KEY environment variable.
    
    Features:
    - Standard generate() for synchronous calls
    - generate_stream() for streaming token-by-token output
    - Automatic retry with exponential backoff on transient errors
    - Configurable base_url for API proxy support
    """
    
    DEFAULT_MODEL = "deepseek-chat"
    API_BASE = "https://api.deepseek.com/v1"
    
    def __init__(
        self,
        model: str | None = None,
        api_key: str | None = None,
        timeout: float = 60.0,
        max_retries: int = 3,
        base_url: str | None = None,
        **kwargs
    ) -> None:
        """
        Initialize DeepSeek client.
        
        Args:
            model: Model name (defaults to deepseek-chat)
            api_key: API key (defaults to DEEPSEEK_API_KEY env var)
            timeout: Request timeout in seconds
            max_retries: Max retry attempts on transient errors
            base_url: Optional custom API base URL (for proxies)
            **kwargs: Additional options
        """
        self._model = model or os.getenv("DEEPSEEK_MODEL", self.DEFAULT_MODEL)
        self._api_key = api_key or os.getenv("DEEPSEEK_API_KEY")
        self._timeout = timeout
        self._max_retries = max_retries
        self._base_url = base_url or os.getenv("DEEPSEEK_BASE_URL", self.API_BASE)
        self._client = None
    
    def _get_client(self):
        """Lazy-load the OpenAI client (DeepSeek uses OpenAI-compatible API)."""
        if self._client is None:
            try:
                from openai import OpenAI
            except ImportError:
                raise LLMConfigError(
                    "OpenAI SDK is required for DeepSeek client. "
                    "Install with: pip install openai"
                )
            
            if not self._api_key:
                raise LLMConfigError(
                    "DeepSeek API key required. Set DEEPSEEK_API_KEY environment "
                    "variable or pass api_key parameter."
                )
            
            self._client = OpenAI(
                api_key=self._api_key,
                base_url=self._base_url,
                timeout=self._timeout,
            )
        
        return self._client
    
    def _is_retryable(self, exc: Exception) -> bool:
        """Check if an exception is retryable (transient)."""
        exc_str = str(exc).lower()
        retryable_keywords = [
            "rate limit", "timeout", "connection", "server error",
            "502", "503", "504", "overloaded", "capacity",
        ]
        return any(kw in exc_str for kw in retryable_keywords)
    
    def generate(self, prompt: str, **kwargs) -> LLMResponse:
        """
        Generate text using DeepSeek API with automatic retry.
        
        Args:
            prompt: Input prompt
            **kwargs: Additional options
                - temperature: Sampling temperature (0-1)
                - max_tokens: Maximum tokens to generate
                - system_prompt: System message
        
        Returns:
            LLMResponse with generated content
        """
        last_error = None
        
        for attempt in range(self._max_retries):
            start_time = time.time()
            
            try:
                client = self._get_client()
                
                # Build messages
                messages = []
                system_prompt = kwargs.get("system_prompt")
                if system_prompt:
                    messages.append({"role": "system", "content": system_prompt})
                messages.append({"role": "user", "content": prompt})
                
                # Build request options
                options = {
                    "model": self._model,
                    "messages": messages,
                }
                if "temperature" in kwargs:
                    options["temperature"] = kwargs["temperature"]
                if "max_tokens" in kwargs:
                    options["max_tokens"] = kwargs["max_tokens"]
                
                response = client.chat.completions.create(**options)
                
                latency_ms = (time.time() - start_time) * 1000
                content = response.choices[0].message.content or ""
                
                return LLMResponse(
                    content=content.strip(),
                    model=response.model or self._model,
                    tokens_used=response.usage.total_tokens if response.usage else 0,
                    latency_ms=latency_ms,
                    metadata={
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
                    "DeepSeek API call failed (attempt %d/%d): %s",
                    attempt + 1, self._max_retries, exc
                )
                
                if not self._is_retryable(exc) or attempt == self._max_retries - 1:
                    break
                
                # Exponential backoff
                import random
                backoff = min(2 ** attempt + random.uniform(0, 1), 10)
                time.sleep(backoff)
        
        return LLMResponse(
            content="",
            model=self._model,
            tokens_used=0,
            latency_ms=0,
            metadata={"attempts": self._max_retries},
            success=False,
            error=str(last_error),
        )
    
    def generate_stream(self, prompt: str, **kwargs) -> Generator[str, None, None]:
        """
        Stream text generation from DeepSeek API.
        
        Yields content chunks as they arrive, suitable for SSE.
        
        Args:
            prompt: Input prompt
            **kwargs: Additional options (same as generate)
        
        Yields:
            String chunks of generated content
        """
        client = self._get_client()
        
        messages = []
        system_prompt = kwargs.get("system_prompt")
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})
        
        options = {
            "model": self._model,
            "messages": messages,
            "stream": True,
        }
        if "temperature" in kwargs:
            options["temperature"] = kwargs["temperature"]
        if "max_tokens" in kwargs:
            options["max_tokens"] = kwargs["max_tokens"]
        
        try:
            stream = client.chat.completions.create(**options)
            for chunk in stream:
                if chunk.choices and chunk.choices[0].delta.content:
                    yield chunk.choices[0].delta.content
        except Exception as exc:
            logger.error("DeepSeek streaming failed: %s", exc)
            yield f"[Error: {exc}]"
    
    def is_available(self) -> bool:
        """Check if DeepSeek API key is configured."""
        return bool(self._api_key or os.getenv("DEEPSEEK_API_KEY"))
    
    @property
    def provider_name(self) -> str:
        """Provider name."""
        return "deepseek"
    
    @property
    def default_model(self) -> str:
        """Default model name."""
        return self.DEFAULT_MODEL