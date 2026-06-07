"""
OpenAI LLM client implementation.

Provides integration with OpenAI's API for vulnerability analysis.
"""

import os
import time
from typing import Any

from llm.base import LLMClientBase, LLMResponse
from llm.exceptions import LLMConfigError, LLMConnectionError


class OpenAIClient(LLMClientBase):
    """
    OpenAI LLM client.
    
    Uses OpenAI's chat completions API for text generation.
    Requires OPENAI_API_KEY environment variable.
    """
    
    DEFAULT_MODEL = "gpt-4o-mini"
    
    def __init__(
        self,
        model: str | None = None,
        api_key: str | None = None,
        timeout: float = 30.0,
        base_url: str | None = None,
        **kwargs
    ) -> None:
        """
        Initialize OpenAI client.
        
        Args:
            model: Model name (defaults to gpt-4o-mini)
            api_key: API key (defaults to OPENAI_API_KEY env var)
            timeout: Request timeout in seconds
            base_url: Custom API base URL (optional)
            **kwargs: Additional options
        """
        self._model = model or self.DEFAULT_MODEL
        self._api_key = api_key or os.getenv("OPENAI_API_KEY")
        self._timeout = timeout
        self._base_url = base_url
        self._client = None
    
    def _get_client(self):
        """Lazy-load the OpenAI client."""
        if self._client is None:
            try:
                from openai import OpenAI
            except ImportError:
                raise LLMConfigError(
                    "OpenAI SDK is required. Install with: pip install openai"
                )
            
            if not self._api_key:
                raise LLMConfigError(
                    "OpenAI API key required. Set OPENAI_API_KEY environment "
                    "variable or pass api_key parameter."
                )
            
            options = {
                "api_key": self._api_key,
                "timeout": self._timeout,
            }
            if self._base_url:
                options["base_url"] = self._base_url
            
            self._client = OpenAI(**options)
        
        return self._client
    
    def generate(self, prompt: str, **kwargs) -> LLMResponse:
        """
        Generate text using OpenAI API.
        
        Args:
            prompt: Input prompt
            **kwargs: Additional options
                - temperature: Sampling temperature (0-1)
                - max_tokens: Maximum tokens to generate
                - system_prompt: System message
        
        Returns:
            LLMResponse with generated content
        """
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
                },
                success=True,
                error=None,
            )
        
        except LLMConfigError:
            raise
        except Exception as exc:
            return LLMResponse(
                content="",
                model=self._model,
                tokens_used=0,
                latency_ms=(time.time() - start_time) * 1000,
                metadata={},
                success=False,
                error=str(exc),
            )
    
    def is_available(self) -> bool:
        """Check if OpenAI API key is configured."""
        return bool(self._api_key or os.getenv("OPENAI_API_KEY"))
    
    @property
    def provider_name(self) -> str:
        """Provider name."""
        return "openai"
    
    @property
    def default_model(self) -> str:
        """Default model name."""
        return self.DEFAULT_MODEL