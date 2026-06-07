"""
Abstract base interfaces for LLM clients.

Defines the contract that all LLM client implementations must follow,
allowing agents to use LLMs without being tied to specific providers.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass
class LLMResponse:
    """
    Standardized response from any LLM client.
    
    Attributes:
        content: The generated text content
        model: The model name used for generation
        tokens_used: Approximate token count (if available)
        latency_ms: Response latency in milliseconds (if available)
        metadata: Additional provider-specific metadata
        success: Whether the request succeeded
        error: Error message if success is False
    """
    content: str = ""
    model: str = ""
    tokens_used: int = 0
    latency_ms: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)
    success: bool = True
    error: str | None = None


class LLMClientBase(ABC):
    """
    Abstract base class for LLM clients.
    
    All LLM implementations (OpenAI, DeepSeek, Mock, etc.) must inherit
    from this class and implement the generate method.
    
    This abstraction allows agents to use LLMs without knowing the
    specific provider implementation.
    """
    
    @abstractmethod
    def generate(self, prompt: str, **kwargs) -> LLMResponse:
        """
        Generate text from a prompt.
        
        Args:
            prompt: The input prompt text
            **kwargs: Additional provider-specific options
                - temperature: Sampling temperature (0-1)
                - max_tokens: Maximum tokens to generate
                - system_prompt: System message (for chat models)
                - stop: Stop sequences
        
        Returns:
            LLMResponse with generated content and metadata
        """
        pass
    
    @abstractmethod
    def is_available(self) -> bool:
        """
        Check if the LLM client is available and properly configured.
        
        Returns:
            True if the client can make requests
        """
        pass
    
    @property
    @abstractmethod
    def provider_name(self) -> str:
        """
        Get the name of the LLM provider.
        
        Returns:
            Provider name (e.g., "openai", "deepseek", "mock")
        """
        pass
    
    @property
    @abstractmethod
    def default_model(self) -> str:
        """
        Get the default model name for this provider.
        
        Returns:
            Default model name
        """
        pass


class LLMClientFactory:
    """
    Factory for creating LLM clients based on configuration.
    
    Allows runtime selection of LLM provider without hardcoding
    specific implementations in agents.
    """
    
    _registry: dict[str, type[LLMClientBase]] = {}
    
    @classmethod
    def register(cls, provider: str, client_class: type[LLMClientBase]) -> None:
        """Register a client class for a provider."""
        cls._registry[provider.lower()] = client_class
    
    @classmethod
    def create(
        cls,
        provider: str,
        model: str | None = None,
        api_key: str | None = None,
        **kwargs
    ) -> LLMClientBase:
        """
        Create an LLM client for the specified provider.
        
        Args:
            provider: Provider name ("openai", "deepseek", "mock")
            model: Model name (optional, uses default if not specified)
            api_key: API key (optional for mock)
            **kwargs: Additional provider-specific options
        
        Returns:
            LLM client instance
        
        Raises:
            ValueError: If provider is not registered
        """
        provider_lower = provider.lower()
        if provider_lower not in cls._registry:
            raise ValueError(f"Unknown LLM provider: {provider}")
        
        client_class = cls._registry[provider_lower]
        return client_class(model=model, api_key=api_key, **kwargs)
    
    @classmethod
    def available_providers(cls) -> list[str]:
        """Get list of registered providers."""
        return list(cls._registry.keys())