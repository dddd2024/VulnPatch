"""
Exceptions for LLM client operations.
"""


class LLMError(Exception):
    """Base exception for LLM-related errors."""
    pass


class LLMConfigError(LLMError):
    """Error in LLM client configuration."""
    pass


class LLMConnectionError(LLMError):
    """Error connecting to LLM API."""
    pass


class LLMTimeoutError(LLMError):
    """Timeout waiting for LLM response."""
    pass


class LLMRateLimitError(LLMError):
    """Rate limit exceeded."""
    pass


class LLMResponseError(LLMError):
    """Error in LLM response."""
    pass