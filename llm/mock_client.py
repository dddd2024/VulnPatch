"""
Mock LLM client for testing purposes.

This client does not make real API calls and returns predefined
responses, allowing tests to run without API keys.
"""

import time
from typing import Any

from llm.base import LLMClientBase, LLMResponse


class MockLLMClient(LLMClientBase):
    """
    Mock LLM client for testing.
    
    Returns predefined responses based on prompt patterns,
    simulating realistic LLM behavior without actual API calls.
    """
    
    # Predefined response templates based on prompt keywords
    RESPONSE_TEMPLATES = {
        "vulnerability": {
            "sql": (
                "## Vulnerability Analysis\n\n"
                "Type: SQL Injection (CWE-89)\n\n"
                "The code constructs SQL queries by directly concatenating user input "
                "into the query string. This allows attackers to manipulate the query "
                "logic and potentially extract, modify, or delete data.\n\n"
                "Attack Vector: User-controlled input flows into execute() without "
                "parameterization.\n\n"
                "Recommendation: Use parameterized queries or prepared statements."
            ),
            "xss": (
                "## Vulnerability Analysis\n\n"
                "Type: Cross-Site Scripting (CWE-79)\n\n"
                "The code directly writes user input to HTML output without sanitization. "
                "This allows attackers to inject malicious scripts that execute in "
                "victim browsers.\n\n"
                "Attack Vector: User input rendered in innerHTML or response.send().\n\n"
                "Recommendation: Use HTML sanitization libraries or content security policy."
            ),
            "command": (
                "## Vulnerability Analysis\n\n"
                "Type: Command Injection (CWE-78)\n\n"
                "The code executes system commands with user-controlled input. "
                "Attackers can inject arbitrary commands to execute on the server.\n\n"
                "Attack Vector: User input passed to system(), exec(), or subprocess "
                "with shell=True.\n\n"
                "Recommendation: Avoid shell=True, use argument lists, and validate input."
            ),
            "path": (
                "## Vulnerability Analysis\n\n"
                "Type: Path Traversal (CWE-22)\n\n"
                "The code uses user input to construct file paths without validation. "
                "Attackers can access files outside intended directories.\n\n"
                "Attack Vector: User input in open() or file operations.\n\n"
                "Recommendation: Validate paths, use basename, and restrict allowed directories."
            ),
            "default": (
                "## Vulnerability Analysis\n\n"
                "A potential security vulnerability has been identified. "
                "Further investigation is recommended to determine the exact "
                "attack vector and impact."
            ),
        },
        "attack_surface": (
            "## Attack Surface Analysis\n\n"
            "Identified potential entry points:\n\n"
            "1. Web Routes: HTTP endpoints accepting user input\n"
            "2. File Operations: Functions reading/writing files\n"
            "3. Database Queries: SQL execution points\n"
            "4. Command Execution: System command invocations\n"
            "5. Deserialization: Object deserialization operations\n\n"
            "Recommendation: Focus security review on these entry points."
        ),
        "evidence": (
            "## Evidence Summary\n\n"
            "The vulnerability trace shows:\n\n"
            "1. Source: User input from request parameters\n"
            "2. Propagation: Data flows through variable assignments\n"
            "3. Sink: Dangerous function call with tainted data\n\n"
            "Confidence: HIGH - Clear data flow from source to sink."
        ),
        "judge": {
            "confirmed": (
                "## Judge Decision\n\n"
                "Verdict: CONFIRMED\n\n"
                "The vulnerability is real and exploitable. Evidence shows clear "
                "attack path from user input to dangerous sink.\n\n"
                "Risk Score: 85/100\n\n"
                "Reason: Direct data flow without sanitization, known attack patterns apply."
            ),
            "suspicious": (
                "## Judge Decision\n\n"
                "Verdict: SUSPICIOUS\n\n"
                "The vulnerability may be real but requires manual verification. "
                "Some evidence suggests potential exploitability.\n\n"
                "Risk Score: 50/100\n\n"
                "Reason: Indirect data flow or partial sanitization detected."
            ),
            "rejected": (
                "## Judge Decision\n\n"
                "Verdict: REJECTED\n\n"
                "The reported finding is likely not exploitable. Evidence shows "
                "adequate protection or unreachable attack path.\n\n"
                "Risk Score: 15/100\n\n"
                "Reason: Sanitization present or data flow not reachable."
            ),
        },
        "default": (
            "## Response\n\n"
            "I have analyzed the provided information. Based on the context, "
            "this appears to be a security-related concern that warrants further "
            "investigation.\n\n"
            "Recommendation: Review the code for proper input validation and "
            "output encoding."
        ),
    }
    
    def __init__(
        self,
        model: str | None = None,
        api_key: str | None = None,
        response_delay_ms: float = 50,
        **kwargs
    ) -> None:
        """
        Initialize mock client.
        
        Args:
            model: Model name (ignored, for interface compatibility)
            api_key: API key (ignored, for interface compatibility)
            response_delay_ms: Simulated response latency in milliseconds
            **kwargs: Additional options (ignored)
        """
        self._model = model or "mock-model"
        self._api_key = api_key
        self._delay_ms = response_delay_ms
        self._call_count = 0
    
    def generate(self, prompt: str, **kwargs) -> LLMResponse:
        """
        Generate a mock response based on prompt content.
        
        Args:
            prompt: Input prompt
            **kwargs: Additional options (ignored)
        
        Returns:
            LLMResponse with predefined content
        """
        # Simulate latency
        if self._delay_ms > 0:
            time.sleep(self._delay_ms / 1000)
        
        self._call_count += 1
        
        # Determine response based on prompt keywords
        content = self._match_response(prompt)
        
        return LLMResponse(
            content=content,
            model=self._model,
            tokens_used=len(prompt.split()) + len(content.split()),
            latency_ms=self._delay_ms,
            metadata={
                "mock_call_count": self._call_count,
                "prompt_length": len(prompt),
            },
            success=True,
            error=None,
        )
    
    def _match_response(self, prompt: str) -> str:
        """Match prompt to predefined response template."""
        prompt_lower = prompt.lower()
        
        # Check for vulnerability analysis
        if "vulnerability" in prompt_lower or "漏洞" in prompt:
            vuln_type = self._detect_vuln_type(prompt_lower)
            return self.RESPONSE_TEMPLATES["vulnerability"].get(
                vuln_type,
                self.RESPONSE_TEMPLATES["vulnerability"]["default"]
            )
        
        # Check for attack surface
        if "attack surface" in prompt_lower or "攻击面" in prompt:
            return self.RESPONSE_TEMPLATES["attack_surface"]
        
        # Check for evidence summary
        if "evidence" in prompt_lower or "证据" in prompt:
            return self.RESPONSE_TEMPLATES["evidence"]
        
        # Check for judge decision
        if "judge" in prompt_lower or "裁决" in prompt:
            verdict = self._detect_verdict(prompt_lower)
            return self.RESPONSE_TEMPLATES["judge"].get(
                verdict,
                self.RESPONSE_TEMPLATES["judge"]["confirmed"]
            )
        
        return self.RESPONSE_TEMPLATES["default"]
    
    def _detect_vuln_type(self, prompt_lower: str) -> str:
        """Detect vulnerability type from prompt."""
        if "sql" in prompt_lower:
            return "sql"
        if "xss" in prompt_lower or "script" in prompt_lower:
            return "xss"
        if "command" in prompt_lower or "exec" in prompt_lower:
            return "command"
        if "path" in prompt_lower or "traversal" in prompt_lower or "file" in prompt_lower:
            return "path"
        return "default"
    
    def _detect_verdict(self, prompt_lower: str) -> str:
        """Detect expected verdict from prompt."""
        if "reject" in prompt_lower or "false" in prompt_lower:
            return "rejected"
        if "suspicious" in prompt_lower or "maybe" in prompt_lower:
            return "suspicious"
        return "confirmed"
    
    def is_available(self) -> bool:
        """Mock client is always available."""
        return True
    
    @property
    def provider_name(self) -> str:
        """Provider name."""
        return "mock"
    
    @property
    def default_model(self) -> str:
        """Default model name."""
        return "mock-model"
    
    def get_call_count(self) -> int:
        """Get number of generate calls made."""
        return self._call_count
    
    def reset_call_count(self) -> None:
        """Reset call count."""
        self._call_count = 0