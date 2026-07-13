"""
RAG (Retrieval-Augmented Generation) retriever.

Retrieves relevant context from knowledge bases for vulnerability analysis.
Implements a lightweight, deterministic, no-external-dependency knowledge retriever.
"""

from typing import Any
import re
import json


# Built-in vulnerability knowledge base
VULNERABILITY_KNOWLEDGE_BASE = [
    {
        "id": "vuln-001",
        "title": "SQL Injection",
        "vulnerability_type": "SQL Injection",
        "cwe_id": "CWE-89",
        "summary": "SQL injection occurs when untrusted user input is concatenated directly into SQL queries, allowing attackers to execute arbitrary SQL commands.",
        "remediation": "Use parameterized queries or prepared statements. Never concatenate user input into SQL strings.",
        "keywords": ["sql", "injection", "query", "execute", "cursor", "database", "select", "insert", "update", "delete", "concatenate"],
    },
    {
        "id": "vuln-002",
        "title": "Path Traversal",
        "vulnerability_type": "Path Traversal",
        "cwe_id": "CWE-22",
        "summary": "Path traversal allows attackers to access files outside the intended directory by using '../' sequences or absolute paths in user input.",
        "remediation": "Validate and sanitize file paths. Use allowlists for permitted directories. Normalize paths before use.",
        "keywords": ["path", "traversal", "file", "directory", "../", "..", "open", "read", "write", "pathlib", "os.path"],
    },
    {
        "id": "vuln-003",
        "title": "Command Injection",
        "vulnerability_type": "Command Injection",
        "cwe_id": "CWE-78",
        "summary": "Command injection occurs when user input is passed to system shell commands without proper sanitization, allowing arbitrary command execution.",
        "remediation": "Avoid shell commands with user input. Use parameterized APIs. Validate and sanitize input strictly.",
        "keywords": ["command", "injection", "os.system", "subprocess", "popen", "exec", "shell", "cmd", "execute"],
    },
    {
        "id": "vuln-004",
        "title": "Cross-Site Scripting (XSS)",
        "vulnerability_type": "XSS",
        "cwe_id": "CWE-79",
        "summary": "XSS vulnerabilities allow attackers to inject malicious scripts into web pages viewed by other users, stealing sessions or defacing sites.",
        "remediation": "Encode output for HTML context. Use Content Security Policy. Validate and sanitize all user input.",
        "keywords": ["xss", "cross", "script", "html", "javascript", "innerhtml", "document.write", "alert", "cookie"],
    },
    {
        "id": "vuln-005",
        "title": "Server-Side Request Forgery (SSRF)",
        "vulnerability_type": "SSRF",
        "cwe_id": "CWE-918",
        "summary": "SSRF allows attackers to make requests from the server to internal resources or external systems, bypassing access controls.",
        "remediation": "Validate and sanitize URLs. Use allowlists for permitted destinations. Disable unnecessary URL schemes.",
        "keywords": ["ssrf", "request", "url", "fetch", "http", "internal", "localhost", "metadata", "aws"],
    },
    {
        "id": "vuln-006",
        "title": "Hardcoded Secret",
        "vulnerability_type": "Hardcoded Secret",
        "cwe_id": "CWE-798",
        "summary": "Hardcoded credentials, API keys, or secrets in source code can be exposed, leading to unauthorized access.",
        "remediation": "Use environment variables or secure vaults. Never hardcode secrets. Rotate exposed credentials immediately.",
        "keywords": ["secret", "password", "api_key", "token", "credential", "hardcoded", "config", "auth", "bearer"],
    },
    {
        "id": "vuln-007",
        "title": "Weak Cryptography",
        "vulnerability_type": "Weak Cryptography",
        "cwe_id": "CWE-327",
        "summary": "Use of weak or broken cryptographic algorithms (MD5, SHA1, DES) can compromise data confidentiality and integrity.",
        "remediation": "Use strong algorithms (AES-256, SHA-256, RSA-2048+). Avoid deprecated algorithms. Keep crypto libraries updated.",
        "keywords": ["crypto", "md5", "sha1", "des", "rc4", "encryption", "hash", "cipher", "weak", "broken"],
    },
    {
        "id": "vuln-008",
        "title": "Insecure Deserialization",
        "vulnerability_type": "Insecure Deserialization",
        "cwe_id": "CWE-502",
        "summary": "Deserialization of untrusted data can lead to remote code execution, authentication bypass, or data tampering.",
        "remediation": "Avoid deserializing untrusted data. Use safe formats like JSON. Implement integrity checks if serialization is required.",
        "keywords": ["deserialize", "pickle", "yaml.load", "marshal", "objectinputstream", "readobject", "serialization"],
    },
]


class RagRetriever:
    """
    Retriever for RAG-based knowledge enhancement.
    
    Implements a lightweight, deterministic knowledge retriever using
    keyword overlap matching against a built-in vulnerability knowledge base.
    
    Features:
    - No external dependencies (no network, no vector DB)
    - Built-in knowledge base with 8 common vulnerability types
    - Keyword-based matching with scoring
    - JSON-serializable output
    """
    
    def __init__(self) -> None:
        """Initialize the retriever with the built-in knowledge base."""
        self._knowledge_base = VULNERABILITY_KNOWLEDGE_BASE
    
    def retrieve(self, query: str, top_k: int = 3) -> list[dict[str, Any]]:
        """
        Retrieve relevant documents for a query.
        
        Args:
            query: The query string to search for
            top_k: Maximum number of results to return (default: 3)
            
        Returns:
            List of matching knowledge items, each containing:
            - id: Unique identifier
            - title: Vulnerability title
            - vulnerability_type: Type of vulnerability
            - cwe_id: CWE identifier
            - summary: Description of the vulnerability
            - remediation: How to fix the vulnerability
            - score: Relevance score (0.0 - 1.0)
            - matched_terms: List of matched keywords
            
        Returns empty list if:
        - query is empty or None
        - top_k <= 0
        - No matches found
        """
        # Handle edge cases
        if not query or not isinstance(query, str):
            return []
        
        if top_k <= 0:
            return []
        
        # Normalize query: lowercase and extract tokens
        query_lower = query.lower()
        query_tokens = set(re.findall(r'\b[a-z_]+\b', query_lower))
        
        # Score each knowledge item
        scored_results = []
        for item in self._knowledge_base:
            score, matched_terms = self._calculate_score(query_lower, query_tokens, item)
            if score > 0:
                result = {
                    "id": item["id"],
                    "title": item["title"],
                    "vulnerability_type": item["vulnerability_type"],
                    "cwe_id": item["cwe_id"],
                    "summary": item["summary"],
                    "remediation": item["remediation"],
                    "score": round(score, 4),
                    "matched_terms": matched_terms,
                }
                scored_results.append((score, result))
        
        # Sort by score descending
        scored_results.sort(key=lambda x: x[0], reverse=True)
        
        # Return top_k results
        return [result for _, result in scored_results[:top_k]]
    
    def _calculate_score(
        self, 
        query_lower: str, 
        query_tokens: set[str], 
        item: dict[str, Any]
    ) -> tuple[float, list[str]]:
        """
        Calculate relevance score between query and knowledge item.
        
        Args:
            query_lower: Lowercase query string
            query_tokens: Set of query tokens
            item: Knowledge base item
            
        Returns:
            Tuple of (score, matched_terms)
        """
        matched_terms = []
        total_weight = 0.0
        
        # Check keywords
        for keyword in item["keywords"]:
            keyword_lower = keyword.lower()
            # Exact match in query
            if keyword_lower in query_lower:
                matched_terms.append(keyword)
                total_weight += 1.0
            # Partial match (token-based)
            elif keyword_lower in query_tokens:
                matched_terms.append(keyword)
                total_weight += 0.5
        
        # Check title match
        title_lower = item["title"].lower()
        if title_lower in query_lower:
            total_weight += 2.0
            matched_terms.append(item["title"])
        
        # Check vulnerability type match
        vuln_type_lower = item["vulnerability_type"].lower()
        if vuln_type_lower in query_lower:
            total_weight += 1.5
            matched_terms.append(item["vulnerability_type"])
        
        # Check CWE ID match
        cwe_id = item["cwe_id"].lower()
        if cwe_id in query_lower:
            total_weight += 1.5
            matched_terms.append(item["cwe_id"])
        
        # Normalize score (max possible is around 10+ depending on keywords)
        score = min(total_weight / 5.0, 1.0)
        
        return score, list(set(matched_terms))  # Remove duplicates
    
    def get_knowledge_by_cwe(self, cwe_id: str) -> dict[str, Any] | None:
        """
        Get knowledge item by CWE ID.
        
        Args:
            cwe_id: CWE identifier (e.g., "CWE-89")
            
        Returns:
            Knowledge item dict or None if not found
        """
        cwe_id_upper = cwe_id.upper()
        for item in self._knowledge_base:
            if item["cwe_id"] == cwe_id_upper:
                return {
                    "id": item["id"],
                    "title": item["title"],
                    "vulnerability_type": item["vulnerability_type"],
                    "cwe_id": item["cwe_id"],
                    "summary": item["summary"],
                    "remediation": item["remediation"],
                }
        return None
    
    def get_all_knowledge(self) -> list[dict[str, Any]]:
        """
        Get all knowledge items (without scores).
        
        Returns:
            List of all knowledge items
        """
        return [
            {
                "id": item["id"],
                "title": item["title"],
                "vulnerability_type": item["vulnerability_type"],
                "cwe_id": item["cwe_id"],
                "summary": item["summary"],
                "remediation": item["remediation"],
            }
            for item in self._knowledge_base
        ]