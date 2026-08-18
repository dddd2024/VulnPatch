"""Canonical vulnerability-type to CWE mapping used by agents and reports."""
from __future__ import annotations

from typing import Any

_MAPPINGS: dict[str, dict[str, str]] = {
    "sql_injection": {"id": "CWE-89", "name": "SQL Injection", "description": "Improper neutralization of special elements used in an SQL command."},
    "path_traversal": {"id": "CWE-22", "name": "Path Traversal", "description": "Improper limitation of a pathname to a restricted directory."},
    "command_injection": {"id": "CWE-78", "name": "OS Command Injection", "description": "Improper neutralization of special elements used in an OS command."},
    "xss": {"id": "CWE-79", "name": "Cross-site Scripting (XSS)", "description": "Improper neutralization of input during web page generation."},
    "ssrf": {"id": "CWE-918", "name": "Server-Side Request Forgery (SSRF)", "description": "Server-side request forgery to an unintended resource."},
    "hardcoded_secret": {"id": "CWE-798", "name": "Hard-coded Credentials", "description": "Use of hard-coded credentials or secrets."},
    "weak_crypto": {"id": "CWE-327", "name": "Use of a Broken or Risky Cryptographic Algorithm", "description": "Use of a broken or risky cryptographic algorithm."},
    "deserialization": {"id": "CWE-502", "name": "Deserialization of Untrusted Data", "description": "Deserialization of untrusted data."},
    "insecure_deserialization": {"id": "CWE-502", "name": "Deserialization of Untrusted Data", "description": "Deserialization of untrusted data."},
    "file_upload": {"id": "CWE-434", "name": "Unrestricted Upload of File with Dangerous Type", "description": "Insufficient restriction of uploaded file types."},
    "insecure_random": {"id": "CWE-330", "name": "Use of Insufficiently Random Values", "description": "Security-sensitive use of insufficiently random values."},
}

_ALIASES = {
    "sql injection": "sql_injection",
    "path traversal": "path_traversal",
    "command injection": "command_injection",
    "cross site scripting": "xss",
    "cross-site scripting": "xss",
    "hardcoded secret": "hardcoded_secret",
    "hard-coded secret": "hardcoded_secret",
    "weak cryptography": "weak_crypto",
    "insecure deserialization": "insecure_deserialization",
}


def _normalize(vulnerability_type: Any) -> str:
    if not isinstance(vulnerability_type, str):
        return ""
    value = " ".join(vulnerability_type.strip().lower().replace("_", " ").split())
    if value in _ALIASES:
        return _ALIASES[value]
    return value.replace(" ", "_")


def map_cwe(vulnerability_type: Any) -> dict[str, str]:
    key = _normalize(vulnerability_type)
    if key in _MAPPINGS:
        return dict(_MAPPINGS[key])
    original = vulnerability_type if isinstance(vulnerability_type, str) else ""
    return {"id": "CWE-UNKNOWN", "name": original, "description": "Unknown vulnerability type."}


def get_cwe_id(vulnerability_type: Any) -> str:
    return map_cwe(vulnerability_type)["id"]


def is_known_vulnerability_type(vulnerability_type: Any) -> bool:
    return _normalize(vulnerability_type) in _MAPPINGS


def get_all_cwe_mappings() -> dict[str, dict[str, str]]:
    return {key: dict(value) for key, value in _MAPPINGS.items()}
