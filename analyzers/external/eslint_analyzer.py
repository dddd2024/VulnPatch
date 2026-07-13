"""
ESLint security analyzer integration.

Uses eslint with security-focused plugins (eslint-plugin-security, 
eslint-plugin-no-secrets) to detect JavaScript/TypeScript vulnerabilities.

Installation:
  npm install -g eslint eslint-plugin-security eslint-plugin-no-secrets

This analyzer:
1. Writes JS/TS code units to a temp directory
2. Creates a minimal eslint config with security plugins
3. Runs `eslint --format json <dir>`
4. Parses JSON output into RawFinding objects
"""

import json
import logging
import os
import subprocess
import tempfile
from pathlib import Path

from analyzers.base import BaseAnalyzer
from audit_core.models import CodeUnit, RawFinding

logger = logging.getLogger(__name__)

# ESLint severity mapping
SEVERITY_MAP = {
    0: "INFO",    # off
    1: "WARN",    # warn
    2: "ERROR",   # error
}

# Rule ID to CWE/vuln type mapping for common security rules
RULE_METADATA = {
    "no-eval": {"cwe": "CWE-95", "type": "Code Injection"},
    "no-implied-eval": {"cwe": "CWE-95", "type": "Code Injection"},
    "no-new-func": {"cwe": "CWE-95", "type": "Code Injection"},
    "security/detect-object-injection": {"cwe": "CWE-94", "type": "Code Injection"},
    "security/detect-eval-with-expression": {"cwe": "CWE-95", "type": "Code Injection"},
    "security/detect-non-literal-regexp": {"cwe": "CWE-1333", "type": "ReDoS"},
    "security/detect-unsafe-regex": {"cwe": "CWE-1333", "type": "ReDoS"},
    "security/detect-child-process": {"cwe": "CWE-78", "type": "Command Injection"},
    "security/detect-dangerous-calls": {"cwe": "CWE-78", "type": "Command Injection"},
    "security/detect-pseudoRandomBytes": {"cwe": "CWE-330", "type": "Insecure Random"},
    "security/detect-insecure-randomness": {"cwe": "CWE-330", "type": "Insecure Random"},
    "security/detect-buffer-noassert": {"cwe": "CWE-120", "type": "Buffer Overflow"},
    "security/detect-no-callback-in-sync-method": {"cwe": "CWE-400", "type": "Resource Exhaustion"},
    "security/detect-possible-timing-attacks": {"cwe": "CWE-208", "type": "Timing Attack"},
    "security/detect-unsafe-crypto": {"cwe": "CWE-327", "type": "Weak Cryptography"},
    "security/detect-insecurecompare": {"cwe": "CWE-208", "type": "Timing Attack"},
    "security/detect-unsafe-assignment": {"cwe": "CWE-1321", "type": "Prototype Pollution"},
    "no-secrets/no-secrets": {"cwe": "CWE-798", "type": "Hardcoded Secret"},
    "no-secrets/no-hardcoded-credentials": {"cwe": "CWE-798", "type": "Hardcoded Secret"},
}

# Minimal ESLint config for security scanning
ESLINT_CONFIG = """{
  "plugins": ["security", "no-secrets"],
  "parserOptions": {
    "ecmaVersion": 2022,
    "sourceType": "module"
  },
  "rules": {
    "no-eval": "error",
    "no-implied-eval": "error",
    "no-new-func": "warn",
    "security/detect-object-injection": "error",
    "security/detect-eval-with-expression": "error",
    "security/detect-non-literal-regexp": "warn",
    "security/detect-unsafe-regex": "warn",
    "security/detect-child-process": "error",
    "security/detect-dangerous-calls": "error",
    "security/detect-pseudoRandomBytes": "warn",
    "security/detect-insecure-randomness": "warn",
    "security/detect-buffer-noassert": "warn",
    "security/detect-no-callback-in-sync-method": "warn",
    "security/detect-possible-timing-attacks": "warn",
    "security/detect-unsafe-crypto": "error",
    "security/detect-insecurecompare": "warn",
    "no-secrets/no-secrets": "error"
  }
}
"""


class ESLintSecurityAnalyzer(BaseAnalyzer):
    """
    Analyzer that wraps ESLint with security plugins for JS/TS analysis.

    Requires:
    - eslint (globally installed)
    - eslint-plugin-security
    - eslint-plugin-no-secrets (optional)

    Falls back gracefully if any dependency is missing.

    Configuration (via environment variables):
    - ESLINT_TIMEOUT: Timeout in seconds (default: 60)
    - ESLINT_EXTRA_ARGS: Additional CLI arguments
    """

    name = "eslint-security"
    supported_languages = ["javascript", "typescript"]

    def __init__(self) -> None:
        self._available: bool | None = None
        self._timeout = int(os.getenv("ESLINT_TIMEOUT", "60"))
        extra = os.getenv("ESLINT_EXTRA_ARGS", "")
        self._extra_args = extra.split() if extra.strip() else []

    def is_available(self) -> bool:
        """Check if eslint is installed."""
        if self._available is None:
            try:
                result = subprocess.run(
                    ["eslint", "--version"],
                    capture_output=True, text=True, timeout=10
                )
                self._available = result.returncode == 0
                if self._available:
                    logger.info("ESLint detected: %s", result.stdout.strip())
            except (FileNotFoundError, subprocess.TimeoutExpired):
                self._available = False
        return self._available

    def analyze(self, code_units: list[CodeUnit]) -> list[RawFinding]:
        """Run ESLint with security plugins on JS/TS code units."""
        if not code_units:
            return []

        if not self.is_available():
            logger.info("ESLint not available, skipping external analysis")
            return []

        js_units = [u for u in code_units if u.language in ("javascript", "typescript")]
        if not js_units:
            return []

        findings: list[RawFinding] = []

        with tempfile.TemporaryDirectory(prefix="vulnpatch_eslint_") as tmpdir:
            self._write_code_units(js_units, tmpdir)
            self._write_eslint_config(tmpdir)

            try:
                cmd = [
                    "eslint",
                    "--format", "json",
                    "--no-eslintrc",
                    "--config", os.path.join(tmpdir, ".eslintrc.json"),
                    "--resolve-plugins-relative-to", tmpdir,
                    str(tmpdir),
                ] + self._extra_args

                logger.info("Running ESLint security on %d JS/TS files", len(js_units))

                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=self._timeout,
                    cwd=tmpdir,
                )

                if result.stdout.strip():
                    findings = self._parse_results(result.stdout)
                else:
                    logger.info("ESLint found no issues")

            except subprocess.TimeoutExpired:
                logger.warning("ESLint timed out after %ds", self._timeout)
            except Exception as exc:
                logger.warning("ESLint execution failed: %s", exc)

        logger.info("ESLint security found %d issues", len(findings))
        return findings

    def _write_code_units(self, code_units: list[CodeUnit], tmpdir: str) -> None:
        """Write JS/TS code units to temp directory."""
        tmpdir_path = Path(tmpdir)
        for unit in code_units:
            file_path = Path(unit.path)
            # Ensure .js/.ts extension for eslint
            ext = ".ts" if unit.language == "typescript" else ".js"
            if file_path.suffix not in (".js", ".jsx", ".ts", ".tsx", ".mjs"):
                dest = tmpdir_path / (file_path.stem + ext)
            else:
                dest = tmpdir_path / (file_path.name if file_path.is_absolute() else file_path)
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(unit.content, encoding="utf-8", errors="replace")

    def _write_eslint_config(self, tmpdir: str) -> None:
        """Write minimal eslint config to temp directory."""
        config_path = Path(tmpdir) / ".eslintrc.json"
        config_path.write_text(ESLINT_CONFIG, encoding="utf-8")

    def _parse_results(self, stdout: str) -> list[RawFinding]:
        """Parse ESLint JSON output into RawFinding objects."""
        findings: list[RawFinding] = []

        try:
            data = json.loads(stdout)
        except json.JSONDecodeError:
            logger.warning("Failed to parse ESLint JSON output")
            return findings

        if not isinstance(data, list):
            return findings

        for file_result in data[:500]:
            file_path = file_result.get("filePath", "")
            messages = file_result.get("messages", [])

            for msg in messages[:100]:
                try:
                    finding = self._convert_result(msg, file_path)
                    if finding:
                        findings.append(finding)
                except Exception as exc:
                    logger.debug("Failed to convert ESLint result: %s", exc)

        return findings

    def _convert_result(self, msg: dict, file_path: str) -> RawFinding | None:
        """Convert a single ESLint message to RawFinding."""
        rule_id = msg.get("ruleId", "")
        severity = msg.get("severity", 1)
        line = msg.get("line", 0)
        end_line = msg.get("endLine", line)
        column = msg.get("column", 1)
        message = msg.get("message", "")

        # Look up rule metadata
        meta = RULE_METADATA.get(rule_id, {})
        cwe = meta.get("cwe")
        vuln_type = meta.get("type", rule_id.replace("-", " ").title())

        # Map severity
        mapped_severity = SEVERITY_MAP.get(severity, "WARN")

        # Confidence: ESLint doesn't have confidence, infer from severity
        confidence = "high" if severity == 2 else "medium"

        return RawFinding(
            rule_id=rule_id,
            type=vuln_type,
            cwe=cwe,
            severity=mapped_severity,
            confidence=confidence,
            file_path=file_path,
            start_line=line,
            end_line=end_line,
            message=message,
            engine=self.name,
            evidence={
                "column": column,
            },
            metadata={
                "source": "eslint-security",
                "rule_id": rule_id,
                "eslint_severity": severity,
            },
        )
