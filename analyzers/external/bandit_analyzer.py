"""
Bandit analyzer integration.

Bandit is a Python security linter that detects common security issues
in Python code using AST analysis and pattern matching.

Installation: pip install bandit
Documentation: https://bandit.readthedocs.io/

This analyzer:
1. Writes Python code units to a temporary directory
2. Runs `bandit -r <dir> -f json`
3. Parses JSON output into RawFinding objects
"""

import json
import logging
import os
import subprocess
import sys
import tempfile
from pathlib import Path

from analyzers.base import BaseAnalyzer
from audit_core.models import CodeUnit, RawFinding

logger = logging.getLogger(__name__)

# Bandit severity/confidence mapping
SEVERITY_MAP = {
    "HIGH": "ERROR",
    "MEDIUM": "WARN",
    "LOW": "INFO",
}

CONFIDENCE_MAP = {
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
}


class BanditAnalyzer(BaseAnalyzer):
    """
    Analyzer that wraps Bandit CLI for Python security analysis.

    Bandit specializes in Python-specific security issues:
    - Hardcoded passwords and secrets
    - SQL injection patterns
    - Shell injection
    - Insecure TLS/SSL usage
    - Dangerous imports (pickle, subprocess, etc.)
    - Weak cryptography

    Configuration (via environment variables):
    - BANDIT_TIMEOUT: Timeout in seconds (default: 60)
    - BANDIT_EXTRA_ARGS: Additional CLI arguments
    """

    name = "bandit"
    supported_languages = ["python"]

    def __init__(self) -> None:
        self._available: bool | None = None
        self._timeout = int(os.getenv("BANDIT_TIMEOUT", "60"))
        extra = os.getenv("BANDIT_EXTRA_ARGS", "")
        self._extra_args = extra.split() if extra.strip() else []

    def _find_bandit_cmd(self) -> str | None:
        """Find bandit executable: try PATH first, then common locations."""
        try:
            result = subprocess.run(
                ["bandit", "--version"],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                return "bandit"
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        candidates = [
            Path(sys.executable).parent / "bandit.exe",
            Path(sys.executable).parent.parent / "Scripts" / "bandit.exe",
        ]
        venv_scripts = Path(os.environ.get("VIRTUAL_ENV", "")) / "Scripts" / "bandit.exe"
        if venv_scripts.parent.exists():
            candidates.append(venv_scripts)
        for candidate in candidates:
            if candidate.exists():
                return str(candidate)
        return None

    def is_available(self) -> bool:
        """Check if bandit is installed."""
        if self._available is None:
            cmd = self._find_bandit_cmd()
            self._available = cmd is not None
            if self._available:
                logger.info("Bandit detected via: %s", cmd)
        return self._available

    def analyze(self, code_units: list[CodeUnit]) -> list[RawFinding]:
        """Run Bandit on Python code units."""
        if not code_units:
            return []

        if not self.is_available():
            logger.info("Bandit not available, skipping external analysis")
            return []

        python_units = [u for u in code_units if u.language == "python"]
        if not python_units:
            return []

        findings: list[RawFinding] = []

        with tempfile.TemporaryDirectory(prefix="vulnpatch_bandit_") as tmpdir:
            self._write_code_units(python_units, tmpdir)

            try:
                bandit_cmd = self._find_bandit_cmd() or "bandit"
                cmd = [
                    bandit_cmd,
                    "-r", str(tmpdir),
                    "-f", "json",
                    "-q",  # Quiet mode, no banner
                ] + self._extra_args

                logger.info("Running Bandit on %d Python files", len(python_units))

                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=self._timeout,
                )

                if result.stdout.strip():
                    findings = self._parse_results(result.stdout)
                else:
                    logger.info("Bandit found no issues")

            except subprocess.TimeoutExpired:
                logger.warning("Bandit timed out after %ds", self._timeout)
            except Exception as exc:
                logger.warning("Bandit execution failed: %s", exc)

        logger.info("Bandit found %d issues", len(findings))
        return findings

    def _write_code_units(self, code_units: list[CodeUnit], tmpdir: str) -> None:
        """Write Python code units to temp directory."""
        tmpdir_path = Path(tmpdir)
        for unit in code_units:
            file_path = Path(unit.path)
            dest = tmpdir_path / (file_path.name if file_path.is_absolute() else file_path)
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(unit.content, encoding="utf-8", errors="replace")

    def _parse_results(self, stdout: str) -> list[RawFinding]:
        """Parse Bandit JSON output into RawFinding objects."""
        findings: list[RawFinding] = []

        try:
            data = json.loads(stdout)
        except json.JSONDecodeError:
            logger.warning("Failed to parse Bandit JSON output")
            return findings

        results = data.get("results", [])
        for item in results[:500]:
            try:
                finding = self._convert_result(item)
                if finding:
                    findings.append(finding)
            except Exception as exc:
                logger.debug("Failed to convert Bandit result: %s", exc)

        return findings

    def _convert_result(self, item: dict) -> RawFinding | None:
        """Convert a single Bandit result to RawFinding."""
        issue_text = item.get("issue_text", "")
        issue_severity = item.get("issue_severity", "MEDIUM")
        issue_confidence = item.get("issue_confidence", "MEDIUM")
        test_name = item.get("test_name", "")
        test_id = item.get("test_id", "")
        cwe = item.get("cwe", {})
        cwe_id = cwe.get("id") if isinstance(cwe, dict) else None

        # Location
        filename = item.get("filename", "")
        line_number = item.get("line_number", 0)
        line_range = item.get("line_range", [])

        # Code snippet
        code_snippet = item.get("code", "")

        # More info
        more_info = item.get("more_info", "")

        return RawFinding(
            rule_id=test_id or test_name,
            type=test_name.replace("_", " ").replace("-", " ").title(),
            cwe=cwe_id,
            severity=SEVERITY_MAP.get(issue_severity, "WARN"),
            confidence=CONFIDENCE_MAP.get(issue_confidence, "medium"),
            file_path=filename,
            start_line=line_number,
            end_line=line_range[-1] if line_range else line_number,
            message=issue_text,
            engine=self.name,
            evidence={
                "code_snippet": code_snippet,
                "more_info": more_info,
            },
            metadata={
                "source": "bandit",
                "test_name": test_name,
                "test_id": test_id,
                "bandit_severity": issue_severity,
                "bandit_confidence": issue_confidence,
            },
        )
