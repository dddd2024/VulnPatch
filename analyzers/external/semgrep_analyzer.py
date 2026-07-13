"""
Semgrep analyzer integration.

Semgrep is a fast, open-source static analysis tool that uses pattern matching
and dataflow analysis to find bugs and security vulnerabilities.
Supports Python, JavaScript, TypeScript, Java, C, Go, Ruby, and more.

Installation: pip install semgrep  (or: brew install semgrep)
Documentation: https://semgrep.dev/docs/

This analyzer:
1. Writes code units to a temporary directory (preserving file paths)
2. Runs `semgrep --json --config auto <dir>`
3. Parses JSON output into RawFinding objects
4. Cleans up temporary files

Semgrep rules used:
- "auto" (default p/r rules from semgrep.dev)
- Can be extended with custom rules via SEMGREP_RULES env var
"""

import json
import logging
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from analyzers.base import BaseAnalyzer
from audit_core.models import CodeUnit, RawFinding

logger = logging.getLogger(__name__)

# Severity mapping: semgrep -> VulnPatch
SEVERITY_MAP = {
    "ERROR": "ERROR",
    "WARNING": "WARN",
    "INFO": "INFO",
}

# Confidence mapping based on semgrep metadata
CONFIDENCE_MAP = {
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
}


class SemgrepAnalyzer(BaseAnalyzer):
    """
    Analyzer that wraps Semgrep CLI for multi-language static analysis.

    Supports all languages that Semgrep supports (Python, JavaScript, TypeScript,
    Java, C, C++, Go, Ruby, PHP, etc.). Falls back gracefully if Semgrep
    is not installed.

    Configuration (via environment variables):
    - SEMGREP_RULES: Custom rules path or URL (default: "auto")
    - SEMGREP_TIMEOUT: Timeout in seconds (default: 120)
    - SEMGREP_EXTRA_ARGS: Additional CLI arguments (space-separated)
    """

    name = "semgrep"
    supported_languages = [
        "python", "javascript", "typescript", "java",
        "c", "cpp", "go", "ruby", "php", "kotlin",
        "scala", "rust", "swift",
    ]

    def __init__(self) -> None:
        self._available: bool | None = None
        self._rules = os.getenv("SEMGREP_RULES", "auto")
        self._timeout = int(os.getenv("SEMGREP_TIMEOUT", "120"))
        extra = os.getenv("SEMGREP_EXTRA_ARGS", "")
        self._extra_args = extra.split() if extra.strip() else []

    def _find_semgrep_cmd(self) -> str | None:
        """Find semgrep executable: try PATH first, then common locations."""
        # Try PATH
        try:
            result = subprocess.run(
                ["semgrep", "--version"],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                return "semgrep"
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        # Try common install locations
        candidates = [
            Path(sys.executable).parent / "semgrep.exe",  # Same dir as python
            Path(sys.executable).parent.parent / "Scripts" / "semgrep.exe",
        ]
        # Also check the venv if we're in one
        venv_scripts = Path(os.environ.get("VIRTUAL_ENV", "")) / "Scripts" / "semgrep.exe"
        if venv_scripts.parent.exists():
            candidates.append(venv_scripts)
        for candidate in candidates:
            if candidate.exists():
                return str(candidate)
        return None

    def is_available(self) -> bool:
        """Check if semgrep is installed and available."""
        if self._available is None:
            cmd = self._find_semgrep_cmd()
            self._available = cmd is not None
            if self._available:
                logger.info("Semgrep detected via: %s", cmd)
        return self._available

    def analyze(self, code_units: list[CodeUnit]) -> list[RawFinding]:
        """
        Run Semgrep on code units and return findings.

        Args:
            code_units: List of code units to analyze

        Returns:
            List of RawFinding objects from Semgrep results
        """
        if not code_units:
            return []

        if not self.is_available():
            logger.info("Semgrep not available, skipping external analysis")
            return []

        # Filter to supported languages
        supported_units = [u for u in code_units if self.supports_language(u.language)]
        if not supported_units:
            return []

        findings: list[RawFinding] = []

        # Write code units to temp directory
        with tempfile.TemporaryDirectory(prefix="vulnpatch_semgrep_") as tmpdir:
            self._write_code_units(supported_units, tmpdir)

            # Run semgrep
            try:
                semgrep_cmd = self._find_semgrep_cmd() or "semgrep"
                cmd = [
                    semgrep_cmd,
                    "--json",
                    "--config", self._rules,
                    "--no-git-ignore",
                    str(tmpdir),
                ] + self._extra_args

                logger.info("Running Semgrep on %d files: %s", len(supported_units), " ".join(cmd))

                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=self._timeout,
                    cwd=tmpdir,
                )

                if result.returncode == 0 or result.returncode == 1:
                    # semgrep returns 1 when it finds issues
                    findings = self._parse_results(result.stdout, tmpdir)
                else:
                    logger.warning("Semgrep failed (exit %d): %s", result.returncode, result.stderr[:500])

            except subprocess.TimeoutExpired:
                logger.warning("Semgrep timed out after %ds", self._timeout)
            except Exception as exc:
                logger.warning("Semgrep execution failed: %s", exc)

        logger.info("Semgrep found %d issues across %d files", len(findings), len(supported_units))
        return findings

    def _write_code_units(self, code_units: list[CodeUnit], tmpdir: str) -> None:
        """Write code units to temp directory preserving relative paths."""
        tmpdir_path = Path(tmpdir)
        for unit in code_units:
            # Preserve file path structure
            file_path = Path(unit.path)
            # Use just the filename if path is absolute, otherwise preserve relative
            if file_path.is_absolute():
                dest = tmpdir_path / file_path.name
            else:
                dest = tmpdir_path / file_path

            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(unit.content, encoding="utf-8", errors="replace")

    def _parse_results(self, stdout: str, tmpdir: str) -> list[RawFinding]:
        """Parse Semgrep JSON output into RawFinding objects."""
        findings: list[RawFinding] = []
        tmpdir_path = Path(tmpdir)

        try:
            data = json.loads(stdout)
        except json.JSONDecodeError:
            logger.warning("Failed to parse Semgrep JSON output")
            return findings

        results = data.get("results", [])
        for result in results[:500]:  # Cap at 500 findings
            try:
                finding = self._convert_result(result, tmpdir_path)
                if finding:
                    findings.append(finding)
            except Exception as exc:
                logger.debug("Failed to convert Semgrep result: %s", exc)

        return findings

    def _convert_result(self, result: dict, tmpdir: Path) -> RawFinding | None:
        """Convert a single Semgrep result to RawFinding."""
        # Extract file path (relative to tmpdir)
        code_path = result.get("path", "")
        try:
            rel_path = str(Path(code_path).relative_to(tmpdir))
        except ValueError:
            rel_path = code_path

        # Extract check info
        check = result.get("check_id", "")
        # Extract rule metadata
        extra = result.get("extra", {})
        metadata = extra.get("metadata", {})
        severity = extra.get("severity", "WARNING")
        message = extra.get("message", result.get("extra", {}).get("message", "Semgrep finding"))
        cwe = metadata.get("cwe", [])
        cwe_str = cwe[0] if isinstance(cwe, list) and cwe else str(cwe) if cwe else None
        confidence = metadata.get("confidence", "MEDIUM")
        category = metadata.get("category", "security")
        subcategory = metadata.get("subcategory", "")
        technology = metadata.get("technology", [])

        # Build vulnerability type from category/subcategory
        vuln_type = subcategory or category or check.split(".")[-1] if check else "semgrep-finding"

        # Map severity
        mapped_severity = SEVERITY_MAP.get(severity, "WARN")
        mapped_confidence = CONFIDENCE_MAP.get(confidence, "medium")

        # Extract line info
        start_line = result.get("start", {}).get("line", 0)
        end_line = result.get("end", {}).get("line", start_line)
        start_col = result.get("start", {}).get("col", 1)
        end_col = result.get("end", {}).get("col", 1)

        # Code snippet
        code_snippet = result.get("extra", {}).get("lines", "")

        return RawFinding(
            rule_id=check,
            type=vuln_type.replace("-", " ").replace("_", " ").title(),
            cwe=cwe_str,
            severity=mapped_severity,
            confidence=mapped_confidence,
            file_path=rel_path,
            start_line=start_line,
            end_line=end_line,
            message=message,
            engine=self.name,
            evidence={
                "code_snippet": code_snippet,
                "is_primary": result.get("is_primary", False),
                "technology": technology,
                "category": category,
                "subcategory": subcategory,
                "semgrep_rule_id": check,
                "start_col": start_col,
                "end_col": end_col,
            },
            metadata={
                "source": "semgrep",
                "rule_id": check,
                "semgrep_severity": severity,
                "semgrep_confidence": confidence,
            },
        )
