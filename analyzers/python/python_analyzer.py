"""Deterministic Python vulnerability analyzer.

The analyzer intentionally keeps a small, auditable ruleset for the project
baseline.  It does not invoke an LLM and emits the common ``RawFinding`` model.
"""

from __future__ import annotations

import re
import shutil
import tempfile
from pathlib import Path

from analyzers.base import BaseAnalyzer
from audit_core.models import CodeUnit, RawFinding


class PythonAnalyzer(BaseAnalyzer):
    name = "python"
    supported_languages = ["python"]

    _TAINT_SOURCE = re.compile(
        r"\b([A-Za-z_]\w*)\s*=\s*(?:request\.(?:args|form|values|json)(?:\.get)?|input\s*\(|sys\.argv|os\.environ)",
        re.IGNORECASE,
    )
    _SECRET = re.compile(
        r"\b(password|passwd|pwd|secret|api[_-]?key|access[_-]?key|secret[_-]?key|token)\b\s*=\s*([\"'])([^\"']{4,})\2",
        re.IGNORECASE,
    )

    def __init__(self) -> None:
        self._tmp_dir: str | None = None

    def analyze(self, code_units: list[CodeUnit]) -> list[RawFinding]:
        if not code_units:
            return []
        if self._tmp_dir is None:
            self._tmp_dir = tempfile.mkdtemp(prefix="vulnpatch_python_analyzer_")

        findings: list[RawFinding] = []
        for unit in code_units:
            if unit.language.lower() != "python":
                continue
            findings.extend(self._analyze_unit(unit))
        return findings

    def cleanup(self) -> None:
        if self._tmp_dir:
            shutil.rmtree(self._tmp_dir, ignore_errors=True)
            self._tmp_dir = None

    def _finding(
        self,
        unit: CodeUnit,
        *,
        rule_id: str,
        vuln_type: str,
        cwe: str,
        severity: str,
        confidence: str,
        line: int,
        message: str,
        matched_line: str,
        symbol: str | None = None,
    ) -> RawFinding:
        evidence = {"matched_line": matched_line.strip()}
        if symbol:
            evidence["symbol"] = symbol
        return RawFinding(
            rule_id=rule_id,
            type=vuln_type,
            cwe=cwe,
            severity=severity,
            confidence=confidence,
            file_path=unit.path,
            start_line=unit.start_line + line - 1,
            message=message,
            engine=self.name,
            evidence=evidence,
        )

    def _analyze_unit(self, unit: CodeUnit) -> list[RawFinding]:
        source = unit.content
        lines = source.splitlines()
        tainted = {m.group(1) for m in self._TAINT_SOURCE.finditer(source)}
        findings: list[RawFinding] = []
        seen: set[tuple[str, int]] = set()

        def add(kind: str, line_no: int, finding: RawFinding) -> None:
            key = (kind, line_no)
            if key not in seen:
                seen.add(key)
                findings.append(finding)

        for idx, line in enumerate(lines, 1):
            stripped = line.strip()

            # SQL injection: f-string / interpolation / concatenation passed to
            # DB execution methods.  Also catches a tainted SQL variable used in
            # execute() when the assignment on a nearby line is concatenated.
            if re.search(r"\.(?:execute|executemany)\s*\(", line):
                risky = bool(re.search(r"\.(?:execute|executemany)\s*\(\s*f[\"']", line))
                risky |= "+" in line or ".format(" in line or "%" in line
                if not risky:
                    arg = re.search(r"\.(?:execute|executemany)\s*\(\s*([A-Za-z_]\w*)", line)
                    if arg:
                        var = re.escape(arg.group(1))
                        context = "\n".join(lines[max(0, idx - 6):idx])
                        risky = bool(re.search(rf"\b{var}\s*=.*(?:\+|f[\"']|\.format\()", context))
                if risky:
                    add("sql", idx, self._finding(
                        unit, rule_id="PY_SQL_001", vuln_type="SQL Injection", cwe="CWE-89",
                        severity="ERROR", confidence="high", line=idx,
                        message="Potential SQL injection: dynamic SQL reaches a database execution sink.",
                        matched_line=stripped, symbol="execute",
                    ))

            # Path traversal: direct request/input in file APIs, or a variable
            # previously assigned from a common user-input source.
            if re.search(r"\b(?:open|Path)\s*\(", line):
                risky = bool(re.search(r"request\.|input\s*\(|sys\.argv", line, re.IGNORECASE))
                sink_arg = re.search(r"\b(?:open|Path)\s*\(\s*([A-Za-z_]\w*)", line)
                if sink_arg and sink_arg.group(1) in tainted:
                    risky = True
                if risky:
                    add("path", idx, self._finding(
                        unit, rule_id="PY_PATH_001", vuln_type="Path Traversal", cwe="CWE-22",
                        severity="ERROR", confidence="high", line=idx,
                        message="Potential path traversal: user-controlled path reaches a filesystem sink.",
                        matched_line=stripped, symbol="open",
                    ))

            # Command injection / dynamic code execution.
            command_match = re.search(
                r"\b(os\.system|os\.popen|subprocess\.(?:run|call|Popen)|eval|exec)\s*\(", line
            )
            if command_match:
                risky = "+" in line or "shell=True" in line or any(re.search(rf"\b{re.escape(v)}\b", line) for v in tainted)
                # ``os.system(variable)`` is inherently worth flagging even if
                # the source line is outside the local context.
                risky |= command_match.group(1) in {"os.system", "os.popen", "eval", "exec"}
                if risky:
                    add("command", idx, self._finding(
                        unit, rule_id="PY_CMD_001", vuln_type="Command Injection", cwe="CWE-78",
                        severity="ERROR", confidence="high", line=idx,
                        message="Potential command injection: dynamic data reaches a command/code execution sink.",
                        matched_line=stripped, symbol=command_match.group(1),
                    ))

            secret = self._SECRET.search(line)
            if secret:
                add("secret", idx, self._finding(
                    unit, rule_id="PY_SECRET_001", vuln_type="Hardcoded Secret", cwe="CWE-798",
                    severity="WARN", confidence="high", line=idx,
                    message=f"Hardcoded credential-like value assigned to {secret.group(1)}.",
                    matched_line=stripped, symbol=secret.group(1),
                ))

        return findings
