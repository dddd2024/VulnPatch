"""Python AST security analyzer.

This deterministic analyzer complements pattern/taint rules with structural
checks that are difficult to express reliably as text patterns.  It performs
no network or LLM calls.
"""
from __future__ import annotations

import ast
from typing import Iterable

from audit_core.models import CodeUnit, RawFinding
from analyzers.base import BaseAnalyzer


class ASTAnalyzer(BaseAnalyzer):
    """Detect dangerous Python call structures using the built-in AST."""

    name = "ast"
    supported_languages = ["python"]

    def analyze(self, code_units: list[CodeUnit]) -> list[RawFinding]:
        findings: list[RawFinding] = []
        for unit in code_units:
            if (unit.language or "").lower() != "python":
                continue
            findings.extend(self._analyze_python_ast(unit))
        return findings

    @staticmethod
    def _call_name(node: ast.Call) -> str:
        func = node.func
        if isinstance(func, ast.Name):
            return func.id
        if isinstance(func, ast.Attribute):
            parts: list[str] = [func.attr]
            value = func.value
            while isinstance(value, ast.Attribute):
                parts.append(value.attr)
                value = value.value
            if isinstance(value, ast.Name):
                parts.append(value.id)
            return ".".join(reversed(parts))
        return ""

    @staticmethod
    def _is_literal(node: ast.AST | None) -> bool:
        return isinstance(node, ast.Constant) and isinstance(node.value, (str, bytes))

    def _finding(
        self,
        unit: CodeUnit,
        node: ast.AST,
        *,
        rule_id: str,
        vuln_type: str,
        cwe: str,
        message: str,
        confidence: str = "high",
    ) -> RawFinding:
        line = unit.start_line + max(1, getattr(node, "lineno", 1)) - 1
        end_line = unit.start_line + max(
            getattr(node, "lineno", 1), getattr(node, "end_lineno", getattr(node, "lineno", 1))
        ) - 1
        return RawFinding(
            rule_id=rule_id,
            type=vuln_type,
            cwe=cwe,
            severity="ERROR",
            confidence=confidence,
            file_path=unit.path,
            start_line=line,
            end_line=end_line,
            message=message,
            engine=self.name,
            evidence={"ast_node": type(node).__name__},
        )

    def _analyze_python_ast(self, unit: CodeUnit) -> list[RawFinding]:
        try:
            tree = ast.parse(unit.content, filename=unit.path)
        except (SyntaxError, ValueError):
            return []

        findings: list[RawFinding] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = self._call_name(node)

            if name in {"eval", "exec"}:
                findings.append(self._finding(
                    unit,
                    node,
                    rule_id="PY_AST_CODE_EXEC",
                    vuln_type="Code Injection",
                    cwe="CWE-95",
                    message=f"Dynamic code execution via {name}() requires trusted input.",
                ))
                continue

            if name in {"os.system", "os.popen"}:
                arg = node.args[0] if node.args else None
                if not self._is_literal(arg):
                    findings.append(self._finding(
                        unit,
                        node,
                        rule_id="PY_AST_COMMAND",
                        vuln_type="Command Injection",
                        cwe="CWE-78",
                        message=f"Non-literal command reaches {name}().",
                    ))
                continue

            if name in {"subprocess.run", "subprocess.call", "subprocess.Popen"}:
                shell_true = any(
                    kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True
                    for kw in node.keywords
                )
                arg = node.args[0] if node.args else None
                if shell_true and not self._is_literal(arg):
                    findings.append(self._finding(
                        unit,
                        node,
                        rule_id="PY_AST_SUBPROCESS_SHELL",
                        vuln_type="Command Injection",
                        cwe="CWE-78",
                        message="Dynamic subprocess command is executed with shell=True.",
                    ))
                continue

            if name in {"pickle.loads", "pickle.load"}:
                findings.append(self._finding(
                    unit,
                    node,
                    rule_id="PY_AST_DESERIALIZE",
                    vuln_type="Unsafe Deserialization",
                    cwe="CWE-502",
                    message=f"Python pickle deserialization via {name}() must only consume trusted data.",
                    confidence="medium",
                ))

        return findings
