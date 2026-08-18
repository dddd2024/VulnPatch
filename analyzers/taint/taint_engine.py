"""Lightweight taint-analysis adapter for the default analyzer registry.

``TaintAnalyzer`` delegates deterministic source/sink discovery to a small
``TaintEngine``.  The boundary is intentionally separate from PythonAnalyzer so
it can be replaced by a richer data-flow engine without changing callers.
"""

from __future__ import annotations

import re

from analyzers.base import BaseAnalyzer
from audit_core.models import CodeUnit, RawFinding


class TaintEngine:
    """Minimal source-to-sink detector used by the top-level adapter."""

    SOURCE = re.compile(r"\b([A-Za-z_]\w*)\s*=\s*(?:input\s*\(|request\.|sys\.argv|os\.environ)", re.I)

    def analyze_unit(self, unit: CodeUnit) -> list[RawFinding]:
        if unit.language.lower() != "python":
            return []
        lines = unit.content.splitlines()
        tainted = {m.group(1) for m in self.SOURCE.finditer(unit.content)}
        findings: list[RawFinding] = []
        for idx, line in enumerate(lines, 1):
            sinks: list[tuple[str, str, str, str]] = []
            if re.search(r"\.(?:execute|executemany)\s*\(", line):
                sinks.append(("SQL Injection", "CWE-89", "TAINT_SQL_001", "database execution"))
            if re.search(r"\b(?:os\.system|os\.popen|subprocess\.(?:run|call|Popen))\s*\(", line):
                sinks.append(("Command Injection", "CWE-78", "TAINT_CMD_001", "command execution"))
            if re.search(r"\bopen\s*\(", line):
                sinks.append(("Path Traversal", "CWE-22", "TAINT_PATH_001", "filesystem access"))
            if not sinks:
                continue
            line_tainted = any(re.search(rf"\b{re.escape(var)}\b", line) for var in tainted)
            # Also recognize dynamic construction where the input source is on a
            # prior assignment in the same function and the sink consumes a
            # derived variable.
            context = "\n".join(lines[max(0, idx - 8):idx])
            derived = bool(tainted) and any(re.search(rf"\b{re.escape(var)}\b", context) for var in tainted)
            if not (line_tainted or derived):
                continue
            for vuln_type, cwe, rule_id, sink in sinks:
                findings.append(RawFinding(
                    rule_id=rule_id,
                    type=vuln_type,
                    cwe=cwe,
                    severity="WARN",
                    confidence="medium",
                    file_path=unit.path,
                    start_line=unit.start_line + idx - 1,
                    message=f"Tainted input may reach {sink}.",
                    engine="taint",
                    evidence={"matched_line": line.strip(), "tainted_variables": sorted(tainted)},
                ))
        return findings


class TaintAnalyzer(BaseAnalyzer):
    """BaseAnalyzer adapter that delegates to :class:`TaintEngine`."""

    name = "taint"
    supported_languages = ["python"]

    def __init__(self, engine: TaintEngine | None = None) -> None:
        self.engine = engine or TaintEngine()

    def analyze(self, code_units: list[CodeUnit]) -> list[RawFinding]:
        findings: list[RawFinding] = []
        for unit in code_units:
            if unit.language.lower() != "python":
                continue
            findings.extend(self.engine.analyze_unit(unit))
        return findings

    def cleanup(self) -> None:
        """Compatibility hook for engines that later allocate resources."""
        return None
