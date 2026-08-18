"""Build conservative, source-grounded call-chain evidence for a finding.

The builder intentionally limits itself to relationships visible in the supplied
``CodeUnit``.  Python receives AST-based caller tracing; other languages receive
a conservative enclosing-function location rather than fabricated cross-file
edges.  Cross-file call graphs can be added later without changing the public
EvidenceBundle contract.
"""
from __future__ import annotations

import ast
import re
from collections import deque
from typing import Any

from audit_core.models import CodeUnit, RawFinding


_GENERIC_FUNCTION_RE = re.compile(
    r"^\s*(?:(?:public|private|protected|static|final|async|export|default|"
    r"synchronized|native|abstract|override|virtual|inline|extern)\s+)*"
    r"(?:[A-Za-z_$][\w$<>\[\],.?]*\s+)+"
    r"(?P<name>[A-Za-z_$][\w$]*)\s*\([^;{}]*\)\s*(?:throws\s+[^\{]+)?\{?\s*$"
)


def _local_finding_line(finding: RawFinding, code_unit: CodeUnit) -> int:
    return max(1, int(finding.start_line) - int(code_unit.start_line or 1) + 1)


def _step(name: str, code_unit: CodeUnit, line: int, *, kind: str, vulnerable: bool = False) -> dict[str, Any]:
    return {
        "name": name,
        "file": code_unit.path,
        "line": int(code_unit.start_line or 1) + max(1, int(line)) - 1,
        "kind": kind,
        "vulnerable": vulnerable,
    }


def _python_call_chain(finding: RawFinding, code_unit: CodeUnit) -> list[dict[str, Any]]:
    try:
        tree = ast.parse(code_unit.content, filename=code_unit.path)
    except (SyntaxError, ValueError, TypeError):
        return []

    functions: dict[str, tuple[int, int]] = {}
    calls: list[tuple[str, str, int]] = []
    stack: list[str] = []

    class Visitor(ast.NodeVisitor):
        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            name = node.name
            functions[name] = (node.lineno, getattr(node, "end_lineno", node.lineno))
            stack.append(name)
            self.generic_visit(node)
            stack.pop()

        visit_AsyncFunctionDef = visit_FunctionDef

        def visit_Call(self, node: ast.Call) -> None:
            caller = stack[-1] if stack else "<module>"
            func = node.func
            if isinstance(func, ast.Name):
                callee = func.id
            elif isinstance(func, ast.Attribute):
                callee = func.attr
            else:
                callee = ""
            if callee:
                calls.append((caller, callee, node.lineno))
            self.generic_visit(node)

    Visitor().visit(tree)
    local_line = _local_finding_line(finding, code_unit)
    containing = [
        (name, start, end)
        for name, (start, end) in functions.items()
        if start <= local_line <= end
    ]
    if not containing:
        return [_step("<module>", code_unit, local_line, kind="module", vulnerable=True)]

    target, target_start, _ = min(containing, key=lambda item: item[2] - item[1])
    reverse: dict[str, list[tuple[str, int]]] = {}
    for caller, callee, line in calls:
        reverse.setdefault(callee, []).append((caller, line))
    for values in reverse.values():
        values.sort(key=lambda item: (item[0], item[1]))

    # Prefer a module-rooted path. If none exists, retain the deepest observed
    # caller chain instead of dropping useful caller evidence.
    queue: deque[tuple[str, list[str]]] = deque([(target, [target])])
    visited = {target}
    chosen: list[str] | None = None
    best: list[str] = [target]
    while queue:
        current, upward_path = queue.popleft()
        if len(upward_path) > 8:
            continue
        for caller, _line in reverse.get(current, []):
            candidate = upward_path + [caller]
            forward_candidate = list(reversed(candidate))
            if len(forward_candidate) > len(best):
                best = forward_candidate
            if caller == "<module>":
                chosen = forward_candidate
                queue.clear()
                break
            if caller not in visited:
                visited.add(caller)
                queue.append((caller, candidate))
        if chosen is not None:
            break

    names = chosen or best
    chain: list[dict[str, Any]] = []
    for name in names:
        if name == "<module>":
            line = 1
            kind = "module"
        else:
            line = functions.get(name, (target_start, target_start))[0]
            kind = "function"
        chain.append(_step(name, code_unit, line, kind=kind, vulnerable=name == target))
    return chain


def _generic_enclosing_function(finding: RawFinding, code_unit: CodeUnit) -> list[dict[str, Any]]:
    """Return a conservative enclosing function/method for non-Python source.

    This deliberately does not invent caller edges without a language parser.  It
    still gives EvidenceBundle a useful source location instead of an empty
    placeholder.
    """
    lines = code_unit.content.splitlines()
    local_line = min(_local_finding_line(finding, code_unit), max(1, len(lines)))
    for index in range(local_line - 1, -1, -1):
        match = _GENERIC_FUNCTION_RE.match(lines[index])
        if match:
            return [_step(match.group("name"), code_unit, index + 1, kind="function", vulnerable=True)]
    return [_step("<module>", code_unit, local_line, kind="module", vulnerable=True)]


def build_call_chain(
    finding: RawFinding,
    code_unit: CodeUnit | None,
) -> list[dict[str, Any]]:
    """Build call-chain evidence using only source available in ``code_unit``.

    The result is deterministic and never claims cross-file relationships that
    were not observed.  An absent code unit yields no chain because there is no
    source evidence to support one.
    """
    if code_unit is None or not code_unit.content:
        return []
    language = (code_unit.language or "").lower()
    if language in {"python", "py"}:
        return _python_call_chain(finding, code_unit)
    return _generic_enclosing_function(finding, code_unit)
