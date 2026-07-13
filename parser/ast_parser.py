import ast
import re
from pathlib import Path
from typing import Any


class PythonCodeVisitor(ast.NodeVisitor):
    def __init__(self, filename: str) -> None:
        self.filename = filename
        self.imports: list[str] = []
        self.functions: list[dict[str, Any]] = []
        self.calls: list[dict[str, Any]] = []
        self.routes: list[dict[str, Any]] = []
        self._function_stack: list[str] = []

    def visit_Import(self, node: ast.Import) -> None:
        for n in node.names:
            self.imports.append(n.name)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module:
            self.imports.append(node.module)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self.functions.append({"name": node.name, "line": node.lineno})
        decorators = [self._decorator_name(d) for d in node.decorator_list]
        route_path = self._route_path(node.decorator_list)
        if route_path:
            self.routes.append(
                {
                    "path": route_path,
                    "function": node.name,
                    "decorators": decorators,
                    "line": node.lineno,
                }
            )
        self._function_stack.append(node.name)
        self.generic_visit(node)
        self._function_stack.pop()

    def visit_Call(self, node: ast.Call) -> None:
        callee = self._call_name(node.func)
        caller = self._function_stack[-1] if self._function_stack else "<module>"
        self.calls.append({"caller": caller, "name": callee, "line": node.lineno})
        self.generic_visit(node)

    def _call_name(self, func: ast.AST) -> str:
        if isinstance(func, ast.Name):
            return func.id
        if isinstance(func, ast.Attribute):
            return func.attr
        return "<unknown>"

    def _decorator_name(self, decorator: ast.AST) -> str:
        if isinstance(decorator, ast.Name):
            return decorator.id
        if isinstance(decorator, ast.Call):
            return self._decorator_name(decorator.func)
        if isinstance(decorator, ast.Attribute):
            return decorator.attr
        return "<unknown>"

    def _route_path(self, decorators: list[ast.expr]) -> str | None:
        for dec in decorators:
            if not isinstance(dec, ast.Call):
                continue
            if isinstance(dec.func, ast.Attribute) and dec.func.attr == "route" and dec.args:
                arg0 = dec.args[0]
                if isinstance(arg0, ast.Constant) and isinstance(arg0.value, str):
                    return arg0.value
        return None


def _parse_python(path: str) -> dict[str, Any]:
    source = Path(path).read_text(encoding="utf-8")
    tree = ast.parse(source)
    visitor = PythonCodeVisitor(path)
    visitor.visit(tree)
    return {
        "file": path,
        "imports": visitor.imports,
        "functions": visitor.functions,
        "calls": visitor.calls,
        "routes": visitor.routes,
    }


def _parse_generic(path: str) -> dict[str, Any]:
    source = Path(path).read_text(encoding="utf-8", errors="ignore")
    imports = re.findall(r"^\s*import\s+([A-Za-z0-9_.*]+)", source, flags=re.MULTILINE)
    function_names = re.findall(
        r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\([^)]*\)\s*\{", source, flags=re.MULTILINE
    )
    calls = re.findall(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(", source)
    return {
        "file": path,
        "imports": imports,
        "functions": [{"name": name, "line": 0} for name in function_names],
        "calls": [{"caller": "<module>", "name": c, "line": 0} for c in calls],
        "routes": [],
    }


def parse_file(path: str) -> dict[str, Any]:
    if Path(path).suffix == ".py":
        return _parse_python(path)
    return _parse_generic(path)

