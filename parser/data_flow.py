import ast
from pathlib import Path
from typing import Any


class DataFlowVisitor(ast.NodeVisitor):
    SOURCES = {"get", "get_json", "args", "form"}
    SINKS = {"execute", "open"}

    def __init__(self) -> None:
        self.sources: set[str] = set()
        self.sinks: set[str] = set()
        self.edges: list[tuple[str, str]] = []

    def visit_Assign(self, node: ast.Assign) -> None:
        value_name = self._extract_name(node.value)
        for target in node.targets:
            if isinstance(target, ast.Name):
                self.edges.append((value_name, target.id))
                if value_name in self.sources:
                    self.sources.add(target.id)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        func_name = self._extract_name(node.func)
        if func_name in self.SOURCE_NAMES():
            self.sources.add(func_name)
        if func_name in self.SINKS:
            self.sinks.add(func_name)
            for arg in node.args:
                arg_name = self._extract_name(arg)
                if arg_name:
                    self.edges.append((arg_name, func_name))
        self.generic_visit(node)

    @classmethod
    def SOURCE_NAMES(cls) -> set[str]:
        return set(cls.SOURCES)

    def _extract_name(self, node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            return node.attr
        if isinstance(node, ast.Call):
            return self._extract_name(node.func)
        return "<expr>"


def build_data_flow(path: str) -> dict[str, Any]:
    source = Path(path).read_text(encoding="utf-8")
    tree = ast.parse(source)
    visitor = DataFlowVisitor()
    visitor.visit(tree)
    return {
        "file": path,
        "sources": sorted(visitor.sources),
        "sinks": sorted(visitor.sinks),
        "edges": [{"from": s, "to": t} for s, t in visitor.edges],
    }

