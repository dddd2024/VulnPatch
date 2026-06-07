from pathlib import Path

import networkx as nx

from parser.ast_parser import parse_file
from parser.repo_scanner import scan_repo


def build_call_graph(repo_root: str = "repo") -> nx.DiGraph:
    graph = nx.DiGraph()
    for file in scan_repo(repo_root):
        data = parse_file(file)
        for fn in data["functions"]:
            graph.add_node(fn["name"], type="function", file=file)
        for call in data["calls"]:
            caller = call["caller"]
            callee = call["name"]
            graph.add_node(caller, type="function", file=file)
            graph.add_node(callee, type="function", file=file)
            graph.add_edge(caller, callee, line=call["line"])
    return graph


def export_edges(graph: nx.DiGraph) -> list[dict[str, str]]:
    return [{"source": str(src), "target": str(dst)} for src, dst in graph.edges()]


if __name__ == "__main__":
    g = build_call_graph(str(Path("repo")))
    print(export_edges(g))

