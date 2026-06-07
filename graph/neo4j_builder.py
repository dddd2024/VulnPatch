from typing import Any, Iterable, Tuple

try:
    from neo4j import GraphDatabase
except Exception:  # pragma: no cover - optional dependency at runtime
    GraphDatabase = None  # type: ignore[assignment]


class GraphWriter:
    def __init__(
        self,
        uri: str = "bolt://localhost:7687",
        user: str = "neo4j",
        password: str = "password",
    ) -> None:
        if GraphDatabase is None:
            raise RuntimeError(
                "neo4j package is not available. Install it before using GraphWriter."
            )
        self.driver = GraphDatabase.driver(uri, auth=(user, password))

    def close(self) -> None:
        self.driver.close()

    def add_function_call(self, src: str, dst: str) -> None:
        query = """
        MERGE (a:Function {name:$src})
        MERGE (b:Function {name:$dst})
        MERGE (a)-[:CALLS]->(b)
        """
        with self.driver.session() as session:
            session.run(query, src=src, dst=dst)

    def write_edges(self, edges: Iterable[Tuple[str, str]]) -> None:
        for src, dst in edges:
            self.add_function_call(src, dst)

    def run_query(self, query: str, **params: Any) -> None:
        with self.driver.session() as session:
            session.run(query, **params)

    def write_security_knowledge_graph(
        self,
        nodes: Iterable[dict[str, Any]],
        edges: Iterable[dict[str, str]],
    ) -> None:
        node_rows = [
            {
                "id": str(node["id"]),
                "kind": str(node.get("kind", "unknown")),
                "title": str(node.get("title", "")),
                "props": {k: v for k, v in node.items() if k not in {"id", "kind", "title"}},
            }
            for node in nodes
        ]
        self.run_query(
            """
            UNWIND $nodes AS n
            MERGE (x:SecurityKnowledge {id: n.id})
            SET x.kind = n.kind, x.title = n.title
            SET x += n.props
            """,
            nodes=node_rows,
        )

        edge_rows = [
            {
                "source": str(edge["source"]),
                "target": str(edge["target"]),
                "type": str(edge.get("type", "RELATES_TO")),
            }
            for edge in edges
        ]
        self.run_query(
            """
            UNWIND $edges AS e
            MATCH (s:SecurityKnowledge {id: e.source})
            MATCH (t:SecurityKnowledge {id: e.target})
            MERGE (s)-[r:SEC_REL {type: e.type}]->(t)
            """,
            edges=edge_rows,
        )

