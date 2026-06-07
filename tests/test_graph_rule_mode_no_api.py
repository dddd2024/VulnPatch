from graph.vuln_knowledge_graph import build_vulnerability_knowledge_graph


def test_graph_rule_mode_does_not_call_llm_client(monkeypatch):
    def fail_if_instantiated(*args, **kwargs):
        raise AssertionError("LLMClient must not be used in graph rule mode")

    monkeypatch.setattr("graph.vuln_knowledge_graph.LLMClient", fail_if_instantiated)
    graph = build_vulnerability_knowledge_graph(
        [
            {
                "type": "SQL Injection",
                "severity": "ERROR",
                "cwe": "CWE-89",
                "risk_score": 90,
                "file": "repo/db.py",
                "line": 12,
            }
        ],
        ai_mode="rule",
    )

    insight_nodes = [node for node in graph["nodes"] if node["kind"] == "ai_insight"]
    assert insight_nodes
    assert insight_nodes[0]["mode"] == "rule"
