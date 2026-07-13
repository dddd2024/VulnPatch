from graph.vuln_knowledge_graph import build_vulnerability_knowledge_graph


def test_build_vulnerability_knowledge_graph_contains_expected_nodes_and_edges():
    vulnerabilities = [
        {
            "type": "SQL Injection",
            "severity": "ERROR",
            "cwe": "CWE-89",
            "risk_score": 90,
            "file": "repo/db.py",
            "line": 12,
        }
    ]
    graph = build_vulnerability_knowledge_graph(vulnerabilities, ai_mode="rule")
    kinds = {node["kind"] for node in graph["nodes"]}
    rels = {edge["type"] for edge in graph["edges"]}

    assert graph["summary"]["vulnerability_count"] == 1
    assert "vulnerability" in kinds
    assert "cwe" in kinds
    assert "reference_case" in kinds
    assert "fix_pattern" in kinds
    assert "ai_insight" in kinds
    assert "HAS_CWE" in rels
    assert "REFERENCES_CASE" in rels
    assert "RECOMMENDS_FIX" in rels
    assert "HAS_INSIGHT" in rels


def test_build_vulnerability_knowledge_graph_handles_unknown_type():
    vulnerabilities = [
        {
            "type": "Unknown Vuln",
            "severity": "WARN",
            "risk_score": 60,
            "file": "repo/sample.py",
            "line": 3,
        }
    ]
    graph = build_vulnerability_knowledge_graph(vulnerabilities, ai_mode="rule")
    vuln_nodes = [node for node in graph["nodes"] if node["kind"] == "vulnerability"]
    assert vuln_nodes
    assert vuln_nodes[0]["cwe"] == "CWE-Other"
