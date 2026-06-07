"""
Tests for VulnerabilityGraph.

Verifies:
- Empty evidence_bundles returns empty graph
- Single EvidenceBundle generates finding/file/cwe/judge nodes
- Contains, classified_as, supported_by, judged_as edges are created
- Nodes and edges have no duplicate ids
- JSON serializability
- Graceful handling of missing data
"""

import pytest
import json
from audit_core.models import (
    CodeUnit, RawFinding, AgentHypothesis, AgentLog,
    JudgeDecision, EvidenceBundle
)
from knowledge.vuln_graph import VulnerabilityGraph


# ---------------------------------------------------------------------------
# Test data
# ---------------------------------------------------------------------------

SQL_FINDING = RawFinding(
    rule_id="TEST_SQL_001",
    type="sql_injection",
    cwe="CWE-89",
    severity="ERROR",
    confidence="high",
    file_path="test.py",
    start_line=5,
    end_line=7,
    message="SQL injection detected",
    engine="test",
    evidence={"symbol": "execute"},
)

CODE_UNIT = CodeUnit(
    path="test.py",
    language="python",
    content="""
def search(user_input):
    conn = sqlite3.connect("db.sqlite3")
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE name = '{user_input}'"
    cursor.execute(query)
    return cursor.fetchall()
""",
    start_line=1,
)

HYPOTHESIS = AgentHypothesis(
    agent_name="analysis",
    finding_id=SQL_FINDING.id,
    hypothesis="Potential SQL Injection vulnerability",
    vulnerability_type="SQL Injection",
    reasoning_summary="User input concatenated into SQL query",
    confidence="high",
)

AGENT_LOG = AgentLog(
    agent_name="analysis",
    stage="analysis",
    message="Analyzed SQL finding",
    input_refs=[SQL_FINDING.id],
    output_refs=[HYPOTHESIS.id],
)

JUDGE_DECISION = JudgeDecision(
    finding_id=SQL_FINDING.id,
    verdict="confirmed",
    confidence="high",
    risk_score=85.0,
    reason="Clear SQL injection with user input",
)


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def create_complete_bundle():
    """Create a complete EvidenceBundle with all fields."""
    return EvidenceBundle(
        finding=SQL_FINDING,
        code_unit=CODE_UNIT,
        agent_hypotheses=[HYPOTHESIS],
        agent_logs=[AGENT_LOG],
        judge_decision=JUDGE_DECISION,
        cwe_info={
            "id": "CWE-89",
            "name": "SQL Injection",
            "description": "Improper Neutralization of Special Elements used in an SQL Command",
        },
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestVulnerabilityGraphEmpty:
    """Empty input tests."""

    def test_empty_bundles_returns_empty_graph(self):
        """Empty evidence_bundles should return empty graph."""
        graph_builder = VulnerabilityGraph()
        result = graph_builder.build([])
        
        assert result["nodes"] == []
        assert result["edges"] == []

    def test_none_bundles_returns_empty_graph(self):
        """None input should return empty graph."""
        graph_builder = VulnerabilityGraph()
        result = graph_builder.build(None)
        
        assert result["nodes"] == []
        assert result["edges"] == []


class TestVulnerabilityGraphNodeTypes:
    """Node type generation tests."""

    def test_generates_finding_node(self):
        """Should generate finding node."""
        graph_builder = VulnerabilityGraph()
        bundle = create_complete_bundle()
        result = graph_builder.build([bundle])
        
        finding_nodes = [n for n in result["nodes"] if n["type"] == "finding"]
        assert len(finding_nodes) == 1
        assert finding_nodes[0]["metadata"]["finding_id"] == SQL_FINDING.id

    def test_generates_file_node(self):
        """Should generate file node when code_unit exists."""
        graph_builder = VulnerabilityGraph()
        bundle = create_complete_bundle()
        result = graph_builder.build([bundle])
        
        file_nodes = [n for n in result["nodes"] if n["type"] == "file"]
        assert len(file_nodes) == 1
        assert file_nodes[0]["metadata"]["path"] == "test.py"

    def test_generates_cwe_node(self):
        """Should generate cwe node when cwe_info exists."""
        graph_builder = VulnerabilityGraph()
        bundle = create_complete_bundle()
        result = graph_builder.build([bundle])
        
        cwe_nodes = [n for n in result["nodes"] if n["type"] == "cwe"]
        assert len(cwe_nodes) == 1

    def test_generates_agent_hypothesis_node(self):
        """Should generate agent_hypothesis node."""
        graph_builder = VulnerabilityGraph()
        bundle = create_complete_bundle()
        result = graph_builder.build([bundle])
        
        hypo_nodes = [n for n in result["nodes"] if n["type"] == "agent_hypothesis"]
        assert len(hypo_nodes) == 1
        assert hypo_nodes[0]["metadata"]["agent_name"] == "analysis"

    def test_generates_judge_decision_node(self):
        """Should generate judge_decision node when judge_decision exists."""
        graph_builder = VulnerabilityGraph()
        bundle = create_complete_bundle()
        result = graph_builder.build([bundle])
        
        decision_nodes = [n for n in result["nodes"] if n["type"] == "judge_decision"]
        assert len(decision_nodes) == 1
        assert decision_nodes[0]["metadata"]["verdict"] == "confirmed"


class TestVulnerabilityGraphEdges:
    """Edge generation tests."""

    def test_generates_contains_edge(self):
        """Should generate contains edge from file to finding."""
        graph_builder = VulnerabilityGraph()
        bundle = create_complete_bundle()
        result = graph_builder.build([bundle])
        
        contains_edges = [e for e in result["edges"] if e["relation"] == "contains"]
        assert len(contains_edges) == 1
        
        edge = contains_edges[0]
        assert edge["source"].startswith("file:")
        assert edge["target"].startswith("finding:")

    def test_generates_classified_as_edge(self):
        """Should generate classified_as edge from finding to cwe."""
        graph_builder = VulnerabilityGraph()
        bundle = create_complete_bundle()
        result = graph_builder.build([bundle])
        
        classified_edges = [e for e in result["edges"] if e["relation"] == "classified_as"]
        assert len(classified_edges) == 1
        
        edge = classified_edges[0]
        assert edge["source"].startswith("finding:")
        assert edge["target"].startswith("cwe:")

    def test_generates_supported_by_edge(self):
        """Should generate supported_by edge from finding to hypothesis."""
        graph_builder = VulnerabilityGraph()
        bundle = create_complete_bundle()
        result = graph_builder.build([bundle])
        
        supported_edges = [e for e in result["edges"] if e["relation"] == "supported_by"]
        assert len(supported_edges) == 1
        
        edge = supported_edges[0]
        assert edge["source"].startswith("finding:")
        assert edge["target"].startswith("hypothesis:")

    def test_generates_judged_as_edge(self):
        """Should generate judged_as edge from finding to decision."""
        graph_builder = VulnerabilityGraph()
        bundle = create_complete_bundle()
        result = graph_builder.build([bundle])
        
        judged_edges = [e for e in result["edges"] if e["relation"] == "judged_as"]
        assert len(judged_edges) == 1
        
        edge = judged_edges[0]
        assert edge["source"].startswith("finding:")
        assert edge["target"].startswith("decision:")


class TestVulnerabilityGraphDeduplication:
    """Node and edge deduplication tests."""

    def test_no_duplicate_node_ids(self):
        """Should not have duplicate node ids."""
        graph_builder = VulnerabilityGraph()
        bundle = create_complete_bundle()
        result = graph_builder.build([bundle])
        
        node_ids = [n["id"] for n in result["nodes"]]
        assert len(node_ids) == len(set(node_ids))

    def test_no_duplicate_edges(self):
        """Should not have duplicate edges."""
        graph_builder = VulnerabilityGraph()
        bundle = create_complete_bundle()
        result = graph_builder.build([bundle])
        
        edge_keys = [(e["source"], e["target"], e["relation"]) for e in result["edges"]]
        assert len(edge_keys) == len(set(edge_keys))

    def test_same_bundle_twice_does_not_duplicate(self):
        """Processing same bundle twice should not duplicate nodes."""
        graph_builder = VulnerabilityGraph()
        bundle = create_complete_bundle()
        
        # Build twice with same bundle
        result1 = graph_builder.build([bundle])
        node_count_1 = len(result1["nodes"])
        
        graph_builder.reset()
        result2 = graph_builder.build([bundle, bundle])
        node_count_2 = len(result2["nodes"])
        
        # Node count should be the same (no duplicates)
        assert node_count_1 == node_count_2


class TestVulnerabilityGraphGracefulHandling:
    """Graceful handling of missing data tests."""

    def test_missing_code_unit_no_file_node(self):
        """Missing code_unit should not generate file node."""
        graph_builder = VulnerabilityGraph()
        bundle = EvidenceBundle(
            finding=SQL_FINDING,
            code_unit=None,  # No code unit
            hypotheses=[HYPOTHESIS],
            agent_logs=[AGENT_LOG],
            judge_decision=JUDGE_DECISION,
        )
        result = graph_builder.build([bundle])
        
        file_nodes = [n for n in result["nodes"] if n["type"] == "file"]
        assert len(file_nodes) == 0
        
        # Finding node should still exist
        finding_nodes = [n for n in result["nodes"] if n["type"] == "finding"]
        assert len(finding_nodes) == 1

    def test_missing_judge_decision_no_decision_node(self):
        """Missing judge_decision should not generate decision node."""
        graph_builder = VulnerabilityGraph()
        bundle = EvidenceBundle(
            finding=SQL_FINDING,
            code_unit=CODE_UNIT,
            hypotheses=[HYPOTHESIS],
            agent_logs=[AGENT_LOG],
            judge_decision=None,  # No judge decision
        )
        result = graph_builder.build([bundle])
        
        decision_nodes = [n for n in result["nodes"] if n["type"] == "judge_decision"]
        assert len(decision_nodes) == 0

    def test_missing_cwe_info_no_cwe_node(self):
        """Missing cwe_info should not generate cwe node."""
        graph_builder = VulnerabilityGraph()
        bundle = EvidenceBundle(
            finding=SQL_FINDING,
            code_unit=CODE_UNIT,
            hypotheses=[HYPOTHESIS],
            agent_logs=[AGENT_LOG],
            judge_decision=JUDGE_DECISION,
        )
        # Clear cwe_info
        bundle.cwe_info = {}
        
        result = graph_builder.build([bundle])
        
        cwe_nodes = [n for n in result["nodes"] if n["type"] == "cwe"]
        assert len(cwe_nodes) == 0


class TestVulnerabilityGraphJSONSerialization:
    """JSON serialization tests."""

    def test_graph_is_json_serializable(self):
        """Graph should be JSON serializable."""
        graph_builder = VulnerabilityGraph()
        bundle = create_complete_bundle()
        result = graph_builder.build([bundle])
        
        # Should not raise exception
        json_str = json.dumps(result)
        assert isinstance(json_str, str)
        
        # Should be parseable
        parsed = json.loads(json_str)
        assert "nodes" in parsed
        assert "edges" in parsed


class TestVulnerabilityGraphMultipleBundles:
    """Multiple EvidenceBundle tests."""

    def test_multiple_bundles_create_multiple_findings(self):
        """Multiple bundles should create multiple finding nodes."""
        graph_builder = VulnerabilityGraph()
        
        # Create second finding
        finding2 = RawFinding(
            rule_id="TEST_CMD_001",
            type="command_injection",
            cwe="CWE-78",
            severity="ERROR",
            confidence="high",
            file_path="test2.py",
            start_line=10,
            message="Command injection detected",
            engine="test",
        )
        
        bundle1 = create_complete_bundle()
        bundle2 = EvidenceBundle(
            finding=finding2,
            code_unit=CODE_UNIT,
            hypotheses=[],
            agent_logs=[],
            judge_decision=None,
        )
        
        result = graph_builder.build([bundle1, bundle2])
        
        finding_nodes = [n for n in result["nodes"] if n["type"] == "finding"]
        assert len(finding_nodes) == 2


class TestVulnerabilityGraphNodeStructure:
    """Node structure tests."""

    def test_nodes_have_required_fields(self):
        """Nodes should have required fields."""
        graph_builder = VulnerabilityGraph()
        bundle = create_complete_bundle()
        result = graph_builder.build([bundle])
        
        for node in result["nodes"]:
            assert "id" in node
            assert "type" in node
            assert "label" in node
            assert "metadata" in node

    def test_edges_have_required_fields(self):
        """Edges should have required fields."""
        graph_builder = VulnerabilityGraph()
        bundle = create_complete_bundle()
        result = graph_builder.build([bundle])
        
        for edge in result["edges"]:
            assert "source" in edge
            assert "target" in edge
            assert "relation" in edge
            assert "metadata" in edge


class TestVulnerabilityGraphHelperMethods:
    """Helper method tests."""

    def test_reset_clears_graph(self):
        """reset() should clear the graph."""
        graph_builder = VulnerabilityGraph()
        bundle = create_complete_bundle()
        graph_builder.build([bundle])
        
        assert graph_builder.get_node_count() > 0
        
        graph_builder.reset()
        
        assert graph_builder.get_node_count() == 0
        assert graph_builder.get_edge_count() == 0

    def test_get_node_count_returns_correct_count(self):
        """get_node_count() should return correct node count."""
        graph_builder = VulnerabilityGraph()
        bundle = create_complete_bundle()
        graph_builder.build([bundle])
        
        # Should have: finding, file, cwe, hypothesis, decision = 5 nodes
        assert graph_builder.get_node_count() == 5

    def test_get_edge_count_returns_correct_count(self):
        """get_edge_count() should return correct edge count."""
        graph_builder = VulnerabilityGraph()
        bundle = create_complete_bundle()
        graph_builder.build([bundle])
        
        # Should have: contains, classified_as, supported_by, judged_as = 4 edges
        assert graph_builder.get_edge_count() == 4