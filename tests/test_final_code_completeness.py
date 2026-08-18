from __future__ import annotations

from audit_core.models import CodeUnit, RawFinding
from audit_core.orchestrator import AuditOrchestrator
from evidence.call_chain_builder import build_call_chain
from knowledge.legacy_graph_adapter import LegacyGraphAdapter


def _finding(*, line: int, vuln_type: str = "SQL Injection", cwe: str = "CWE-89") -> RawFinding:
    return RawFinding(
        rule_id="TEST_FINAL_COMPLETENESS",
        type=vuln_type,
        cwe=cwe,
        severity="ERROR",
        confidence="high",
        file_path="sample.py",
        start_line=line,
        end_line=line,
        message="test finding",
        engine="test",
    )


def test_call_chain_builder_returns_observed_python_callers():
    code = """def entry(user):
    return service(user)

def service(user):
    return dangerous(user)

def dangerous(user):
    return eval(user)
"""
    unit = CodeUnit(path="sample.py", language="python", content=code)
    chain = build_call_chain(_finding(line=8, vuln_type="Code Injection", cwe="CWE-95"), unit)

    assert [step["name"] for step in chain] == ["entry", "service", "dangerous"]
    assert chain[-1]["vulnerable"] is True
    assert all(step["file"] == "sample.py" for step in chain)


def test_legacy_graph_adapter_delegates_to_real_graph_builder():
    graph = LegacyGraphAdapter().build([_finding(line=4)])

    assert graph["summary"]["vulnerability_count"] == 1
    assert graph["summary"]["node_count"] > 0
    assert graph["summary"]["edge_count"] > 0
    assert any(node.get("kind") == "vulnerability" for node in graph["nodes"])
    assert any(edge.get("type") == "HAS_CWE" for edge in graph["edges"])


def test_formal_orchestrator_populates_cve_candidate_assessments():
    code = """def dangerous(user):
    return eval(user)
"""
    result = AuditOrchestrator().scan_code(code, language="python")

    assert result.findings, "the deterministic AST analyzer should detect eval()"
    assert len(result.cve_candidates) == len(result.findings)
    assert all("cve_candidate" in item for item in result.cve_candidates)
    cve_stage = result.metadata["stage_results"]["cve_candidate"]
    assert cve_stage["success"] is True
    assert cve_stage["metrics"]["assessment_count"] == len(result.findings)
