"""
Tests for EvidenceBundle builder.

Verifies:
- EvidenceBundle contains finding, code snippet, hypothesis, judge decision
- EvidenceBundle has cwe_info and score_breakdown
"""

import pytest
from audit_core.models import (
    CodeUnit, RawFinding, AgentHypothesis, AgentLog,
    JudgeDecision, EvidenceBundle
)
from evidence.evidence_builder import build_evidence_bundle


# ---------------------------------------------------------------------------
# Test data
# ---------------------------------------------------------------------------

SQL_FINDING = RawFinding(
    rule_id="TEST_SQL_001",
    type="SQL Injection",
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
# Tests
# ---------------------------------------------------------------------------

class TestEvidenceBundleBuilder:

    def test_build_returns_evidence_bundle(self):
        """build_evidence_bundle should return EvidenceBundle."""
        bundle = build_evidence_bundle(
            finding=SQL_FINDING,
            code_unit=CODE_UNIT,
            hypotheses=[HYPOTHESIS],
            agent_logs=[AGENT_LOG],
            judge_decision=JUDGE_DECISION,
        )
        
        assert isinstance(bundle, EvidenceBundle)

    def test_bundle_contains_finding(self):
        """Bundle should contain the finding."""
        bundle = build_evidence_bundle(
            finding=SQL_FINDING,
            code_unit=CODE_UNIT,
            hypotheses=[HYPOTHESIS],
            agent_logs=[AGENT_LOG],
            judge_decision=JUDGE_DECISION,
        )
        
        assert bundle.finding == SQL_FINDING
        assert bundle.finding.type == "SQL Injection"

    def test_bundle_contains_code_unit(self):
        """Bundle should contain the code unit."""
        bundle = build_evidence_bundle(
            finding=SQL_FINDING,
            code_unit=CODE_UNIT,
            hypotheses=[HYPOTHESIS],
            agent_logs=[AGENT_LOG],
            judge_decision=JUDGE_DECISION,
        )
        
        assert bundle.code_unit == CODE_UNIT

    def test_bundle_contains_snippets(self):
        """Bundle should contain code snippets."""
        bundle = build_evidence_bundle(
            finding=SQL_FINDING,
            code_unit=CODE_UNIT,
            hypotheses=[HYPOTHESIS],
            agent_logs=[AGENT_LOG],
            judge_decision=JUDGE_DECISION,
        )
        
        # Should have snippets (if snippet_extractor works)
        assert isinstance(bundle.snippets, list)

    def test_bundle_contains_hypotheses(self):
        """Bundle should contain agent hypotheses."""
        bundle = build_evidence_bundle(
            finding=SQL_FINDING,
            code_unit=CODE_UNIT,
            hypotheses=[HYPOTHESIS],
            agent_logs=[AGENT_LOG],
            judge_decision=JUDGE_DECISION,
        )
        
        assert len(bundle.agent_hypotheses) == 1
        assert bundle.agent_hypotheses[0] == HYPOTHESIS

    def test_bundle_contains_agent_logs(self):
        """Bundle should contain agent logs."""
        bundle = build_evidence_bundle(
            finding=SQL_FINDING,
            code_unit=CODE_UNIT,
            hypotheses=[HYPOTHESIS],
            agent_logs=[AGENT_LOG],
            judge_decision=JUDGE_DECISION,
        )
        
        assert len(bundle.agent_logs) == 1
        assert bundle.agent_logs[0] == AGENT_LOG

    def test_bundle_contains_judge_decision(self):
        """Bundle should contain judge decision."""
        bundle = build_evidence_bundle(
            finding=SQL_FINDING,
            code_unit=CODE_UNIT,
            hypotheses=[HYPOTHESIS],
            agent_logs=[AGENT_LOG],
            judge_decision=JUDGE_DECISION,
        )
        
        assert bundle.judge_decision == JUDGE_DECISION
        assert bundle.judge_decision.verdict == "confirmed"
        assert bundle.judge_decision.risk_score == 85.0

    def test_bundle_contains_cwe_info(self):
        """Bundle should contain CWE info."""
        bundle = build_evidence_bundle(
            finding=SQL_FINDING,
            code_unit=CODE_UNIT,
            hypotheses=[HYPOTHESIS],
            agent_logs=[AGENT_LOG],
            judge_decision=JUDGE_DECISION,
        )
        
        # cwe_info should be a dict (even if empty)
        assert isinstance(bundle.cwe_info, dict)

    def test_bundle_contains_score_breakdown(self):
        """Bundle should contain score breakdown."""
        bundle = build_evidence_bundle(
            finding=SQL_FINDING,
            code_unit=CODE_UNIT,
            hypotheses=[HYPOTHESIS],
            agent_logs=[AGENT_LOG],
            judge_decision=JUDGE_DECISION,
        )
        
        assert isinstance(bundle.score_breakdown, dict)
        assert bundle.score_breakdown.get("severity") == "ERROR"
        assert bundle.score_breakdown.get("confidence") == "high"
        assert bundle.score_breakdown.get("verdict") == "confirmed"
        assert bundle.score_breakdown.get("risk_score") == 85.0

    def test_bundle_without_code_unit(self):
        """Bundle should work without code unit."""
        bundle = build_evidence_bundle(
            finding=SQL_FINDING,
            code_unit=None,
            hypotheses=[HYPOTHESIS],
            agent_logs=[AGENT_LOG],
            judge_decision=JUDGE_DECISION,
        )
        
        assert bundle.code_unit is None
        assert bundle.finding == SQL_FINDING

    def test_bundle_without_judge_decision(self):
        """Bundle should work without judge decision."""
        bundle = build_evidence_bundle(
            finding=SQL_FINDING,
            code_unit=CODE_UNIT,
            hypotheses=[HYPOTHESIS],
            agent_logs=[AGENT_LOG],
            judge_decision=None,
        )
        
        assert bundle.judge_decision is None
        assert bundle.score_breakdown.get("verdict") is None
        assert bundle.score_breakdown.get("risk_score") == 0

    def test_bundle_with_multiple_hypotheses(self):
        """Bundle should handle multiple hypotheses."""
        hypothesis2 = AgentHypothesis(
            agent_name="recon",
            hypothesis="Attack surface identified",
            vulnerability_type="Attack Surface",
            reasoning_summary="SQL operations detected",
            confidence="medium",
        )
        
        bundle = build_evidence_bundle(
            finding=SQL_FINDING,
            code_unit=CODE_UNIT,
            hypotheses=[HYPOTHESIS, hypothesis2],
            agent_logs=[AGENT_LOG],
            judge_decision=JUDGE_DECISION,
        )
        
        assert len(bundle.agent_hypotheses) == 2

    def test_bundle_metadata_contains_confidence_ledger(self):
        """Bundle metadata should contain confidence ledger."""
        bundle = build_evidence_bundle(
            finding=SQL_FINDING,
            code_unit=CODE_UNIT,
            hypotheses=[HYPOTHESIS],
            agent_logs=[AGENT_LOG],
            judge_decision=JUDGE_DECISION,
        )
        
        assert "confidence_ledger" in bundle.metadata


class TestEvidenceBundleStructure:

    def test_bundle_has_all_required_fields(self):
        """Bundle should have all required fields."""
        bundle = build_evidence_bundle(
            finding=SQL_FINDING,
            code_unit=CODE_UNIT,
            hypotheses=[HYPOTHESIS],
            agent_logs=[AGENT_LOG],
            judge_decision=JUDGE_DECISION,
        )
        
        # Check all fields exist
        assert hasattr(bundle, "id")
        assert hasattr(bundle, "finding")
        assert hasattr(bundle, "code_unit")
        assert hasattr(bundle, "snippets")
        assert hasattr(bundle, "call_chain")
        assert hasattr(bundle, "agent_hypotheses")
        assert hasattr(bundle, "agent_logs")
        assert hasattr(bundle, "judge_decision")
        assert hasattr(bundle, "cwe_info")
        assert hasattr(bundle, "score_breakdown")
        assert hasattr(bundle, "metadata")

    def test_bundle_is_serializable(self):
        """Bundle should be serializable to dict."""
        bundle = build_evidence_bundle(
            finding=SQL_FINDING,
            code_unit=CODE_UNIT,
            hypotheses=[HYPOTHESIS],
            agent_logs=[AGENT_LOG],
            judge_decision=JUDGE_DECISION,
        )
        
        # Should be able to convert to dict
        data = bundle.model_dump()
        assert isinstance(data, dict)
        assert "finding" in data
        assert "judge_decision" in data