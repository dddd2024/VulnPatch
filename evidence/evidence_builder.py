"""
Evidence builder for constructing EvidenceBundle objects.

Combines findings, code snippets, agent analysis, and judge decisions
into complete evidence packages.
"""

from audit_core.models import (
    CodeUnit, RawFinding, AgentHypothesis, AgentLog,
    JudgeDecision, EvidenceBundle
)
from evidence.snippet_extractor import extract_snippet
from evidence.call_chain_builder import build_call_chain
from evidence.confidence_ledger import build_confidence_ledger
from knowledge.cwe_mapper import map_cwe


def build_evidence_bundle(
    finding: RawFinding,
    code_unit: CodeUnit | None,
    hypotheses: list[AgentHypothesis],
    agent_logs: list[AgentLog],
    judge_decision: JudgeDecision | None
) -> EvidenceBundle:
    """
    Build a complete evidence bundle for a finding.
    
    Args:
        finding: The vulnerability finding
        code_unit: Optional code unit containing the finding
        hypotheses: List of agent hypotheses
        agent_logs: List of agent execution logs
        judge_decision: Optional judge decision
        
    Returns:
        Complete EvidenceBundle
    """
    # Extract code snippet
    snippets = []
    if code_unit:
        snippet = extract_snippet(
            code_unit,
            finding.start_line,
            finding.end_line,
            context_lines=3
        )
        if snippet["content"]:
            snippets.append(snippet)
    
    # Build call chain
    call_chain = build_call_chain(finding, code_unit)
    
    # Build confidence ledger
    confidence_ledger = build_confidence_ledger(finding, hypotheses, judge_decision)
    
    # Get CWE info
    cwe_info = map_cwe(finding.type)
    
    # Build score breakdown
    score_breakdown = {
        "severity": finding.severity,
        "confidence": finding.confidence,
        "verdict": judge_decision.verdict if judge_decision else None,
        "risk_score": judge_decision.risk_score if judge_decision else 0
    }
    
    return EvidenceBundle(
        finding=finding,
        code_unit=code_unit,
        snippets=snippets,
        call_chain=call_chain,
        agent_hypotheses=hypotheses,
        agent_logs=agent_logs,
        judge_decision=judge_decision,
        cwe_info=cwe_info,
        score_breakdown=score_breakdown,
        metadata={
            "confidence_ledger": confidence_ledger
        }
    )
