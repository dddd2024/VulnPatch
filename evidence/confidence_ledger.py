"""
Confidence ledger for tracking confidence scores.

Tracks confidence from analyzers, agents, and judge decisions.
"""

from audit_core.models import RawFinding, AgentHypothesis, JudgeDecision


def build_confidence_ledger(
    finding: RawFinding,
    hypotheses: list[AgentHypothesis],
    judge_decision: JudgeDecision | None = None
) -> dict:
    """
    Build a confidence ledger for a finding.
    
    Args:
        finding: The original finding
        hypotheses: List of agent hypotheses
        judge_decision: Optional judge decision
        
    Returns:
        Dictionary with confidence information:
        - analyzer_confidence: Confidence from the analyzer
        - agent_confidences: List of agent confidences
        - judge_confidence: Confidence from judge (if available)
        - notes: List of confidence-related notes
    """
    agent_confidences = [
        {
            "agent": h.agent_name,
            "confidence": h.confidence,
            "hypothesis_id": h.id
        }
        for h in hypotheses
    ]
    
    notes = []
    
    # Add note if analyzer confidence differs from judge
    if judge_decision and finding.confidence != judge_decision.confidence:
        notes.append(
            f"Analyzer confidence ({finding.confidence}) differs from "
            f"judge confidence ({judge_decision.confidence})"
        )
    
    # Add note about high-confidence findings
    if finding.confidence == "high":
        notes.append("High confidence finding from analyzer")
    
    return {
        "analyzer_confidence": finding.confidence,
        "agent_confidences": agent_confidences,
        "judge_confidence": judge_decision.confidence if judge_decision else None,
        "notes": notes
    }
