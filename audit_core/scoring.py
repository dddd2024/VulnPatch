"""
Scoring module for calculating risk scores for findings.

This module provides lightweight scoring logic without complex CVSS calculations.
Scores are based on severity, confidence, and judge verdict.
"""

from audit_core.models import RawFinding, JudgeDecision


def score_finding(
    finding: RawFinding,
    judge_decision: JudgeDecision | None = None
) -> dict:
    """
    Calculate risk score for a finding.
    
    The scoring logic is:
    - Severity: ERROR/HIGH/CRITICAL -> 40 points, WARN/MEDIUM -> 25 points, INFO/LOW -> 10 points
    - Confidence: high -> +20 points, medium -> +10 points, low -> 0 points
    - Judge verdict: confirmed -> +20 points, suspicious -> +5 points, rejected -> -30 points
    
    Args:
        finding: The raw finding to score
        judge_decision: Optional judge decision to factor in
        
    Returns:
        Dictionary with score breakdown and total risk score
    """
    # Base severity score
    severity_scores = {
        "CRITICAL": 40,
        "ERROR": 40,
        "HIGH": 40,
        "WARN": 25,
        "MEDIUM": 25,
        "INFO": 10,
        "LOW": 10,
        "UNKNOWN": 5
    }
    severity_score = severity_scores.get(finding.severity.upper(), 5)
    
    # Confidence score
    confidence_scores = {
        "high": 20,
        "medium": 10,
        "low": 0
    }
    confidence_score = confidence_scores.get(finding.confidence.lower(), 0)
    
    # Judge score
    judge_score = 0
    if judge_decision:
        verdict_scores = {
            "confirmed": 20,
            "suspicious": 5,
            "rejected": -30
        }
        judge_score = verdict_scores.get(judge_decision.verdict.lower(), 0)
    
    # Calculate total risk score (clamped between 0 and 100)
    total_score = severity_score + confidence_score + judge_score
    risk_score = max(0, min(100, total_score))
    
    return {
        "risk_score": risk_score,
        "severity_score": severity_score,
        "confidence_score": confidence_score,
        "judge_score": judge_score,
        "severity": finding.severity,
        "confidence": finding.confidence,
        "verdict": judge_decision.verdict if judge_decision else None
    }
