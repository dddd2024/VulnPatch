"""
Error policy module for Agent error handling and degradation strategies.

This module defines error policies and fallback strategies for different
stages of the audit pipeline. When Agents fail, the system should gracefully
degrade rather than crashing the entire scan.
"""

from typing import Literal, Any
from dataclasses import dataclass, field
from datetime import datetime

from audit_core.models import AgentHypothesis, JudgeDecision, AgentLog


AgentExecutionStatus = Literal["success", "degraded", "failed", "skipped"]


@dataclass
class AgentExecutionResult:
    """
    Result of an Agent execution with error handling.

    This dataclass encapsulates the outcome of an Agent execution,
    including the output, logs, error information, and fallback status.
    """
    status: AgentExecutionStatus
    output: Any = None
    logs: list[AgentLog] = field(default_factory=list)
    error: Exception | None = None
    fallback_used: bool = False
    stage: str = ""
    agent_name: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "status": self.status,
            "output_type": type(self.output).__name__ if self.output else None,
            "log_count": len(self.logs),
            "error_type": type(self.error).__name__ if self.error else None,
            "error_message": str(self.error) if self.error else None,
            "fallback_used": self.fallback_used,
            "stage": self.stage,
            "agent_name": self.agent_name,
        }


class ErrorPolicy:
    """
    Error policy defining degradation strategies for different stages.

    This class provides fallback strategies when Agents fail:
    - recon: Return empty hypotheses, continue flow
    - analysis: Generate low-confidence hypothesis, continue flow
    - judge: Generate default JudgeDecision with conservative values
    - evidence: Preserve RawFinding, log failure, continue
    """

    # Default conservative risk score for fallback decisions
    FALLBACK_RISK_SCORE = 30

    @staticmethod
    def create_fallback_recon_result(
        code_unit_count: int,
        error: Exception | None = None
    ) -> AgentExecutionResult:
        """
        Create fallback result when ReconAgent fails.

        Strategy: Return empty hypotheses list, log the failure,
        and allow the flow to continue.

        Args:
            code_unit_count: Number of code units that were to be analyzed
            error: The exception that caused the failure, if any

        Returns:
            AgentExecutionResult with empty hypotheses and failure log
        """
        log = AgentLog(
            agent_name="recon",
            stage="recon",
            message=f"ReconAgent failed: {str(error) if error else 'Unknown error'}. "
                    "Returning empty hypotheses and continuing.",
            input_refs=[],
            output_refs=[],
            metadata={
                "error_type": type(error).__name__ if error else None,
                "error_message": str(error) if error else None,
                "code_unit_count": code_unit_count,
                "fallback_applied": True,
            }
        )

        return AgentExecutionResult(
            status="failed",
            output=[],  # Empty hypotheses list
            logs=[log],
            error=error,
            fallback_used=True,
            stage="recon",
            agent_name="recon"
        )

    @staticmethod
    def create_fallback_analysis_result(
        finding_id: str,
        finding_type: str,
        error: Exception | None = None
    ) -> AgentExecutionResult:
        """
        Create fallback result when AnalysisAgent fails.

        Strategy: Generate a low-confidence hypothesis with minimal
        information, log the failure, and allow the flow to continue.

        Args:
            finding_id: ID of the finding being analyzed
            finding_type: Type of the finding
            error: The exception that caused the failure, if any

        Returns:
            AgentExecutionResult with fallback hypothesis and failure log
        """
        # Create a minimal fallback hypothesis
        hypothesis = AgentHypothesis(
            agent_name="analysis",
            hypothesis=f"Analysis failed for {finding_type} finding",
            vulnerability_type=f"Unknown - {finding_type}",
            reasoning_summary=f"AnalysisAgent failed: {str(error) if error else 'Unknown error'}. "
                              "This is a fallback hypothesis with low confidence.",
            confidence="low",
            finding_id=finding_id,
            supporting_evidence_ids=[],
            metadata={
                "fallback_applied": True,
                "error_type": type(error).__name__ if error else None,
                "error_message": str(error) if error else None,
                "original_finding_type": finding_type,
            }
        )

        log = AgentLog(
            agent_name="analysis",
            stage="analysis",
            message=f"AnalysisAgent failed for finding {finding_id}: "
                    f"{str(error) if error else 'Unknown error'}. "
                    "Generated fallback hypothesis with low confidence.",
            input_refs=[finding_id],
            output_refs=[hypothesis.id],
            metadata={
                "error_type": type(error).__name__ if error else None,
                "error_message": str(error) if error else None,
                "fallback_applied": True,
                "hypothesis_id": hypothesis.id,
            }
        )

        return AgentExecutionResult(
            status="degraded",
            output=hypothesis,
            logs=[log],
            error=error,
            fallback_used=True,
            stage="analysis",
            agent_name="analysis"
        )

    @staticmethod
    def create_fallback_judge_result(
        finding_id: str,
        error: Exception | None = None
    ) -> AgentExecutionResult:
        """
        Create fallback result when JudgeAgent fails.

        Strategy: Generate a default JudgeDecision with:
        - verdict = "suspicious" (conservative, requires review)
        - confidence = "low"
        - risk_score = 30 (conservative value)
        - reason explaining the fallback

        Args:
            finding_id: ID of the finding being judged
            error: The exception that caused the failure, if any

        Returns:
            AgentExecutionResult with fallback JudgeDecision and failure log
        """
        # Create a conservative fallback decision
        decision = JudgeDecision(
            finding_id=finding_id,
            verdict="suspicious",
            confidence="low",
            risk_score=ErrorPolicy.FALLBACK_RISK_SCORE,
            reason=f"JudgeAgent failed: {str(error) if error else 'Unknown error'}. "
                   "Fallback decision applied with verdict='suspicious', "
                   "confidence='low', and conservative risk_score=30. "
                   "This finding requires manual review.",
            metadata={
                "fallback_applied": True,
                "error_type": type(error).__name__ if error else None,
                "error_message": str(error) if error else None,
                "original_verdict": None,
            }
        )

        log = AgentLog(
            agent_name="judge",
            stage="judge",
            message=f"JudgeAgent failed for finding {finding_id}: "
                    f"{str(error) if error else 'Unknown error'}. "
                    "Generated fallback decision with verdict='suspicious' "
                    f"and risk_score={ErrorPolicy.FALLBACK_RISK_SCORE}.",
            input_refs=[finding_id],
            output_refs=[decision.id],
            metadata={
                "error_type": type(error).__name__ if error else None,
                "error_message": str(error) if error else None,
                "fallback_applied": True,
                "decision_id": decision.id,
                "verdict": "suspicious",
                "risk_score": ErrorPolicy.FALLBACK_RISK_SCORE,
            }
        )

        return AgentExecutionResult(
            status="degraded",
            output=decision,
            logs=[log],
            error=error,
            fallback_used=True,
            stage="judge",
            agent_name="judge"
        )

    @staticmethod
    def create_evidence_failure_log(
        finding_id: str,
        error: Exception | None = None
    ) -> AgentLog:
        """
        Create a log entry when EvidenceBuilder fails.

        Strategy: Log the failure but don't crash. The finding should
        still be preserved in the audit result.

        Args:
            finding_id: ID of the finding for which evidence building failed
            error: The exception that caused the failure, if any

        Returns:
            AgentLog documenting the evidence building failure
        """
        return AgentLog(
            agent_name="evidence_builder",
            stage="evidence",
            message=f"EvidenceBuilder failed for finding {finding_id}: "
                    f"{str(error) if error else 'Unknown error'}. "
                    "Finding preserved without evidence bundle.",
            input_refs=[finding_id],
            output_refs=[],
            metadata={
                "error_type": type(error).__name__ if error else None,
                "error_message": str(error) if error else None,
                "fallback_applied": True,
                "finding_preserved": True,
            }
        )

    @staticmethod
    def create_success_log(
        agent_name: str,
        stage: str,
        message: str,
        input_refs: list[str] | None = None,
        output_refs: list[str] | None = None,
        metadata: dict[str, Any] | None = None
    ) -> AgentLog:
        """
        Create a standard success log entry.

        Args:
            agent_name: Name of the agent
            stage: Execution stage
            message: Log message
            input_refs: References to input objects
            output_refs: References to output objects
            metadata: Additional metadata

        Returns:
            AgentLog documenting successful execution
        """
        return AgentLog(
            agent_name=agent_name,
            stage=stage,
            message=message,
            input_refs=input_refs or [],
            output_refs=output_refs or [],
            metadata=metadata or {}
        )
