"""
Strongly-typed Agent interfaces for multi-agent collaboration.

This module defines abstract base classes with explicit type signatures
for each Agent role. Concrete Agents should inherit from these interfaces
to ensure type safety and clear input/output contracts.

Usage:
    from agents.interfaces import ReconAgentBase
    from audit_core.models import CodeUnit, AgentHypothesis, AgentLog

    class MyReconAgent(ReconAgentBase):
        def run(self, code_units: list[CodeUnit]) -> tuple[list[AgentHypothesis], list[AgentLog]]:
            # Implementation with type safety
            ...

Note:
    These interfaces extend BaseAgent but provide strongly-typed run()
    signatures. For generic Agent behavior, use BaseAgent. For specific
    roles, use these interfaces.
"""

from __future__ import annotations

from abc import abstractmethod
from typing import TYPE_CHECKING, Optional

from agents.base_agent import BaseAgent

if TYPE_CHECKING:
    from audit_core.models import (
        CodeUnit,
        RawFinding,
        AgentHypothesis,
        AgentLog,
        JudgeDecision,
        EvidenceBundle,
    )


class ReconAgentBase(BaseAgent):
    """
    Interface for reconnaissance agents.

    ReconAgent performs initial code inspection to identify attack surfaces
    and areas of interest. It analyzes CodeUnit objects without directly
    reading files.

    Input:
        code_units: List of CodeUnit objects to inspect

    Output:
        Tuple of (hypotheses, logs) where:
        - hypotheses: List of AgentHypothesis identifying attack surfaces
        - logs: List of AgentLog recording reconnaissance activity

    Example:
        class MyReconAgent(ReconAgentBase):
            name = "my_recon"

            def run(self, code_units: list[CodeUnit]) -> tuple[list[AgentHypothesis], list[AgentLog]]:
                hypotheses = []
                logs = []
                for unit in code_units:
                    # Analyze unit.content for attack surfaces
                    ...
                return hypotheses, logs
    """

    @abstractmethod
    def run(
        self, code_units: list["CodeUnit"]
    ) -> tuple[list["AgentHypothesis"], list["AgentLog"]]:
        """
        Run reconnaissance on code units.

        Args:
            code_units: List of code units to inspect. Each CodeUnit contains
                       path, language, content, and metadata.

        Returns:
            Tuple of (hypotheses, logs):
            - hypotheses: Attack surface hypotheses for significant findings
            - logs: Execution logs for audit trail

        Note:
            Do NOT read files directly. Use code_units[i].content for analysis.
        """
        pass


class AnalysisAgentBase(BaseAgent):
    """
    Interface for analysis agents.

    AnalysisAgent analyzes RawFinding objects and generates hypotheses about
    potential vulnerabilities. It can use LLM clients or fall back to
    rule-based explanations.

    Input:
        finding: The RawFinding to analyze
        code_unit: Optional CodeUnit containing the finding for context

    Output:
        Tuple of (hypothesis, log) where:
        - hypothesis: AgentHypothesis with vulnerability analysis
        - log: AgentLog recording analysis activity

    Example:
        class MyAnalysisAgent(AnalysisAgentBase):
            name = "my_analysis"

            def run(
                self,
                finding: RawFinding,
                code_unit: CodeUnit | None = None
            ) -> tuple[AgentHypothesis, AgentLog]:
                # Analyze finding and generate hypothesis
                hypothesis = AgentHypothesis(...)
                log = AgentLog(...)
                return hypothesis, log
    """

    @abstractmethod
    def run(
        self,
        finding: "RawFinding",
        code_unit: Optional["CodeUnit"] = None,
    ) -> tuple["AgentHypothesis", "AgentLog"]:
        """
        Analyze a finding and generate a hypothesis.

        Args:
            finding: The RawFinding to analyze. Contains type, severity,
                    confidence, file_path, line number, and evidence.
            code_unit: Optional CodeUnit containing the finding. Provides
                      source code context for LLM analysis.

        Returns:
            Tuple of (hypothesis, log):
            - hypothesis: Vulnerability hypothesis with reasoning
            - log: Execution log for audit trail

        Note:
            Implementations should support fallback when LLM is unavailable.
            Use finding.confidence to determine analysis depth.
        """
        pass


class JudgeAgentBase(BaseAgent):
    """
    Interface for judge agents.

    JudgeAgent evaluates findings and hypotheses to make final determinations
    about vulnerability validity. It assigns verdicts and risk scores.

    Input:
        finding: The RawFinding to evaluate
        hypotheses: List of AgentHypothesis from other agents
        evidence_bundle: Optional EvidenceBundle with supporting evidence

    Output:
        Tuple of (decision, log) where:
        - decision: JudgeDecision with verdict and risk score
        - log: AgentLog recording evaluation activity

    Example:
        class MyJudgeAgent(JudgeAgentBase):
            name = "my_judge"

            def run(
                self,
                finding: RawFinding,
                hypotheses: list[AgentHypothesis],
                evidence_bundle: EvidenceBundle | None = None
            ) -> tuple[JudgeDecision, AgentLog]:
                # Evaluate and make decision
                decision = JudgeDecision(...)
                log = AgentLog(...)
                return decision, log
    """

    @abstractmethod
    def run(
        self,
        finding: "RawFinding",
        hypotheses: list["AgentHypothesis"],
        evidence_bundle: Optional["EvidenceBundle"] = None,
    ) -> tuple["JudgeDecision", "AgentLog"]:
        """
        Make a decision on a finding.

        Args:
            finding: The RawFinding to evaluate. Contains severity,
                    confidence, and metadata for decision making.
            hypotheses: List of AgentHypothesis from ReconAgent and
                       AnalysisAgent. May be empty if no hypotheses generated.
            evidence_bundle: Optional EvidenceBundle with code snippets,
                            call chains, and supporting evidence.

        Returns:
            Tuple of (decision, log):
            - decision: Final verdict (confirmed/suspicious/rejected) with
                       risk score (0-100) and reasoning
            - log: Execution log for audit trail

        Note:
            Verdict logic should consider:
            - finding.confidence (high/medium/low)
            - finding.severity (ERROR/WARN/INFO)
            - hypotheses confidence and reasoning
            - evidence_bundle strength
        """
        pass
