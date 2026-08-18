"""Fault-isolating execution wrapper for audit agents.

The runtime depends on the typed agent interfaces rather than concrete agent
implementations.  Each stage converts exceptions into the degradation policy
from :mod:`audit_core.error_policy` so one failed agent does not abort a scan.
"""
from __future__ import annotations

from typing import Iterable, Optional

from agents.interfaces import ReconAgentBase, AnalysisAgentBase, JudgeAgentBase
from audit_core.error_policy import AgentExecutionResult, ErrorPolicy
from audit_core.models import CodeUnit, RawFinding, AgentHypothesis, AgentLog, JudgeDecision, EvidenceBundle
from evidence.evidence_builder import build_evidence_bundle


class AgentRuntime:
    """Execute agent stages with uniform error isolation and audit logging."""

    def run_recon(
        self, agent: ReconAgentBase, code_units: list[CodeUnit]
    ) -> AgentExecutionResult:
        try:
            hypotheses, logs = agent.run(code_units)
            success_log = ErrorPolicy.create_success_log(
                agent_name="recon",
                stage="recon",
                message=f"Recon agent completed with {len(hypotheses)} hypotheses",
                input_refs=[unit.id for unit in code_units],
                output_refs=[h.id for h in hypotheses],
                metadata={"hypothesis_count": len(hypotheses)},
            )
            return AgentExecutionResult(
                status="success", output=hypotheses, logs=list(logs) + [success_log],
                stage="recon", agent_name="recon"
            )
        except Exception as exc:  # stage-level isolation is deliberate
            return ErrorPolicy.create_fallback_recon_result(len(code_units), exc)

    def run_analysis(
        self,
        agent: AnalysisAgentBase,
        finding: RawFinding,
        code_unit: Optional[CodeUnit] = None,
    ) -> AgentExecutionResult:
        try:
            hypothesis, log = agent.run(finding, code_unit)
            return AgentExecutionResult(
                status="success", output=hypothesis, logs=[log], stage="analysis",
                agent_name=getattr(agent, "name", "analysis")
            )
        except Exception as exc:
            return ErrorPolicy.create_fallback_analysis_result(
                finding_id=finding.id, finding_type=finding.type, error=exc
            )

    def run_judge(
        self,
        agent: JudgeAgentBase,
        finding: RawFinding,
        hypotheses: list[AgentHypothesis],
        evidence_bundle: Optional[EvidenceBundle] = None,
    ) -> AgentExecutionResult:
        try:
            decision, log = agent.run(finding, hypotheses, evidence_bundle)
            return AgentExecutionResult(
                status="success", output=decision, logs=[log], stage="judge",
                agent_name=getattr(agent, "name", "judge")
            )
        except Exception as exc:
            return ErrorPolicy.create_fallback_judge_result(finding.id, exc)

    def build_evidence(
        self,
        *,
        finding: RawFinding,
        code_unit: Optional[CodeUnit],
        hypotheses: list[AgentHypothesis],
        agent_logs: list[AgentLog],
        judge_decision: Optional[JudgeDecision],
    ) -> tuple[Optional[EvidenceBundle], list[AgentLog]]:
        try:
            bundle = build_evidence_bundle(
                finding=finding,
                code_unit=code_unit,
                hypotheses=hypotheses,
                agent_logs=agent_logs,
                judge_decision=judge_decision,
            )
            return bundle, []
        except Exception as exc:
            return None, [ErrorPolicy.create_evidence_failure_log(finding.id, exc)]

    def run_analysis_batch(
        self,
        agent: AnalysisAgentBase,
        findings: list[RawFinding],
        code_units: list[CodeUnit],
    ) -> list[AgentExecutionResult]:
        by_path = {unit.path: unit for unit in code_units}
        return [self.run_analysis(agent, finding, by_path.get(finding.file_path)) for finding in findings]

    def run_judge_batch(
        self,
        agent: JudgeAgentBase,
        findings: list[RawFinding],
        hypotheses_by_finding: dict[str, list[AgentHypothesis]],
        evidence_by_finding: dict[str, EvidenceBundle] | None = None,
    ) -> list[AgentExecutionResult]:
        """Judge multiple findings with the same isolation semantics as one finding."""
        evidence_by_finding = evidence_by_finding or {}
        return [
            self.run_judge(
                agent,
                finding,
                list(hypotheses_by_finding.get(finding.id, [])),
                evidence_by_finding.get(finding.id),
            )
            for finding in findings
        ]

    @staticmethod
    def extract_outputs(results: Iterable[AgentExecutionResult]) -> list:
        return [result.output for result in results if result.output is not None]

    @staticmethod
    def collect_logs(results: Iterable[AgentExecutionResult]) -> list[AgentLog]:
        logs: list[AgentLog] = []
        for result in results:
            logs.extend(result.logs)
        return logs
