"""Primary audit orchestration boundary.

The orchestrator owns ingestion, language-aware analyzer dispatch, resilient
agent execution, evidence construction, CVE-candidate assessment and result
summarization. Provider selection remains abstract through ``LLMClientFactory``.
"""
from __future__ import annotations

from typing import Any, Optional

from agents.recon_agent import ReconAgent
from agents.analysis_agent import AnalysisAgent
from agents.judge_agent import JudgeAgent
from audit_core.agent_runtime import AgentRuntime
from audit_core.models import (
    CodeUnit, RawFinding, AgentHypothesis, AgentLog, AuditSummary, AuditResult,
)
from audit_core.registry import AnalyzerRegistry, build_default_registry
from audit_core.result_merger import merge_findings
from audit_core.scoring import score_finding
from ingest.repo_loader import RepoLoader
from llm import LLMClientFactory


class AuditOrchestrator:
    """Coordinate the formal, product-facing security audit workflow."""

    def __init__(
        self,
        *,
        registry: AnalyzerRegistry | None = None,
        llm_client: Any | None = None,
        llm_config: dict[str, Any] | None = None,
        use_pipeline: bool = True,
    ) -> None:
        self.registry = registry or build_default_registry()
        self.repo_loader = RepoLoader()
        self.runtime = AgentRuntime()
        self.use_pipeline = use_pipeline

        client = llm_client
        if client is None and llm_config:
            try:
                config = dict(llm_config)
                provider = config.pop("provider")
                client = LLMClientFactory.create(provider, **config)
            except Exception:
                client = None
        self._llm_client = client
        self.recon_agent = ReconAgent(llm_client=client)
        self.analysis_agent = AnalysisAgent(llm_client=client)
        self.judge_agent = JudgeAgent(llm_client=client)

    def get_llm_client(self):
        return self._llm_client

    def set_llm_client(self, client) -> None:
        self._llm_client = client
        for agent in (self.recon_agent, self.analysis_agent, self.judge_agent):
            setter = getattr(agent, "set_llm_client", None)
            if setter:
                setter(client)

    def scan(
        self,
        *,
        input_type: str,
        code: str | None = None,
        repo_path: str | None = None,
        repo_url: str | None = None,
        language: str | None = None,
        branch: str | None = None,
    ) -> AuditResult:
        kind = input_type.lower()
        if kind == "code":
            return self.scan_code(code or "", language=language)
        if kind == "path":
            if not repo_path:
                raise ValueError("repo_path is required for path input")
            return self._scan_units(self.repo_loader.load_local_repo(repo_path))
        if kind == "github":
            if not repo_url:
                raise ValueError("repo_url is required for github input")
            return self.scan_github(repo_url, branch=branch)
        raise ValueError(f"Unsupported input_type: {input_type}")

    def scan_code(self, code: str, language: str | None = None) -> AuditResult:
        units = self.repo_loader.load_code_snippet(code, language)
        return self._scan_units(units)

    def scan_github(self, repo_url: str, branch: str | None = None) -> AuditResult:
        units = self.repo_loader.load_github_repo(repo_url, branch)
        return self._scan_units(units)

    @staticmethod
    def _group_code_units_by_language(code_units: list[CodeUnit]) -> dict[str, list[CodeUnit]]:
        grouped: dict[str, list[CodeUnit]] = {}
        for unit in code_units:
            language = (unit.language or "unknown").lower()
            grouped.setdefault(language, []).append(unit)
        return grouped

    def _run_analyzers(self, code_units: list[CodeUnit]) -> tuple[list[RawFinding], dict[str, Any]]:
        findings: list[RawFinding] = []
        metadata: dict[str, Any] = {
            "analyzer_runs": [], "analyzer_errors": [], "skipped_languages": []
        }
        for language, units in self._group_code_units_by_language(code_units).items():
            analyzers = self.registry.get_analyzers_for_language(language)
            if not analyzers:
                metadata["skipped_languages"].append({
                    "language": language, "code_unit_count": len(units), "reason": "no_analyzer"
                })
                continue
            for analyzer in analyzers:
                try:
                    produced = analyzer.analyze(units)
                    findings.extend(produced)
                    metadata["analyzer_runs"].append({
                        "analyzer_name": analyzer.name,
                        "language": language,
                        "code_unit_count": len(units),
                        "finding_count": len(produced),
                        "success": True,
                    })
                except Exception as exc:
                    metadata["analyzer_errors"].append({
                        "analyzer_name": analyzer.name,
                        "language": language,
                        "error_type": type(exc).__name__,
                        "error_message": str(exc),
                    })
        return findings, metadata

    @staticmethod
    def _find_code_unit(finding: RawFinding, code_units: list[CodeUnit]) -> Optional[CodeUnit]:
        for unit in code_units:
            if unit.path == finding.file_path:
                return unit
        return None

    @staticmethod
    def _stage(success: bool = True, **metrics: Any) -> dict[str, Any]:
        return {"success": success, "error": None if success else metrics.pop("error", None), "metrics": metrics}

    @staticmethod
    def _evaluate_cve_candidates(
        findings: list[RawFinding],
        code_units: list[CodeUnit],
    ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        """Evaluate CVE candidacy without making the primary scan fail.

        CVE review is an enrichment stage.  Its failure is surfaced in pipeline
        metadata, but analyzer/repair workflows remain available.
        """
        if not findings:
            return [], {"success": True, "error": None, "metrics": {"candidate_count": 0}}
        try:
            from cve_candidate.evaluator import CveCandidateEvaluator

            evaluator = CveCandidateEvaluator()
            results = evaluator.evaluate_batch(findings, code_units=code_units)
            payloads = [result.model_dump(mode="json") for result in results]
            candidates = sum(1 for result in payloads if result.get("cve_candidate"))
            return payloads, {
                "success": True,
                "error": None,
                "metrics": {"assessment_count": len(payloads), "candidate_count": candidates},
            }
        except Exception as exc:
            return [], {
                "success": False,
                "error": f"{type(exc).__name__}: {exc}",
                "metrics": {"assessment_count": 0, "candidate_count": 0},
            }

    def _scan_units(self, code_units: list[CodeUnit]) -> AuditResult:
        stage_results: dict[str, dict[str, Any]] = {}
        all_logs: list[AgentLog] = []

        recon_result = self.runtime.run_recon(self.recon_agent, code_units)
        recon_hypotheses: list[AgentHypothesis] = recon_result.output or []
        all_logs.extend(recon_result.logs)
        stage_results["recon"] = self._stage(True, hypothesis_count=len(recon_hypotheses), degraded=recon_result.fallback_used)

        raw_findings, analyzer_info = self._run_analyzers(code_units)
        stage_results["analyzer"] = self._stage(True, finding_count=len(raw_findings), error_count=len(analyzer_info["analyzer_errors"]))

        findings = merge_findings(raw_findings)
        stage_results["merge"] = self._stage(True, finding_count=len(findings))

        analysis_by_finding: dict[str, AgentHypothesis] = {}
        relevant_recon_by_finding: dict[str, list[AgentHypothesis]] = {}
        for finding in findings:
            unit = self._find_code_unit(finding, code_units)
            relevant_recon = [
                h for h in recon_hypotheses
                if unit is not None and unit.id in (h.supporting_evidence_ids or [])
            ]
            relevant_recon_by_finding[finding.id] = relevant_recon
            result = self.runtime.run_analysis(self.analysis_agent, finding, unit)
            all_logs.extend(result.logs)
            if result.output is not None:
                analysis_by_finding[finding.id] = result.output
        stage_results["analysis"] = self._stage(True, hypothesis_count=len(analysis_by_finding))

        decisions = {}
        per_finding_logs: dict[str, list[AgentLog]] = {}
        for finding in findings:
            hypotheses = list(relevant_recon_by_finding.get(finding.id, []))
            analysis_hypothesis = analysis_by_finding.get(finding.id)
            if analysis_hypothesis:
                hypotheses.append(analysis_hypothesis)
            jr = self.runtime.run_judge(self.judge_agent, finding, hypotheses, None)
            all_logs.extend(jr.logs)
            per_finding_logs[finding.id] = list(jr.logs)
            if jr.output is not None:
                decisions[finding.id] = jr.output
        stage_results["judge"] = self._stage(True, decision_count=len(decisions))

        evidence = []
        for finding in findings:
            unit = self._find_code_unit(finding, code_units)
            hypotheses = list(relevant_recon_by_finding.get(finding.id, []))
            analysis_hypothesis = analysis_by_finding.get(finding.id)
            if analysis_hypothesis:
                hypotheses.append(analysis_hypothesis)
            bundle, extra_logs = self.runtime.build_evidence(
                finding=finding,
                code_unit=unit,
                hypotheses=hypotheses,
                agent_logs=per_finding_logs.get(finding.id, []),
                judge_decision=decisions.get(finding.id),
            )
            all_logs.extend(extra_logs)
            if bundle is not None:
                score = score_finding(finding, decisions.get(finding.id))
                bundle.score_breakdown = score
                if finding.cwe:
                    bundle.cwe_info = {"cwe_id": finding.cwe}
                evidence.append(bundle)
        stage_results["evidence"] = self._stage(True, evidence_count=len(evidence))

        cve_candidates, cve_stage = self._evaluate_cve_candidates(findings, code_units)
        stage_results["cve_candidate"] = cve_stage

        risks = [score_finding(f, decisions.get(f.id))["risk_score"] for f in findings]
        summary = AuditSummary(
            total_code_units=len(code_units),
            total_findings=len(findings),
            total_evidence_bundles=len(evidence),
            risk_score=round(sum(risks) / len(risks), 1) if risks else 0.0,
            languages=sorted({(u.language or "unknown").lower() for u in code_units}),
            scanned_files=[u.path for u in code_units][:50],
        )
        stage_results["summary"] = self._stage(True, total_findings=len(findings))

        metadata: dict[str, Any] = {"analyzer_info": analyzer_info}
        if self.use_pipeline:
            metadata["stage_results"] = stage_results
        return AuditResult(
            summary=summary,
            findings=findings,
            evidence=evidence,
            agent_logs=all_logs,
            metadata=metadata,
            cve_candidates=cve_candidates,
        )
