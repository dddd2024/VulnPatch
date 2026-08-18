"""Reusable repair workflow shared by product APIs and reproducible fixtures."""
from __future__ import annotations

import uuid
from typing import Any, Callable

from audit_core.models import CodeUnit, RawFinding
from agents.repair_agent import RepairAgent
from agents.verification_agent import VerificationAgent
from knowledge.case_evolver import CaseEvolver
from knowledge.case_retriever import CaseRetriever
from knowledge.case_store import CaseStore
from llm.model_router import ModelRouter
from llm.routing_models import RoutingContext, RoutingDecision
from llm.routing_store import RoutingDecisionStore


class RepairPipeline:
    """Execute routing -> case retrieval -> repair -> verification -> evolution."""

    def __init__(
        self,
        *,
        store: CaseStore | None = None,
        router: ModelRouter | None = None,
        repair_agent: RepairAgent | None = None,
        verifier: VerificationAgent | None = None,
    ) -> None:
        self.store = store or CaseStore()
        self.router = router or ModelRouter()
        self.retriever = CaseRetriever(self.store)
        self.evolver = CaseEvolver(self.store)
        self.repair_agent = repair_agent or RepairAgent(self.router)
        self.verifier = verifier or VerificationAgent()
        self.routing_store = RoutingDecisionStore()

    @staticmethod
    def _record_case_reuse_results(
        store: CaseStore,
        matches: list[Any],
        patch: Any,
        *,
        verification_passed: bool,
        scan_id: str,
        new_case_id: str,
    ) -> None:
        retrieved_ids = {match.case.case_id for match in matches}
        roles: dict[str, str] = {}
        for case_id in list(getattr(patch, "historical_cases_used", []) or []):
            roles[case_id] = "used"
        for case_id in list(getattr(patch, "historical_cases_avoided", []) or []):
            roles.setdefault(case_id, "avoided")
        for case_id, role in roles.items():
            if case_id not in retrieved_ids:
                continue
            store.mark_reuse_result(
                case_id,
                success=verification_passed,
                scan_id=scan_id,
                metadata={
                    "patch_id": getattr(patch, "patch_id", None),
                    "new_case_id": new_case_id,
                    "reuse_role": role,
                },
            )

    def run(
        self,
        *,
        finding: RawFinding,
        code_unit: CodeUnit,
        context: RoutingContext,
        scan_id: str | None = None,
        variant: str = "auto",
        recorded_response: dict[str, Any] | None = None,
        traversal_vectors: dict[str, list[str]] | None = None,
        framework: str = "generic",
        case_metadata: dict[str, Any] | None = None,
        top_k: int = 6,
        simulate_selected_provider_failure: bool = False,
        failure_reason: str = "SIMULATED_PROVIDER_FAILURE",
    ) -> dict[str, Any]:
        run_id = scan_id or f"repair-{uuid.uuid4().hex[:10]}"
        decision = self.router.select(context)
        self.routing_store.save(decision, scan_id=run_id)
        if simulate_selected_provider_failure and decision.selected_provider != "rule_engine":
            failed = decision.selected_provider
            self.router.record_failure(decision, failed, failure_reason)
            decision.metadata["simulated_failure"] = True
            decision.metadata["simulated_failed_provider"] = failed
            decision.fallback_chain = [p for p in decision.fallback_chain if p != failed] or ["rule_engine"]

        matches = self.retriever.retrieve(
            finding,
            language=code_unit.language,
            code=code_unit.content,
            top_k=top_k,
            scan_id=run_id,
            record_events=True,
        )
        patch = self.repair_agent.generate(
            finding=finding,
            code_unit=code_unit,
            decision=decision,
            historical_matches=matches,
            variant=variant,
            recorded_response=recorded_response,
        )
        verification, verification_log = self.verifier.run(
            finding=finding,
            code_unit=code_unit,
            patch=patch,
            traversal_vectors=traversal_vectors,
        )
        evolved_metadata = dict(case_metadata or {})
        evolved_metadata.setdefault("routing_decision_id", decision.decision_id)
        case = self.evolver.evolve(
            finding=finding,
            code_unit=code_unit,
            patch=patch,
            verification=verification,
            scan_id=run_id,
            evidence_refs=[decision.decision_id, verification.verification_id],
            framework=framework,
            metadata=evolved_metadata,
        )
        self._record_case_reuse_results(
            self.store,
            matches,
            patch,
            verification_passed=verification.passed,
            scan_id=run_id,
            new_case_id=case.case_id,
        )
        self.routing_store.save(decision, scan_id=run_id)
        return {
            "run_id": run_id,
            "routing_decision": decision,
            "historical_matches": matches,
            "patch": patch,
            "verification": verification,
            "verification_log": verification_log,
            "evolved_case": case,
        }
