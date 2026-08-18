"""Backend validation API for autonomous routing and repair-case evolution.

This router does not fabricate UI data. Every response is derived from the same
objects used by the repair pipeline: RoutingDecision, CaseMatch,
PatchCandidate, VerificationResult and RepairCase.
"""
from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException, Query

from api.schemas import CompetitionDemoRequest, CompetitionDemoResponse
from audit_core.models import CodeUnit, RawFinding
from audit_core.repair_pipeline import RepairPipeline
from audit_core.registry import build_default_registry
from knowledge.case_models import RepairCase
from knowledge.case_store import CaseStore
from llm.model_router import ModelRouter
from llm.routing_models import RoutingContext
from llm.routing_store import RoutingDecisionStore

router = APIRouter(tags=["competition-demo"])
ROOT = Path(__file__).resolve().parent.parent
DEMO_ROOT = ROOT / "demo"

_store = CaseStore()
_model_router = ModelRouter()
_pipeline = RepairPipeline(store=_store, router=_model_router)
_repair = _pipeline.repair_agent
_routing_store = RoutingDecisionStore()
_recent_runs: list[dict[str, Any]] = []

SCENARIOS = {
    "simple_sql": DEMO_ROOT / "simple_sql" / "SimpleSql.java",
    "path_evolution": DEMO_ROOT / "path_evolution" / "VulnerableDownload.java",
    "similar_path": DEMO_ROOT / "path_evolution" / "SimilarDownload.java",
}


def _ensure_seed_cases() -> None:
    seed_path = DEMO_ROOT / "seed_cases.json"
    if not seed_path.exists():
        return
    for raw in json.loads(seed_path.read_text(encoding="utf-8")):
        if _store.get_case(raw["case_id"]) is None:
            _store.add_case(RepairCase(**raw))


def _case_stats() -> dict[str, int]:
    cases = _store.list_cases(limit=1000)
    positive = sum(case.outcome == "POSITIVE" for case in cases)
    negative = sum(case.outcome == "NEGATIVE" for case in cases)
    demo = sum(bool(case.metadata.get("demo")) for case in cases)
    high_trust = sum(case.trust_score >= 0.80 for case in cases)
    return {
        "total": len(cases),
        "positive": positive,
        "negative": negative,
        "high_trust": high_trust,
        "demo_created": demo,
    }


def _load_scenario(name: str) -> CodeUnit:
    path = SCENARIOS.get(name)
    if path is None or not path.exists():
        raise HTTPException(status_code=404, detail=f"Demo scenario not found: {name}")
    return CodeUnit(path=path.name, language="java", content=path.read_text(encoding="utf-8"))


def _find_primary_finding(unit: CodeUnit) -> RawFinding:
    findings: list[RawFinding] = []
    for analyzer in build_default_registry().get_analyzers():
        try:
            findings.extend(analyzer.analyze([unit]))
        except Exception:
            continue
    if not findings:
        raise HTTPException(status_code=422, detail="Scenario did not produce a vulnerability finding")
    priorities = {"CWE-22": 0, "CWE-89": 1}
    findings.sort(key=lambda f: (priorities.get((f.cwe or "").upper(), 99), f.start_line))
    return findings[0]


def _confidence(value: str) -> float:
    return {"high": 0.95, "medium": 0.65, "low": 0.35}.get((value or "").lower(), 0.5)


def _routing_context(request: CompetitionDemoRequest, finding: RawFinding, unit: CodeUnit) -> RoutingContext:
    if request.scenario == "simple_sql":
        complexity = "low"
        capabilities = ["deterministic_fix"]
        verification_requirements = ["sql_parameterization", "anti_bypass"]
    else:
        complexity = "high"
        # anti_bypass is a deterministic VerificationAgent requirement, not a
        # model-provider capability. Providers must be able to generate a patch;
        # the verifier independently establishes bypass resistance afterwards.
        capabilities = ["patch_generation"]
        verification_requirements = ["anti_bypass"]
    return RoutingContext(
        finding_id=finding.id,
        cwe=finding.cwe,
        vulnerability_type=finding.type,
        language=unit.language,
        complexity=complexity,
        confidence=_confidence(finding.confidence),
        sensitivity=request.sensitivity,
        file_count=1,
        cross_file=False,
        required_capabilities=capabilities,
        metadata={
            "scenario": request.scenario,
            "competition_demo": True,
            "verification_requirements": verification_requirements,
        },
    )


def _load_traversal_vectors() -> dict[str, list[str]]:
    path = DEMO_ROOT / "path_evolution" / "traversal_vectors.json"
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}


def _recorded_response(unit: CodeUnit, finding: RawFinding) -> dict[str, Any]:
    path = DEMO_ROOT / "recorded_responses" / "safe_path_patch.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    # The checked-in recording supplies transport identity (provider/model),
    # while the scenario-specific candidate is reconstructed from the current
    # fixture. Always replace strategy/reason/code so replay cannot mislabel a
    # SQL case with path-containment metadata from the recording file.
    patched, strategy, reason = _repair._rule_patch(finding, unit, variant="auto")
    data["patched_code"] = patched
    data["strategy"] = strategy
    data["reason"] = f"Scenario-matched replay candidate. {reason}"
    return data


def _record_case_reuse_results(
    matches: list[Any],
    patch: Any,
    *,
    verification_passed: bool,
    scan_id: str,
    new_case_id: str,
) -> None:
    """Compatibility helper delegating to the shared repair pipeline policy."""
    RepairPipeline._record_case_reuse_results(
        _store, matches, patch,
        verification_passed=verification_passed,
        scan_id=scan_id,
        new_case_id=new_case_id,
    )


def _event_dicts(limit: int = 50) -> list[dict[str, Any]]:
    return [event.model_dump(mode="json") for event in _store.list_events(limit=limit)]


def run_demo_pipeline(request: CompetitionDemoRequest) -> dict[str, Any]:
    """Execute a reproducible fixture through the shared product repair pipeline."""
    _ensure_seed_cases()
    run_id = f"demo-{uuid.uuid4().hex[:10]}"
    unit = _load_scenario(request.scenario)
    finding = _find_primary_finding(unit)

    replay = _recorded_response(unit, finding) if request.mode == "replay" else None
    execution = _pipeline.run(
        finding=finding,
        code_unit=unit,
        context=_routing_context(request, finding, unit),
        scan_id=run_id,
        variant=request.repair_variant,
        recorded_response=replay,
        traversal_vectors=_load_traversal_vectors(),
        framework="JDBC" if (finding.cwe or "").upper() == "CWE-89" else "generic",
        case_metadata={
            "demo": True,
            "scenario": request.scenario,
            "mode": request.mode,
            "repair_variant": request.repair_variant,
        },
        simulate_selected_provider_failure=request.simulate_provider_failure,
        failure_reason="SIMULATED_COMPETITION_FAILURE",
    )

    decision = execution["routing_decision"]
    case = execution["evolved_case"]

    result = {
        "run_id": run_id,
        "scenario": request.scenario,
        "mode": request.mode,
        "finding": finding.model_dump(mode="json"),
        "routing_decision": decision.model_dump(mode="json"),
        "historical_matches": [m.model_dump(mode="json") for m in execution["historical_matches"]],
        "patch": execution["patch"].model_dump(mode="json"),
        "verification": execution["verification"].model_dump(mode="json"),
        "verification_log": execution["verification_log"].model_dump(mode="json"),
        "evolved_case": case.model_dump(mode="json"),
        "case_stats": _case_stats(),
        "events": _event_dicts(),
    }
    _recent_runs.insert(0, result)
    del _recent_runs[25:]
    return result


@router.post("/demo/run", response_model=CompetitionDemoResponse)
def run_demo(request: CompetitionDemoRequest) -> CompetitionDemoResponse:
    result = run_demo_pipeline(request)
    return CompetitionDemoResponse(**result)


@router.post("/demo/reset")
def reset_demo() -> dict[str, Any]:
    global _model_router, _pipeline, _repair
    removed = _store.reset_demo_cases()
    _recent_runs.clear()
    _model_router = ModelRouter()
    _pipeline = RepairPipeline(store=_store, router=_model_router)
    _repair = _pipeline.repair_agent
    _ensure_seed_cases()
    return {"status": "ok", "removed_demo_cases": removed, "case_stats": _case_stats()}


@router.get("/demo/state")
def demo_state() -> dict[str, Any]:
    _ensure_seed_cases()
    return {
        "case_stats": _case_stats(),
        "latest_run": _recent_runs[0] if _recent_runs else None,
        "events": _event_dicts(),
    }


@router.get("/routing/decisions")
def routing_decisions(limit: int = Query(20, ge=1, le=100)) -> list[dict[str, Any]]:
    return [decision.model_dump(mode="json") for decision in _routing_store.list(limit=limit)]


@router.get("/models/health")
def model_health() -> list[dict[str, Any]]:
    result = []
    for profile in _model_router.profiles():
        result.append({
            **profile.model_dump(mode="json"),
            "available": _model_router._provider_available(profile),
            "health": _model_router.health(profile.provider),
        })
    return result


@router.get("/cases")
def cases(
    cwe: str | None = None,
    outcome: str | None = None,
    limit: int = Query(200, ge=1, le=1000),
) -> list[dict[str, Any]]:
    _ensure_seed_cases()
    return [case.model_dump(mode="json") for case in _store.list_cases(cwe=cwe, outcome=outcome, limit=limit)]


@router.get("/cases/events")
def case_events(limit: int = Query(200, ge=1, le=1000)) -> list[dict[str, Any]]:
    _ensure_seed_cases()
    return _event_dicts(limit)


@router.get("/cases/retrievals")
def case_retrievals(limit: int = Query(200, ge=1, le=1000)) -> list[dict[str, Any]]:
    _ensure_seed_cases()
    return [
        event.model_dump(mode="json")
        for event in _store.list_events(event_type="CASE_RETRIEVED", limit=limit)
    ]
