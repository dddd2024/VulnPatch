from types import SimpleNamespace

from api.schemas import CompetitionDemoRequest
from audit_core.models import CodeUnit
from audit_core.registry import build_default_registry
from knowledge.case_models import CaseMatch, RepairCase
from llm.model_router import ModelRouter
from llm.routing_models import RoutingContext


def _finding_for(path):
    unit = CodeUnit(path=path.name, language="java", content=path.read_text(encoding="utf-8"))
    findings = []
    for analyzer in build_default_registry().get_analyzers():
        findings.extend(analyzer.analyze([unit]))
    assert findings
    return unit, findings[0]


def test_router_enforces_required_capabilities():
    router = ModelRouter(
        availability_overrides={
            "rule_engine": True,
            "ollama": True,
            "deepseek": True,
            "openai": True,
        }
    )
    decision = router.select(
        RoutingContext(
            complexity="high",
            confidence=0.60,
            sensitivity="public",
            required_capabilities=["cross_file"],
        )
    )
    by_provider = {candidate.provider: candidate for candidate in decision.candidates}

    assert decision.selected_provider in {"deepseek", "openai"}
    assert by_provider["rule_engine"].score == 0.0
    assert by_provider["ollama"].score == 0.0
    assert "MISSING_REQUIRED_CAPABILITIES:cross_file" in by_provider["rule_engine"].reasons
    assert "MISSING_REQUIRED_CAPABILITIES:cross_file" in by_provider["ollama"].reasons
    assert not any(
        reason.startswith("MISSING_REQUIRED_CAPABILITIES:")
        for reason in by_provider[decision.selected_provider].reasons
    )


def test_router_reports_unmet_capabilities_on_emergency_fallback():
    router = ModelRouter(
        availability_overrides={
            "rule_engine": True,
            "ollama": False,
            "deepseek": False,
            "openai": False,
        }
    )
    decision = router.select(
        RoutingContext(
            complexity="high",
            confidence=0.60,
            sensitivity="confidential",
            required_capabilities=["capability_that_does_not_exist"],
        )
    )
    selected = next(candidate for candidate in decision.candidates if candidate.provider == decision.selected_provider)

    assert decision.selected_provider == "rule_engine"
    assert "EMERGENCY_LOCAL_FALLBACK" in selected.reasons
    assert "MISSING_REQUIRED_CAPABILITIES:capability_that_does_not_exist" in selected.reasons
    assert "REQUIRED_CAPABILITIES_UNMET_FALLBACK" in decision.reason_codes
    assert decision.metadata["selected_missing_capabilities"] == ["capability_that_does_not_exist"]


def test_path_scenario_separates_provider_and_verification_capabilities():
    import api.competition_demo as demo_api

    unit = demo_api._load_scenario("path_evolution")
    finding = demo_api._find_primary_finding(unit)
    context = demo_api._routing_context(
        CompetitionDemoRequest(
            scenario="path_evolution",
            sensitivity="public",
            mode="live",
            repair_variant="auto",
        ),
        finding,
        unit,
    )

    assert context.required_capabilities == ["patch_generation"]
    assert context.metadata["verification_requirements"] == ["anti_bypass"]


def test_path_scenario_rule_engine_satisfies_patch_generation_requirement():
    import api.competition_demo as demo_api

    unit = demo_api._load_scenario("path_evolution")
    finding = demo_api._find_primary_finding(unit)
    context = demo_api._routing_context(
        CompetitionDemoRequest(
            scenario="path_evolution",
            sensitivity="confidential",
            mode="live",
            repair_variant="auto",
        ),
        finding,
        unit,
    )
    router = ModelRouter(
        availability_overrides={
            "rule_engine": True,
            "ollama": False,
            "deepseek": False,
            "openai": False,
        }
    )
    decision = router.select(context)
    selected = next(candidate for candidate in decision.candidates if candidate.provider == decision.selected_provider)

    assert decision.selected_provider == "rule_engine"
    assert not any(reason.startswith("MISSING_REQUIRED_CAPABILITIES:") for reason in selected.reasons)
    assert "REQUIRED_CAPABILITIES_UNMET_FALLBACK" not in decision.reason_codes
    assert decision.metadata["selected_missing_capabilities"] == []


def test_case_reuse_metrics_only_for_cases_patch_consumed(monkeypatch):
    import api.competition_demo as demo_api

    positive = RepairCase(
        case_id="CASE-REUSE-POS",
        cwe="CWE-22",
        vulnerability_type="Path Traversal",
        language="java",
        outcome="POSITIVE",
        strategy="normalize + containment",
        trust_score=0.99,
    )
    negative = RepairCase(
        case_id="CASE-REUSE-NEG",
        cwe="CWE-22",
        vulnerability_type="Path Traversal",
        language="java",
        outcome="NEGATIVE",
        strategy="string replace ../",
        trust_score=0.98,
    )
    unselected = RepairCase(
        case_id="CASE-REUSE-UNSELECTED",
        cwe="CWE-22",
        vulnerability_type="Path Traversal",
        language="java",
        outcome="POSITIVE",
        strategy="another positive strategy",
        trust_score=0.90,
    )
    matches = [
        CaseMatch(case=positive, similarity=0.99, reasons=["SAME_CWE"]),
        CaseMatch(case=negative, similarity=0.98, reasons=["SAME_CWE"]),
        CaseMatch(case=unselected, similarity=0.90, reasons=["SAME_CWE"]),
    ]
    patch = SimpleNamespace(
        patch_id="patch-reuse-test",
        historical_cases_used=[positive.case_id],
        historical_cases_avoided=[negative.case_id],
    )
    calls = []

    def record(case_id, *, success, scan_id=None, metadata=None):
        calls.append((case_id, success, scan_id, metadata or {}))

    monkeypatch.setattr(demo_api._store, "mark_reuse_result", record)
    demo_api._record_case_reuse_results(
        matches,
        patch,
        verification_passed=True,
        scan_id="scan-reuse-test",
        new_case_id="CASE-NEW",
    )

    assert {call[0] for call in calls} == {positive.case_id, negative.case_id}
    assert unselected.case_id not in {call[0] for call in calls}
    roles = {call[0]: call[3]["reuse_role"] for call in calls}
    assert roles == {positive.case_id: "used", negative.case_id: "avoided"}

    calls.clear()
    bypass_patch = SimpleNamespace(
        patch_id="patch-bypass-test",
        historical_cases_used=[],
        historical_cases_avoided=[],
    )
    demo_api._record_case_reuse_results(
        matches,
        bypass_patch,
        verification_passed=False,
        scan_id="scan-bypass-test",
        new_case_id="CASE-NEW-BYPASS",
    )
    assert calls == []


def test_replay_metadata_matches_sql_scenario():
    import api.competition_demo as demo_api

    path = demo_api.SCENARIOS["simple_sql"]
    unit, finding = _finding_for(path)
    replay = demo_api._recorded_response(unit, finding)

    strategy = replay["strategy"].lower()
    assert "parameterized" in strategy or "prepared" in strategy
    assert "containment" not in strategy
    assert "PreparedStatement" in replay["patched_code"]
    assert replay["reason"].startswith("Scenario-matched replay candidate.")
