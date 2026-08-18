from pathlib import Path

from audit_core.models import CodeUnit
from audit_core.registry import build_default_registry
from agents.repair_agent import RepairAgent
from agents.verification_agent import VerificationAgent
from knowledge.case_models import CaseMatch, RepairCase
from llm.model_router import ModelRouter
from llm.routing_models import RoutingContext

ROOT = Path(__file__).resolve().parent.parent


def _finding_for(path: Path):
    unit = CodeUnit(path=path.name, language="java", content=path.read_text(encoding="utf-8"))
    findings = []
    for analyzer in build_default_registry().get_analyzers():
        findings.extend(analyzer.analyze([unit]))
    assert findings
    return unit, findings[0]


def _rule_decision(router: ModelRouter, finding, *, complexity: str = "high"):
    return router.select(RoutingContext(
        finding_id=finding.id,
        cwe=finding.cwe,
        vulnerability_type=finding.type,
        language="java",
        complexity=complexity,
        confidence=0.95,
        sensitivity="public",
    ))


def test_router_prefers_rules_for_simple_high_confidence():
    router = ModelRouter(availability_overrides={"rule_engine": True, "ollama": True, "deepseek": True, "openai": True})
    assert router.select(RoutingContext(complexity="low", confidence=0.95, sensitivity="public")).selected_provider == "rule_engine"


def test_router_prefers_semantic_model_for_complex_public_task():
    router = ModelRouter(availability_overrides={"rule_engine": True, "ollama": True, "deepseek": True, "openai": True})
    assert router.select(RoutingContext(complexity="high", confidence=0.60, sensitivity="public")).selected_provider in {"deepseek", "openai"}


def test_confidential_blocks_cloud_candidates():
    router = ModelRouter(availability_overrides={"rule_engine": True, "ollama": True, "deepseek": True, "openai": True})
    decision = router.select(RoutingContext(complexity="high", confidence=0.60, sensitivity="confidential"))
    by_provider = {candidate.provider: candidate for candidate in decision.candidates}
    assert decision.selected_provider in {"ollama", "rule_engine"}
    assert by_provider["deepseek"].allowed is False
    assert by_provider["openai"].allowed is False


def test_ollama_enabled_false_is_authoritative(monkeypatch):
    monkeypatch.setenv("OLLAMA_ENABLED", "false")
    monkeypatch.setenv("OLLAMA_BASE_URL", "http://localhost:11434/v1")
    monkeypatch.setenv("LLM_PROVIDER", "ollama")
    router = ModelRouter()
    ollama = next(profile for profile in router.profiles() if profile.provider == "ollama")
    assert router._provider_available(ollama) is False
    assert router.health("ollama") == "unavailable"

    decision = router.select(RoutingContext(complexity="high", confidence=0.60, sensitivity="confidential"))
    candidate = next(item for item in decision.candidates if item.provider == "ollama")
    assert candidate.available is False
    assert candidate.health == "unavailable"
    assert "NOT_CONFIGURED" in candidate.reasons
    assert "HEALTH_UNAVAILABLE" in candidate.reasons


def test_weak_path_patch_becomes_verification_failure_and_safe_patch_passes():
    import json

    path = ROOT / "demo" / "path_evolution" / "VulnerableDownload.java"
    vectors = json.loads((ROOT / "demo" / "path_evolution" / "traversal_vectors.json").read_text(encoding="utf-8"))
    unit, finding = _finding_for(path)
    router = ModelRouter(availability_overrides={"rule_engine": True})
    decision = _rule_decision(router, finding)
    repair = RepairAgent(router)
    verifier = VerificationAgent()

    weak = repair.generate(finding=finding, code_unit=unit, decision=decision, variant="weak")
    weak_result, _ = verifier.run(finding=finding, code_unit=unit, patch=weak, traversal_vectors=vectors)
    assert weak_result.passed is False
    assert any(check.name == "anti_bypass" and check.status == "fail" for check in weak_result.checks)

    safe = repair.generate(finding=finding, code_unit=unit, decision=_rule_decision(router, finding), variant="safe")
    safe_result, _ = verifier.run(finding=finding, code_unit=unit, patch=safe, traversal_vectors=vectors)
    assert safe_result.passed is True


def test_verified_cases_change_rule_engine_repair_decision():
    import json

    path = ROOT / "demo" / "path_evolution" / "SimilarDownload.java"
    vectors = json.loads((ROOT / "demo" / "path_evolution" / "traversal_vectors.json").read_text(encoding="utf-8"))
    unit, finding = _finding_for(path)
    router = ModelRouter(availability_overrides={"rule_engine": True, "ollama": False, "deepseek": False, "openai": False})
    repair = RepairAgent(router)
    verifier = VerificationAgent()

    baseline = repair.generate(
        finding=finding,
        code_unit=unit,
        decision=_rule_decision(router, finding),
        historical_matches=[],
    )
    baseline_result, _ = verifier.run(finding=finding, code_unit=unit, patch=baseline, traversal_vectors=vectors)
    assert baseline_result.passed is True
    assert baseline.metadata["case_policy"]["mode"] == "default_rule"

    positive = RepairCase(
        case_id="CASE-TEST-CWE22-POS",
        cwe="CWE-22",
        vulnerability_type="Path Traversal",
        language="java",
        outcome="POSITIVE",
        strategy="normalize + base-directory containment",
        trust_score=0.99,
        patched_code="verified containment patch",
    )
    negative = RepairCase(
        case_id="CASE-TEST-CWE22-NEG",
        cwe="CWE-22",
        vulnerability_type="Path Traversal",
        language="java",
        outcome="NEGATIVE",
        strategy="string replace ../",
        trust_score=0.98,
        failure_reason="Nested traversal bypasses literal replacement.",
    )
    matches = [
        CaseMatch(case=positive, similarity=0.99, reasons=["SAME_CWE"]),
        CaseMatch(case=negative, similarity=0.98, reasons=["SAME_CWE"]),
    ]

    guided = repair.generate(
        finding=finding,
        code_unit=unit,
        decision=_rule_decision(router, finding),
        historical_matches=matches,
    )
    guided_result, _ = verifier.run(finding=finding, code_unit=unit, patch=guided, traversal_vectors=vectors)

    assert guided_result.passed is True
    assert guided.patched_code != baseline.patched_code
    assert guided.strategy != baseline.strategy
    assert "safeBase" in guided.patched_code
    assert guided.historical_cases_used == [positive.case_id]
    assert negative.case_id in guided.historical_cases_avoided
    assert guided.metadata["case_policy"]["mode"] == "case_guided"
    assert guided.metadata["case_policy"]["selected_case_id"] == positive.case_id
    assert "string replace ../" in guided.metadata["case_policy"]["blocked_strategies"]
    assert "string replace" not in guided.strategy.lower()
