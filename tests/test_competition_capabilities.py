from pathlib import Path
from audit_core.models import CodeUnit
from audit_core.registry import build_default_registry
from agents.repair_agent import RepairAgent
from agents.verification_agent import VerificationAgent
from llm.model_router import ModelRouter
from llm.routing_models import RoutingContext
ROOT = Path(__file__).resolve().parent.parent

def _finding_for(path: Path):
    unit = CodeUnit(path=path.name, language="java", content=path.read_text(encoding="utf-8")); findings = []
    for analyzer in build_default_registry().get_analyzers(): findings.extend(analyzer.analyze([unit]))
    assert findings; return unit, findings[0]

def test_router_prefers_rules_for_simple_high_confidence():
    router = ModelRouter(availability_overrides={"rule_engine": True, "ollama": True, "deepseek": True, "openai": True})
    assert router.select(RoutingContext(complexity="low", confidence=0.95, sensitivity="public")).selected_provider == "rule_engine"

def test_router_prefers_semantic_model_for_complex_public_task():
    router = ModelRouter(availability_overrides={"rule_engine": True, "ollama": True, "deepseek": True, "openai": True})
    assert router.select(RoutingContext(complexity="high", confidence=0.60, sensitivity="public")).selected_provider in {"deepseek", "openai"}

def test_confidential_blocks_cloud_candidates():
    router = ModelRouter(availability_overrides={"rule_engine": True, "ollama": True, "deepseek": True, "openai": True})
    decision = router.select(RoutingContext(complexity="high", confidence=0.60, sensitivity="confidential")); by_provider = {c.provider:c for c in decision.candidates}
    assert decision.selected_provider in {"ollama", "rule_engine"}; assert by_provider["deepseek"].allowed is False; assert by_provider["openai"].allowed is False

def test_weak_path_patch_becomes_verification_failure_and_safe_patch_passes():
    import json
    path = ROOT / "demo" / "path_evolution" / "VulnerableDownload.java"; vectors = json.loads((ROOT / "demo" / "path_evolution" / "traversal_vectors.json").read_text(encoding="utf-8")); unit, finding = _finding_for(path)
    router = ModelRouter(availability_overrides={"rule_engine": True}); decision = router.select(RoutingContext(finding_id=finding.id, cwe=finding.cwe, vulnerability_type=finding.type, language="java", complexity="high", confidence=0.95, sensitivity="public")); repair = RepairAgent(router); verifier = VerificationAgent()
    weak = repair.generate(finding=finding, code_unit=unit, decision=decision, variant="weak"); weak_result, _ = verifier.run(finding=finding, code_unit=unit, patch=weak, traversal_vectors=vectors)
    assert weak_result.passed is False; assert any(c.name == "anti_bypass" and c.status == "fail" for c in weak_result.checks)
    safe = repair.generate(finding=finding, code_unit=unit, decision=router.select(decision.context), variant="safe"); safe_result, _ = verifier.run(finding=finding, code_unit=unit, patch=safe, traversal_vectors=vectors)
    assert safe_result.passed is True
