"""Turn verification evidence into positive/negative reusable repair cases."""

from __future__ import annotations

from audit_core.models import CodeUnit, RawFinding
from knowledge.case_models import CaseEvent, RepairCase, VerificationResult
from knowledge.case_store import CaseStore


class CaseEvolver:
    """Verification-gated writeback into the repair case library."""

    def __init__(self, store: CaseStore | None = None) -> None:
        self.store = store or CaseStore()

    @staticmethod
    def _trust_score(result: VerificationResult) -> float:
        weights = {
            "compile": 0.15,
            "syntax": 0.15,
            "static_rescan": 0.20,
            "poc": 0.25,
            "regression": 0.20,
            "anti_bypass": 0.20,
        }
        total = 0.0
        earned = 0.0
        for check in result.checks:
            weight = weights.get(check.name, 0.08)
            total += weight
            if check.status == "pass":
                earned += weight
            elif check.status == "skipped":
                earned += weight * 0.35
        if total <= 0:
            return 0.5 if result.passed else 0.35
        normalized = earned / total
        # Negative cases can be highly trustworthy when a bypass was directly
        # demonstrated.  Trust means confidence in the lesson, not "goodness".
        if not result.passed:
            failed_security = any(
                c.status == "fail" and c.name in {"poc", "anti_bypass", "static_rescan"}
                for c in result.checks
            )
            if failed_security:
                normalized = max(normalized, 0.90)
        return round(max(0.0, min(1.0, normalized)), 3)

    @staticmethod
    def _failure_reason(result: VerificationResult) -> str | None:
        failures = [
            f"{check.name}: {check.details or check.input or 'failed'}"
            for check in result.checks
            if check.status == "fail"
        ]
        return "; ".join(failures) if failures else None

    def evolve(
        self,
        *,
        finding: RawFinding,
        code_unit: CodeUnit,
        patch: object,
        verification: VerificationResult,
        scan_id: str | None = None,
        evidence_refs: list[str] | None = None,
        framework: str = "generic",
        metadata: dict | None = None,
    ) -> RepairCase:
        patch_strategy = str(getattr(patch, "strategy", "unknown strategy"))
        patched_code = str(getattr(patch, "patched_code", ""))
        patch_id = str(getattr(patch, "patch_id", ""))
        outcome = "POSITIVE" if verification.passed else "NEGATIVE"
        case = RepairCase(
            cwe=finding.cwe,
            vulnerability_type=finding.type,
            language=code_unit.language,
            framework=framework,
            source_finding_id=finding.id,
            source_scan_id=scan_id,
            outcome=outcome,
            strategy=patch_strategy,
            original_code=code_unit.content,
            patched_code=patched_code,
            verification=verification,
            trust_score=self._trust_score(verification),
            failure_reason=self._failure_reason(verification),
            evidence_refs=list(evidence_refs or []) + ([patch_id] if patch_id else []),
            metadata=metadata or {},
        )
        self.store.add_case(case)
        self.store.add_event(CaseEvent(
            case_id=case.case_id,
            event_type="CASE_CREATED",
            scan_id=scan_id,
            metadata={
                "outcome": case.outcome,
                "trust_score": case.trust_score,
                "verification_id": verification.verification_id,
            },
        ))
        if verification.passed and case.trust_score >= 0.80:
            self.store.add_event(CaseEvent(
                case_id=case.case_id,
                event_type="CASE_PROMOTED",
                scan_id=scan_id,
                metadata={"tier": "HIGH_TRUST", "trust_score": case.trust_score},
            ))
        return case
