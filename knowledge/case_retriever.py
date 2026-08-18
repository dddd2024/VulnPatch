"""Evidence-aware retrieval over verified positive and negative repair cases."""

from __future__ import annotations

import re
from typing import Iterable

from audit_core.models import RawFinding
from knowledge.case_models import CaseMatch, RepairCase
from knowledge.case_store import CaseStore


_TOKEN_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{2,}")


class CaseRetriever:
    """Retrieve similar historical repair cases without external services.

    Similarity intentionally combines high-signal structured fields (CWE,
    language, vulnerability type) with light lexical overlap.  This keeps the
    competition/demo path deterministic and offline-capable while preserving a
    replaceable boundary for vector search later.
    """

    def __init__(self, store: CaseStore | None = None) -> None:
        self.store = store or CaseStore()

    @staticmethod
    def _tokens(text: str) -> set[str]:
        return {token.lower() for token in _TOKEN_RE.findall(text or "")}

    def _score(
        self,
        case: RepairCase,
        *,
        finding: RawFinding,
        language: str,
        code: str,
    ) -> tuple[float, list[str]]:
        score = 0.0
        reasons: list[str] = []

        if finding.cwe and case.cwe and finding.cwe.lower() == case.cwe.lower():
            score += 0.52
            reasons.append("SAME_CWE")
        elif finding.type and case.vulnerability_type and finding.type.lower() in case.vulnerability_type.lower():
            score += 0.34
            reasons.append("SAME_VULNERABILITY_TYPE")

        if language and case.language.lower() == language.lower():
            score += 0.20
            reasons.append("SAME_LANGUAGE")

        query_tokens = self._tokens(" ".join([finding.type, finding.message, code]))
        case_tokens = self._tokens(" ".join([
            case.vulnerability_type,
            case.strategy,
            case.original_code,
            case.patched_code,
            case.failure_reason or "",
        ]))
        if query_tokens and case_tokens:
            overlap = len(query_tokens & case_tokens) / max(1, len(query_tokens | case_tokens))
            lexical = min(0.20, overlap * 0.60)
            if lexical > 0.02:
                score += lexical
                reasons.append("LEXICAL_OVERLAP")

        # Verified/high-trust cases rank slightly higher, but negative cases
        # remain first-class retrieval results because they constrain repair.
        score += min(0.08, case.trust_score * 0.08)
        reasons.append("VERIFIED_TRUST")

        return min(1.0, score), reasons

    def retrieve(
        self,
        finding: RawFinding,
        *,
        language: str = "unknown",
        code: str = "",
        top_k: int = 6,
        scan_id: str | None = None,
        min_similarity: float = 0.25,
        record_events: bool = True,
    ) -> list[CaseMatch]:
        # Narrow by CWE first when possible, then fall back to the complete
        # library if the specific CWE has no historical experience.
        candidates = self.store.list_cases(cwe=finding.cwe, limit=300) if finding.cwe else []
        if not candidates:
            candidates = self.store.list_cases(limit=300)

        matches: list[CaseMatch] = []
        for case in candidates:
            similarity, reasons = self._score(case, finding=finding, language=language, code=code)
            if similarity < min_similarity:
                continue
            matches.append(CaseMatch(case=case, similarity=round(similarity, 4), reasons=reasons))

        matches.sort(key=lambda item: (item.similarity, item.case.trust_score), reverse=True)
        selected = matches[: max(1, top_k)]
        if record_events:
            for match in selected:
                self.store.mark_retrieved(
                    match.case.case_id,
                    scan_id=scan_id,
                    similarity=match.similarity,
                    metadata={"outcome": match.case.outcome},
                )
        return selected

    @staticmethod
    def split(matches: Iterable[CaseMatch]) -> tuple[list[CaseMatch], list[CaseMatch]]:
        positive: list[CaseMatch] = []
        negative: list[CaseMatch] = []
        for match in matches:
            (positive if match.case.outcome == "POSITIVE" else negative).append(match)
        return positive, negative

    @staticmethod
    def format_prompt_context(matches: Iterable[CaseMatch]) -> str:
        positive, negative = CaseRetriever.split(matches)
        parts: list[str] = []
        if positive:
            parts.append("## VERIFIED SUCCESSFUL HISTORICAL CASES")
            for match in positive[:3]:
                case = match.case
                parts.extend([
                    f"- {case.case_id} | similarity={match.similarity:.2f} | trust={case.trust_score:.2f}",
                    f"  Strategy: {case.strategy}",
                    "  Treat this as positive guidance, not code to copy blindly.",
                ])
        if negative:
            parts.append("## VERIFIED FAILED HISTORICAL STRATEGIES")
            for match in negative[:3]:
                case = match.case
                parts.extend([
                    f"- {case.case_id} | similarity={match.similarity:.2f} | trust={case.trust_score:.2f}",
                    f"  Failed strategy: {case.strategy}",
                    f"  Failure reason: {case.failure_reason or 'verification failed'}",
                    "  Do NOT repeat this strategy unless you explicitly address its failure mode.",
                ])
        return "\n".join(parts)
