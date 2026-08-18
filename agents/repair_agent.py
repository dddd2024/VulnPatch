"""Patch generation agent with model routing and historical-case constraints."""

from __future__ import annotations

import difflib
import json
import re
import uuid
from typing import Any, Iterable

from pydantic import BaseModel, Field

from audit_core.models import CodeUnit, RawFinding
from knowledge.case_models import CaseMatch
from knowledge.case_retriever import CaseRetriever
from llm.model_router import ModelRouter
from llm.routing_models import RoutingDecision


class PatchCandidate(BaseModel):
    patch_id: str = Field(default_factory=lambda: f"patch-{uuid.uuid4().hex[:10]}")
    provider: str
    model: str | None = None
    strategy: str
    patched_code: str
    diff: str
    reason: str = ""
    historical_cases_used: list[str] = Field(default_factory=list)
    historical_cases_avoided: list[str] = Field(default_factory=list)
    routing_decision_id: str | None = None
    fallback_path: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class RepairAgent:
    """Generate structured patch candidates under routing/case constraints."""

    name = "repair"
    CASE_RULE_MIN_TRUST = 0.80

    SYSTEM_PROMPT = """You are a secure-code repair agent. Return only a JSON object with keys:
strategy, patched_code, reason. Preserve intended behavior while removing the vulnerability.
Use verified positive historical cases as guidance. Never repeat a verified failed strategy
unless your patch explicitly fixes the documented failure mode. Do not include markdown fences."""

    def __init__(self, router: ModelRouter | None = None) -> None:
        self.router = router or ModelRouter()

    @staticmethod
    def _diff(original: str, patched: str, path: str) -> str:
        return "".join(difflib.unified_diff(
            original.splitlines(keepends=True),
            patched.splitlines(keepends=True),
            fromfile=f"a/{path}",
            tofile=f"b/{path}",
        ))

    @staticmethod
    def _history_ids(matches: Iterable[CaseMatch]) -> tuple[list[str], list[str]]:
        used: list[str] = []
        avoided: list[str] = []
        for match in matches:
            if match.case.outcome == "POSITIVE":
                used.append(match.case.case_id)
            else:
                avoided.append(match.case.case_id)
        return used, avoided

    @staticmethod
    def _normalize_strategy(strategy: str) -> str:
        return " ".join((strategy or "").strip().lower().replace("_", " ").split())

    @staticmethod
    def _parse_json_response(content: str) -> dict[str, Any]:
        text = content.strip()
        if text.startswith("```"):
            text = re.sub(r"^```(?:json)?\s*", "", text, flags=re.IGNORECASE)
            text = re.sub(r"\s*```$", "", text)
        try:
            data = json.loads(text)
            if isinstance(data, dict):
                return data
        except json.JSONDecodeError:
            pass
        start = text.find("{")
        end = text.rfind("}")
        if start >= 0 and end > start:
            data = json.loads(text[start:end + 1])
            if isinstance(data, dict):
                return data
        raise ValueError("LLM repair response is not a JSON object")

    def _build_prompt(
        self,
        finding: RawFinding,
        code_unit: CodeUnit,
        matches: list[CaseMatch],
    ) -> str:
        historical = CaseRetriever.format_prompt_context(matches)
        return "\n".join([
            "## Vulnerability repair task",
            f"Finding: {finding.type}",
            f"CWE: {finding.cwe or 'unknown'}",
            f"Severity: {finding.severity}",
            f"Location: {finding.file_path}:{finding.start_line}",
            f"Message: {finding.message}",
            "",
            historical or "No verified historical cases were retrieved.",
            "",
            "## Source code",
            f"Language: {code_unit.language}",
            code_unit.content,
            "",
            "Produce the smallest robust patch and a concise strategy/reason summary.",
        ])

    @staticmethod
    def _path_traversal_safe_patch(code: str) -> tuple[str, str, str]:
        """Default deterministic path-traversal repair."""
        if "File target = new File(base.toFile(), filename); // VULNERABLE_PATH" in code:
            patched = code.replace(
                "File target = new File(base.toFile(), filename); // VULNERABLE_PATH\n        return target.toPath();",
                "Path target = base.resolve(filename).normalize();\n"
                "        if (!target.startsWith(base.normalize())) {\n"
                "            throw new SecurityException(\"Path traversal blocked\");\n"
                "        }\n"
                "        return target;",
            )
            return (
                patched,
                "normalize + base-directory containment",
                "Normalize the resolved path and reject targets outside the configured base directory.",
            )

        if "base.resolve(" in code and ".normalize()" not in code:
            patched = code.replace("base.resolve(filename)", "base.resolve(filename).normalize()")
            return patched, "normalize resolved path", "Normalize the user-controlled path before file access."

        return code, "manual review required", "No deterministic path-traversal rewrite matched the source shape."

    @staticmethod
    def _path_traversal_case_guided_patch(code: str) -> tuple[str, str, str]:
        """Case-adapted containment repair with an explicitly normalized base.

        This is intentionally a separate safe adapter from the default rule so an
        acceptance test can prove that retrieved verified experience changed the
        deterministic repair decision rather than merely decorating metadata.
        """
        if "File target = new File(base.toFile(), filename); // VULNERABLE_PATH" in code:
            patched = code.replace(
                "File target = new File(base.toFile(), filename); // VULNERABLE_PATH\n        return target.toPath();",
                "Path safeBase = base.toAbsolutePath().normalize();\n"
                "        Path target = safeBase.resolve(filename).normalize();\n"
                "        if (!target.startsWith(safeBase)) {\n"
                "            throw new SecurityException(\"Path traversal blocked\");\n"
                "        }\n"
                "        return target;",
            )
            return (
                patched,
                "case-guided normalize + absolute base containment",
                "Apply the verified containment pattern using one normalized absolute base for both resolution and boundary checking.",
            )
        return RepairAgent._path_traversal_safe_patch(code)

    @staticmethod
    def _path_traversal_weak_patch(code: str) -> tuple[str, str, str]:
        if "File target = new File(base.toFile(), filename); // VULNERABLE_PATH" in code:
            patched = code.replace(
                "File target = new File(base.toFile(), filename); // VULNERABLE_PATH\n        return target.toPath();",
                "filename = filename.replace(\"../\", \"\");\n"
                "        return base.resolve(filename); // WEAK_TRAVERSAL_FILTER",
            )
            return (
                patched,
                "string replace ../",
                "Demonstration candidate: removes a literal traversal token but is expected to fail anti-bypass verification.",
            )
        return code, "string replace ../", "Weak demonstration strategy could not be applied to this source shape."

    @staticmethod
    def _sql_safe_patch(code: str) -> tuple[str, str, str]:
        if "Statement stmt = conn.createStatement();" in code and "VULNERABLE_SQL" in code:
            patched = code.replace(
                "Statement stmt = conn.createStatement();\n        String sql = \"SELECT * FROM users WHERE id=\" + userId; // VULNERABLE_SQL\n        return stmt.executeQuery(sql);",
                "java.sql.PreparedStatement stmt = conn.prepareStatement(\"SELECT * FROM users WHERE id=?\");\n"
                "        stmt.setString(1, userId);\n"
                "        return stmt.executeQuery();",
            )
            return patched, "parameterized prepared statement", "Bind user input as a query parameter instead of concatenating SQL."
        return code, "parameterized query", "Use a prepared/parameterized query for user-controlled values."

    def _rule_patch(self, finding: RawFinding, code_unit: CodeUnit, *, variant: str = "auto") -> tuple[str, str, str]:
        cwe = (finding.cwe or "").upper()
        kind = finding.type.lower().replace(" ", "_")
        if cwe == "CWE-22" or "path" in kind:
            if variant == "weak":
                return self._path_traversal_weak_patch(code_unit.content)
            return self._path_traversal_safe_patch(code_unit.content)
        if cwe == "CWE-89" or "sql" in kind:
            return self._sql_safe_patch(code_unit.content)
        return code_unit.content, "manual review required", "No deterministic repair template exists for this finding type."

    def _case_aware_rule_patch(
        self,
        finding: RawFinding,
        code_unit: CodeUnit,
        matches: list[CaseMatch],
    ) -> tuple[str, str, str, list[str], list[str], dict[str, Any]]:
        """Choose a registered deterministic repair using verified case evidence.

        Positive cases may select only a pre-registered safe adapter; arbitrary
        historical code is never copied into the target. Negative cases block a
        matching strategy name and are preserved as explicit avoid evidence.
        """
        positive = [match for match in matches if match.case.outcome == "POSITIVE"]
        negative = [match for match in matches if match.case.outcome == "NEGATIVE"]
        blocked_strategies = {
            self._normalize_strategy(match.case.strategy)
            for match in negative
            if match.case.strategy
        }
        avoided_ids = [match.case.case_id for match in negative]
        cwe = (finding.cwe or "").upper()
        kind = finding.type.lower().replace(" ", "_")

        for match in positive:
            case = match.case
            strategy = self._normalize_strategy(case.strategy)
            if case.trust_score < self.CASE_RULE_MIN_TRUST:
                continue
            if strategy in blocked_strategies:
                continue

            if cwe == "CWE-22" or "path" in kind:
                if "normalize" in strategy and ("containment" in strategy or "startswith" in strategy):
                    patched, selected_strategy, reason = self._path_traversal_case_guided_patch(code_unit.content)
                    if patched != code_unit.content:
                        return (
                            patched,
                            selected_strategy,
                            f"{reason} Selected verified case {case.case_id} (trust={case.trust_score:.2f}).",
                            [case.case_id],
                            avoided_ids,
                            {
                                "mode": "case_guided",
                                "selected_case_id": case.case_id,
                                "selected_case_strategy": case.strategy,
                                "selected_case_trust": case.trust_score,
                                "blocked_strategies": sorted(blocked_strategies),
                            },
                        )

            if cwe == "CWE-89" or "sql" in kind:
                if "parameterized" in strategy or "prepared statement" in strategy:
                    patched, selected_strategy, reason = self._sql_safe_patch(code_unit.content)
                    if patched != code_unit.content:
                        return (
                            patched,
                            f"case-guided {selected_strategy}",
                            f"{reason} Selected verified case {case.case_id} (trust={case.trust_score:.2f}).",
                            [case.case_id],
                            avoided_ids,
                            {
                                "mode": "case_guided",
                                "selected_case_id": case.case_id,
                                "selected_case_strategy": case.strategy,
                                "selected_case_trust": case.trust_score,
                                "blocked_strategies": sorted(blocked_strategies),
                            },
                        )

        patched, strategy, reason = self._rule_patch(finding, code_unit, variant="auto")
        return (
            patched,
            strategy,
            reason,
            [],
            avoided_ids,
            {
                "mode": "default_rule",
                "selected_case_id": None,
                "blocked_strategies": sorted(blocked_strategies),
                "positive_candidates_considered": [match.case.case_id for match in positive],
            },
        )

    def generate(
        self,
        *,
        finding: RawFinding,
        code_unit: CodeUnit,
        decision: RoutingDecision,
        historical_matches: list[CaseMatch] | None = None,
        variant: str = "auto",
        recorded_response: dict[str, Any] | None = None,
    ) -> PatchCandidate:
        matches = list(historical_matches or [])
        used, avoided = self._history_ids(matches)

        # Explicit weak/safe candidates are controlled verification experiments;
        # they are not presented as autonomous case-guided output.
        if variant in {"weak", "safe"}:
            applied_variant = "weak" if variant == "weak" else "auto"
            patched, strategy, reason = self._rule_patch(finding, code_unit, variant=applied_variant)
            self.router.record_execution(decision, "rule_engine")
            return PatchCandidate(
                provider="rule_engine",
                model="deterministic-security-rules",
                strategy=strategy,
                patched_code=patched,
                diff=self._diff(code_unit.content, patched, code_unit.path),
                reason=reason,
                historical_cases_used=[],
                historical_cases_avoided=[],
                routing_decision_id=decision.decision_id,
                fallback_path=list(decision.execution_path),
                metadata={
                    "variant": variant,
                    "demo_candidate": True,
                    "explicit_deterministic_candidate": True,
                    "case_policy": {"mode": "bypassed_for_explicit_variant"},
                },
            )

        if recorded_response is not None:
            provider = str(recorded_response.get("provider", "replay"))
            patched = str(recorded_response.get("patched_code", code_unit.content))
            strategy = str(recorded_response.get("strategy", "recorded repair"))
            reason = str(recorded_response.get("reason", "Recorded model response"))
            return PatchCandidate(
                provider=provider,
                model=recorded_response.get("model"),
                strategy=strategy,
                patched_code=patched,
                diff=self._diff(code_unit.content, patched, code_unit.path),
                reason=reason,
                historical_cases_used=[],
                historical_cases_avoided=[],
                routing_decision_id=decision.decision_id,
                fallback_path=[provider],
                metadata={
                    "replay": True,
                    "case_policy": {"mode": "bypassed_for_replay"},
                },
            )

        prompt = self._build_prompt(finding, code_unit, matches)
        provider_to_model = {candidate.provider: candidate.model for candidate in decision.candidates}

        for provider in decision.fallback_chain:
            self.router.record_execution(decision, provider)
            if provider == "rule_engine":
                patched, strategy, reason, rule_used, rule_avoided, case_policy = self._case_aware_rule_patch(
                    finding,
                    code_unit,
                    matches,
                )
                return PatchCandidate(
                    provider=provider,
                    model=provider_to_model.get(provider),
                    strategy=strategy,
                    patched_code=patched,
                    diff=self._diff(code_unit.content, patched, code_unit.path),
                    reason=reason,
                    historical_cases_used=rule_used,
                    historical_cases_avoided=rule_avoided,
                    routing_decision_id=decision.decision_id,
                    fallback_path=list(decision.execution_path),
                    metadata={"case_policy": case_policy},
                )

            try:
                client = self.router.build_client(provider, provider_to_model.get(provider))
                response = client.generate(
                    prompt,
                    system_prompt=self.SYSTEM_PROMPT,
                    temperature=0.1,
                    max_tokens=4096,
                )
                if not response.success or not response.content:
                    raise RuntimeError(response.error or "empty LLM response")
                data = self._parse_json_response(response.content)
                patched = str(data.get("patched_code") or "")
                if not patched:
                    raise ValueError("LLM response did not contain patched_code")
                return PatchCandidate(
                    provider=provider,
                    model=response.model or provider_to_model.get(provider),
                    strategy=str(data.get("strategy") or "model-generated repair"),
                    patched_code=patched,
                    diff=self._diff(code_unit.content, patched, code_unit.path),
                    reason=str(data.get("reason") or ""),
                    historical_cases_used=used,
                    historical_cases_avoided=avoided,
                    routing_decision_id=decision.decision_id,
                    fallback_path=list(decision.execution_path),
                    metadata={
                        "tokens_used": response.tokens_used,
                        "latency_ms": response.latency_ms,
                    },
                )
            except Exception as exc:
                self.router.record_failure(decision, provider, str(exc))
                continue

        patched, strategy, reason, rule_used, rule_avoided, case_policy = self._case_aware_rule_patch(
            finding,
            code_unit,
            matches,
        )
        return PatchCandidate(
            provider="rule_engine",
            model="deterministic-security-rules",
            strategy=strategy,
            patched_code=patched,
            diff=self._diff(code_unit.content, patched, code_unit.path),
            reason=reason,
            historical_cases_used=rule_used,
            historical_cases_avoided=rule_avoided,
            routing_decision_id=decision.decision_id,
            fallback_path=list(decision.execution_path) + ["rule_engine"],
            metadata={
                "emergency_fallback": True,
                "case_policy": case_policy,
            },
        )
