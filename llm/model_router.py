"""Autonomous model selection for VulnPatch.

``MultiLLMClient`` is the transport abstraction; ``ModelRouter`` is the
policy/decision layer above it.  It scores model candidates using task
complexity, privacy, health, cost and latency and emits a ``RoutingDecision``
that can be persisted as evidence.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml

from llm.multi_llm_client import MultiLLMClient, PROVIDER_DEFAULTS
from llm.routing_models import (
    ModelProfile,
    RoutingCandidate,
    RoutingContext,
    RoutingDecision,
)


_DEFAULT_CONFIG = Path(__file__).resolve().parent.parent / "config" / "model_routing.yaml"
_TRUE_VALUES = {"1", "true", "yes", "on"}
_FALSE_VALUES = {"0", "false", "no", "off"}


class ModelRouter:
    """Policy-driven, health-aware autonomous model router."""

    def __init__(
        self,
        config_path: str | Path | None = None,
        *,
        availability_overrides: dict[str, bool] | None = None,
        health_overrides: dict[str, str] | None = None,
    ) -> None:
        self.config_path = Path(config_path or os.getenv("MODEL_ROUTING_CONFIG") or _DEFAULT_CONFIG)
        self._config = self._load_config()
        self._availability_overrides = availability_overrides or {}
        self._health: dict[str, str] = health_overrides.copy() if health_overrides else {}
        self._decisions: list[RoutingDecision] = []

    def _load_config(self) -> dict[str, Any]:
        if self.config_path.exists():
            with self.config_path.open("r", encoding="utf-8") as fh:
                return yaml.safe_load(fh) or {}
        return {"weights": {}, "providers": {}, "privacy": {}}

    @property
    def decisions(self) -> list[RoutingDecision]:
        return list(self._decisions)

    def profiles(self) -> list[ModelProfile]:
        profiles: list[ModelProfile] = []
        for provider, raw in (self._config.get("providers") or {}).items():
            raw = raw or {}
            profiles.append(ModelProfile(
                provider=provider,
                model=raw.get("model"),
                local=bool(raw.get("local", False)),
                enabled=bool(raw.get("enabled", True)),
                capability=float(raw.get("capability", 0.5)),
                cost=float(raw.get("cost", 0.5)),
                latency=float(raw.get("latency", 0.5)),
                capabilities=list(raw.get("capabilities") or []),
            ))
        return profiles

    @staticmethod
    def _explicit_bool(name: str) -> bool | None:
        raw = os.getenv(name)
        if raw is None or not raw.strip():
            return None
        normalized = raw.strip().lower()
        if normalized in _TRUE_VALUES:
            return True
        if normalized in _FALSE_VALUES:
            return False
        return None

    def _provider_available(self, profile: ModelProfile) -> bool:
        if profile.provider in self._availability_overrides:
            return self._availability_overrides[profile.provider]
        if not profile.enabled:
            return False
        if profile.provider == "rule_engine":
            return True
        if profile.provider == "ollama":
            # An explicit OLLAMA_ENABLED value is authoritative. In particular,
            # `false` must not be overridden merely because the example/default
            # base URL is non-empty.
            explicit = self._explicit_bool("OLLAMA_ENABLED")
            if explicit is not None:
                return explicit
            return bool(
                os.getenv("OLLAMA_BASE_URL")
                or os.getenv("LLM_PROVIDER", "").lower() == "ollama"
            )
        meta = PROVIDER_DEFAULTS.get(profile.provider, {})
        key_env = meta.get("key_env")
        return bool(
            os.getenv(f"{profile.provider.upper()}_API_KEY")
            or (key_env and os.getenv(key_env))
            or (
                os.getenv("LLM_PROVIDER", "").lower() == profile.provider
                and os.getenv("LLM_API_KEY")
            )
        )

    def health(self, provider: str) -> str:
        if provider in self._health:
            return self._health[provider]
        profile = next((item for item in self.profiles() if item.provider == provider), None)
        if profile is not None and not self._provider_available(profile):
            return "unavailable"
        return "healthy"

    def set_health(self, provider: str, state: str) -> None:
        if state not in {"healthy", "degraded", "unavailable"}:
            raise ValueError(f"Unsupported model health state: {state}")
        self._health[provider] = state

    @staticmethod
    def _complexity_target(context: RoutingContext) -> float:
        target = {"low": 0.35, "medium": 0.65, "high": 0.90}[context.complexity]
        if context.cross_file:
            target = min(1.0, target + 0.08)
        return target

    @staticmethod
    def _missing_required_capabilities(profile: ModelProfile, context: RoutingContext) -> list[str]:
        required = {
            capability.strip()
            for capability in context.required_capabilities
            if capability and capability.strip()
        }
        provided = {capability.strip() for capability in profile.capabilities if capability and capability.strip()}
        return sorted(required - provided)

    def _score(self, profile: ModelProfile, context: RoutingContext, health: str) -> float:
        weights = {
            "capability": 0.45,
            "privacy": 0.20,
            "health": 0.15,
            "cost": 0.10,
            "latency": 0.10,
            **(self._config.get("weights") or {}),
        }

        target = self._complexity_target(context)
        capability_fit = max(0.0, 1.0 - abs(profile.capability - target))
        if profile.capability >= target:
            capability_fit = min(1.0, capability_fit + 0.12)

        if context.complexity == "low" and context.confidence >= 0.85 and profile.provider == "rule_engine":
            capability_fit = 1.0

        privacy_fit = 1.0 if profile.local else (0.0 if context.sensitivity == "confidential" else 0.9)
        health_fit = {"healthy": 1.0, "degraded": 0.35, "unavailable": 0.0}.get(health, 0.0)
        cost_fit = 1.0 - profile.cost
        latency_fit = 1.0 - profile.latency

        score = (
            float(weights["capability"]) * capability_fit
            + float(weights["privacy"]) * privacy_fit
            + float(weights["health"]) * health_fit
            + float(weights["cost"]) * cost_fit
            + float(weights["latency"]) * latency_fit
        )

        if context.complexity == "low" and context.confidence >= 0.85:
            if profile.provider == "rule_engine":
                score += 0.28
            elif not profile.local:
                score -= 0.18

        if context.cross_file and "cross_file" in profile.capabilities:
            score += 0.08
        if context.cross_file and profile.provider == "rule_engine":
            score -= 0.20

        return max(0.0, min(1.0, score))

    def select(self, context: RoutingContext) -> RoutingDecision:
        candidates: list[RoutingCandidate] = []
        candidate_profiles: dict[str, ModelProfile] = {}
        privacy_cfg = (self._config.get("privacy") or {}).get(context.sensitivity, {}) or {}
        cloud_allowed = bool(privacy_cfg.get("cloud_allowed", context.sensitivity != "confidential"))

        for profile in self.profiles():
            candidate_profiles[profile.provider] = profile
            available = self._provider_available(profile)
            state = self.health(profile.provider)
            allowed = profile.local or cloud_allowed
            missing_capabilities = self._missing_required_capabilities(profile, context)
            requirements_met = not missing_capabilities
            reasons: list[str] = []
            if not available:
                reasons.append("NOT_CONFIGURED")
            if not allowed:
                reasons.append("PRIVACY_POLICY_BLOCKED")
            if missing_capabilities:
                reasons.append(f"MISSING_REQUIRED_CAPABILITIES:{','.join(missing_capabilities)}")
            if state == "degraded":
                reasons.append("HEALTH_DEGRADED")
            if state == "unavailable":
                reasons.append("HEALTH_UNAVAILABLE")

            score = (
                self._score(profile, context, state)
                if available and allowed and requirements_met and state != "unavailable"
                else 0.0
            )
            candidates.append(RoutingCandidate(
                provider=profile.provider,
                model=profile.model,
                local=profile.local,
                available=available,
                allowed=allowed,
                health=state,  # type: ignore[arg-type]
                score=round(score, 4),
                reasons=reasons,
            ))

        viable = [
            candidate
            for candidate in candidates
            if (
                candidate.available
                and candidate.allowed
                and candidate.health != "unavailable"
                and not any(reason.startswith("MISSING_REQUIRED_CAPABILITIES:") for reason in candidate.reasons)
            )
        ]
        selected_missing_capabilities: list[str] = []
        if not viable:
            fallback = next(
                (
                    candidate
                    for candidate in candidates
                    if candidate.provider == "rule_engine"
                    and candidate.available
                    and candidate.allowed
                    and candidate.health != "unavailable"
                ),
                None,
            )
            if fallback is None:
                fallback_profile = candidate_profiles.get("rule_engine")
                fallback = RoutingCandidate(
                    provider="rule_engine",
                    model=(fallback_profile.model if fallback_profile else "deterministic-security-rules"),
                    local=True,
                    available=True,
                    allowed=True,
                    health="healthy",
                    score=0.5,
                    reasons=["EMERGENCY_LOCAL_FALLBACK"],
                )
                candidates.append(fallback)
            elif "EMERGENCY_LOCAL_FALLBACK" not in fallback.reasons:
                fallback.reasons.append("EMERGENCY_LOCAL_FALLBACK")
                fallback.score = max(fallback.score, 0.5)

            fallback_profile = candidate_profiles.get("rule_engine")
            if fallback_profile is not None:
                selected_missing_capabilities = self._missing_required_capabilities(fallback_profile, context)
            else:
                selected_missing_capabilities = sorted(
                    {
                        capability.strip()
                        for capability in context.required_capabilities
                        if capability and capability.strip()
                    }
                )
            if selected_missing_capabilities:
                missing_reason = f"MISSING_REQUIRED_CAPABILITIES:{','.join(selected_missing_capabilities)}"
                if missing_reason not in fallback.reasons:
                    fallback.reasons.append(missing_reason)
            viable = [fallback]

        viable.sort(key=lambda item: item.score, reverse=True)
        selected = viable[0]
        fallback_chain = [item.provider for item in viable]

        reason_codes: list[str] = [
            f"COMPLEXITY_{context.complexity.upper()}",
            f"SENSITIVITY_{context.sensitivity.upper()}",
        ]
        if context.cross_file:
            reason_codes.append("CROSS_FILE_REASONING")
        if context.confidence >= 0.85:
            reason_codes.append("HIGH_STATIC_CONFIDENCE")
        if selected.local:
            reason_codes.append("LOCAL_EXECUTION")
        else:
            reason_codes.append("CLOUD_ALLOWED")
        if context.sensitivity == "confidential":
            reason_codes.append("CLOUD_BLOCKED_BY_PRIVACY")
        if selected_missing_capabilities:
            reason_codes.append("REQUIRED_CAPABILITIES_UNMET_FALLBACK")

        decision = RoutingDecision(
            context=context,
            selected_provider=selected.provider,
            selected_model=selected.model,
            candidates=sorted(candidates, key=lambda item: item.score, reverse=True),
            reason_codes=reason_codes,
            fallback_chain=fallback_chain,
            execution_path=[],
            metadata={
                "required_capabilities": sorted(
                    {
                        capability.strip()
                        for capability in context.required_capabilities
                        if capability and capability.strip()
                    }
                ),
                "selected_missing_capabilities": selected_missing_capabilities,
            },
        )
        self._decisions.append(decision)
        return decision

    def build_client(self, provider: str, model: str | None = None) -> MultiLLMClient:
        if provider == "rule_engine":
            raise ValueError("rule_engine is deterministic and does not use MultiLLMClient")
        kwargs: dict[str, Any] = {"provider": provider}
        if model:
            kwargs["model"] = model
        if provider == "ollama" and os.getenv("OLLAMA_BASE_URL"):
            kwargs["base_url"] = os.getenv("OLLAMA_BASE_URL")
        return MultiLLMClient(**kwargs)

    def record_execution(self, decision: RoutingDecision, provider: str) -> None:
        if provider not in decision.execution_path:
            decision.execution_path.append(provider)

    def record_failure(self, decision: RoutingDecision, provider: str, error: str | None = None) -> None:
        self.set_health(provider, "degraded")
        self.record_execution(decision, provider)
        decision.metadata.setdefault("failures", []).append({"provider": provider, "error": error or "unknown"})
