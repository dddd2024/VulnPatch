"""
Agent Registry for managing and discovering agents.

Provides a central place to register agents and retrieve them
for use in the audit pipeline.  Mirrors the pattern established
by ``audit_core.registry.AnalyzerRegistry`` so that new agents
can be added without modifying ``AuditOrchestrator`` directly.

Usage::

    from agents.registry import AgentRegistry, build_default_agent_registry

    reg = build_default_agent_registry()
    recon = reg.get("recon")          # ReconAgent instance
    analysis = reg.get("analysis")    # AnalysisAgent instance
    judge = reg.get("judge")          # JudgeAgent instance
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from agents.base_agent import BaseAgent

if TYPE_CHECKING:
    from agents.interfaces import (
        ReconAgentBase,
        AnalysisAgentBase,
        JudgeAgentBase,
    )


class AgentRegistry:
    """
    Registry for managing agents.

    Agents are registered by role name (e.g. ``"recon"``,
    ``"analysis"``, ``"judge"``) and can be retrieved by that name.
    """

    def __init__(self) -> None:
        self._agents: dict[str, BaseAgent] = {}

    # ------------------------------------------------------------------
    # Core operations
    # ------------------------------------------------------------------

    def register(self, agent: BaseAgent) -> None:
        """Register an agent instance by its ``name`` attribute."""
        self._agents[agent.name] = agent

    def get(self, name: str) -> Optional[BaseAgent]:
        """Return the agent registered under *name*, or ``None``."""
        return self._agents.get(name)

    def get_all(self) -> list[BaseAgent]:
        """Return a list of all registered agents."""
        return list(self._agents.values())

    def unregister(self, name: str) -> None:
        """Remove the agent registered under *name* (no-op if absent)."""
        self._agents.pop(name, None)

    def clear(self) -> None:
        """Remove all registered agents."""
        self._agents.clear()

    # ------------------------------------------------------------------
    # Convenience helpers for typed access
    # ------------------------------------------------------------------

    def get_recon(self) -> Optional["ReconAgentBase"]:
        """Return the registered recon agent (by role name ``recon``)."""
        agent = self.get("recon")
        # Runtime type check is intentionally loose so callers get
        # whatever is registered, even if it doesn't strictly inherit
        # the typed interface.
        return agent  # type: ignore[return-value]

    def get_analysis(self) -> Optional["AnalysisAgentBase"]:
        """Return the registered analysis agent (by role name ``analysis``)."""
        return self.get("analysis")  # type: ignore[return-value]

    def get_judge(self) -> Optional["JudgeAgentBase"]:
        """Return the registered judge agent (by role name ``judge``)."""
        return self.get("judge")  # type: ignore[return-value]

    def get_verification(self) -> Optional["BaseAgent"]:
        """Return the registered verification agent (by role name ``verification``)."""
        return self.get("verification")


def build_default_agent_registry() -> AgentRegistry:
    """
    Build a registry pre-loaded with all built-in agents.

    Delegates to ``agents/register_builtin.py`` so that the set of
    built-in agents can be extended without touching this file.
    """
    from agents.register_builtin import register_builtin_agents

    registry = AgentRegistry()
    register_builtin_agents(registry)
    return registry
