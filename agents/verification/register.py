"""
VerificationAgent registration module.

This module provides a self-contained registration function for VerificationAgent.
Team members can add new agents in their own subdirectories without
modifying the central register_builtin.py.
"""

from __future__ import annotations

from agents.registry import AgentRegistry
from agents.verification_agent import VerificationAgent


def register_agents(registry: AgentRegistry) -> None:
    """
    Register VerificationAgent into the given registry.

    Args:
        registry: The AgentRegistry instance to populate.
    """
    registry.register(VerificationAgent())
