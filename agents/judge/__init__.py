"""
JudgeAgent registration module.

This module provides a self-contained registration function for JudgeAgent.
Team members can add new agents in their own subdirectories without
modifying the central register_builtin.py.

Team Member Assignment: Member 3 (Agent & Knowledge)
"""

from __future__ import annotations

from agents.registry import AgentRegistry
from agents.judge_agent import JudgeAgent


def register_agents(registry: AgentRegistry) -> None:
    """
    Register JudgeAgent into the given registry.

    Args:
        registry: The AgentRegistry instance to populate.
    """
    registry.register(JudgeAgent())