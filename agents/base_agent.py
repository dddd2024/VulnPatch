"""
Base agent interface for all LLM agents.

Agents perform reasoning and analysis tasks using LLMs.
They do NOT directly read files or scan repositories - they only process
structured objects: CodeUnit, RawFinding, EvidenceBundle.

For strongly-typed Agent interfaces, use agents.interfaces:
    - ReconAgentBase: For reconnaissance agents
    - AnalysisAgentBase: For analysis agents
    - JudgeAgentBase: For judge agents

Example:
    # Generic agent (flexible but less type-safe)
    from agents.base_agent import BaseAgent

    class MyAgent(BaseAgent):
        name = "my_agent"
        def run(self, *args, **kwargs):
            ...

    # Strongly-typed agent (recommended for specific roles)
    from agents.interfaces import AnalysisAgentBase
    from audit_core.models import RawFinding, AgentHypothesis, AgentLog

    class MyAnalysisAgent(AnalysisAgentBase):
        name = "my_analysis"
        def run(
            self,
            finding: RawFinding,
            code_unit: CodeUnit | None = None
        ) -> tuple[AgentHypothesis, AgentLog]:
            ...
"""

from abc import ABC, abstractmethod


class BaseAgent(ABC):
    """
    Abstract base class for all agents.

    Agents use LLMs to perform reasoning tasks on structured data.
    They do NOT:
    - Read files directly
    - Scan repositories directly

    They ONLY process:
    - CodeUnit objects
    - RawFinding objects
    - EvidenceBundle objects

    Attributes:
        name: Unique name of the agent

    Note:
        For specific Agent roles (Recon, Analysis, Judge), prefer inheriting
        from the strongly-typed interfaces in agents.interfaces instead of
        this base class. This provides better type safety and clearer contracts.

        See:
        - agents.interfaces.ReconAgentBase
        - agents.interfaces.AnalysisAgentBase
        - agents.interfaces.JudgeAgentBase
    """

    name: str = "base"

    @abstractmethod
    def run(self, *args, **kwargs):
        """
        Execute the agent's main task.

        This is a generic signature for flexibility. Concrete implementations
        should provide strongly-typed signatures. For specific Agent roles,
        override with explicit parameter types.

        Args:
            *args: Variable positional arguments
            **kwargs: Variable keyword arguments

        Returns:
            Agent-specific output

        Example:
            # Generic (BaseAgent)
            def run(self, *args, **kwargs):
                code_units = args[0]
                ...

            # Strongly-typed (ReconAgentBase)
            def run(
                self,
                code_units: list[CodeUnit]
            ) -> tuple[list[AgentHypothesis], list[AgentLog]]:
                ...
        """
        pass
