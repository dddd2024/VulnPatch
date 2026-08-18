"""Generic agent facade over the product audit orchestrator.

This module remains for integrations that expect an agent-shaped orchestration
entry point.  The actual workflow ownership lives in ``audit_core.orchestrator``
so API, tests and agent callers share one implementation.
"""
from __future__ import annotations

from typing import Any

from agents.base_agent import BaseAgent
from audit_core.orchestrator import AuditOrchestrator


class OrchestratorAgent(BaseAgent):
    """Delegate generic orchestration requests to :class:`AuditOrchestrator`."""

    name = "orchestrator"

    def __init__(self, orchestrator: AuditOrchestrator | None = None) -> None:
        self.orchestrator = orchestrator or AuditOrchestrator()

    def run(self, *args: Any, **kwargs: Any):
        """Run the formal audit workflow.

        Preferred usage is keyword based and mirrors ``AuditOrchestrator.scan``::

            agent.run(input_type="code", code="...", language="python")

        For compatibility, one positional string is treated as a code snippet.
        """
        if args:
            if len(args) != 1 or kwargs.get("input_type") not in (None, "code"):
                raise TypeError("OrchestratorAgent accepts at most one positional code snippet")
            kwargs = dict(kwargs)
            kwargs.setdefault("input_type", "code")
            kwargs.setdefault("code", args[0])
        kwargs.setdefault("input_type", "code")
        return self.orchestrator.scan(**kwargs)
