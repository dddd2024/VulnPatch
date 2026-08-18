"""Auto-registration hook for RepairAgent."""
from agents.registry import AgentRegistry
from agents.repair_agent import RepairAgent


def register_agents(registry: AgentRegistry) -> None:
    registry.register(RepairAgent())  # type: ignore[arg-type]
