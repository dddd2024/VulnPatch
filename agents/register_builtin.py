"""
Built-in agent registration entry point (auto-discovery aggregator).

This module automatically discovers and registers agents from subdirectories
under agents/. Each subdirectory that contains a register.py with a
register_agents(registry) function will be automatically loaded.

To add a new agent:
1. Create a subdirectory under agents/ (e.g., agents/my_agent/)
2. Create register.py with a register_agents(registry) function
3. That's it — no need to modify this file

This design eliminates merge conflicts when multiple team members add
agents in parallel — each member only modifies their own subdirectory.

Team Member Assignment: All members can add agents independently
"""

from __future__ import annotations

import importlib
import logging
from pathlib import Path

from agents.registry import AgentRegistry

logger = logging.getLogger(__name__)

# Directory containing this file (agents/)
_AGENTS_DIR = Path(__file__).resolve().parent


def _discover_agent_subdirs() -> list[Path]:
    """
    Discover agent subdirectories under agents/.

    Returns sorted list of subdirectory paths that may contain register.py.
    Skips __pycache__, directories starting with _, and non-directories.
    """
    subdirs: list[Path] = []
    if not _AGENTS_DIR.is_dir():
        return subdirs

    for child in sorted(_AGENTS_DIR.iterdir()):
        if not child.is_dir():
            continue
        # Skip private/cache directories
        if child.name.startswith("_") or child.name == "__pycache__":
            continue
        subdirs.append(child)

    return subdirs


def register_builtin_agents(registry: AgentRegistry) -> None:
    """
    Automatically discover and register all built-in agents.

    Scans each subdirectory under agents/ for a register.py module.
    If the module exports a register_agents(registry) function, it is called.

    Errors in individual agent registrations are logged but do not prevent
    other agents from being registered.

    Args:
        registry: The AgentRegistry instance to populate.
    """
    subdirs = _discover_agent_subdirs()

    for subdir in subdirs:
        register_path = subdir / "register.py"
        if not register_path.exists():
            continue

        # Build module name: agents.<subdir_name>.register
        module_name = f"agents.{subdir.name}.register"

        try:
            module = importlib.import_module(module_name)

            if not hasattr(module, "register_agents"):
                logger.debug(
                    "Skipping %s: no register_agents function found",
                    module_name,
                )
                continue

            module.register_agents(registry)
            logger.debug("Registered agents from %s", module_name)

        except Exception as exc:
            logger.warning(
                "Failed to register agents from %s: %s",
                module_name,
                exc,
            )
            # Continue with other subdirectories
