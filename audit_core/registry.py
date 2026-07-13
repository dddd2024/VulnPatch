"""
Analyzer registry for managing and discovering analyzers.

The registry provides a central place to register analyzers
and retrieve them for use in the audit pipeline.

Concrete analyzers are no longer imported here.  Instead,
``build_default_registry()`` delegates to
``analyzers/register_builtin.py``, which calls each language
sub-module's ``register_analyzers()`` function.  This eliminates
the need for the Analyzer team to modify ``audit_core/registry.py``
when adding new analyzers.
"""

from typing import Optional
from analyzers.base import BaseAnalyzer


class AnalyzerRegistry:
    """
    Registry for managing analyzers.

    Analyzers can be registered and retrieved by name or language support.
    """

    def __init__(self):
        self._analyzers: dict[str, BaseAnalyzer] = {}

    def register(self, analyzer: BaseAnalyzer) -> None:
        """
        Register an analyzer.

        Args:
            analyzer: The analyzer instance to register
        """
        self._analyzers[analyzer.name] = analyzer

    def get(self, name: str) -> Optional[BaseAnalyzer]:
        """
        Get an analyzer by name.

        Args:
            name: The name of the analyzer

        Returns:
            The analyzer instance or None if not found
        """
        return self._analyzers.get(name)

    def get_analyzers(self) -> list[BaseAnalyzer]:
        """
        Get all registered analyzers.

        Returns:
            List of all registered analyzer instances
        """
        return list(self._analyzers.values())

    def get_analyzers_for_language(self, language: str) -> list[BaseAnalyzer]:
        """
        Get analyzers that support a specific language.

        Args:
            language: The programming language to check

        Returns:
            List of analyzers supporting the language
        """
        return [
            analyzer for analyzer in self._analyzers.values()
            if language.lower() in [lang.lower() for lang in analyzer.supported_languages]
        ]

    def unregister(self, name: str) -> None:
        """
        Unregister an analyzer.

        Args:
            name: The name of the analyzer to unregister
        """
        if name in self._analyzers:
            del self._analyzers[name]

    def clear(self) -> None:
        """Clear all registered analyzers."""
        self._analyzers.clear()


def build_default_registry() -> AnalyzerRegistry:
    """
    Build a registry with all built-in analyzers.

    Delegates to ``analyzers/register_builtin.py``, which in turn
    calls each language sub-module's ``register_analyzers()`` function.
    The external interface is unchanged — callers still receive a
    fully-populated ``AnalyzerRegistry``.

    To add a new built-in analyzer, modify only the corresponding
    language ``register.py`` (e.g. ``analyzers/python/register.py``).
    No changes to this file are required.

    Returns:
        Registry with all built-in analyzers registered.
    """
    from analyzers.register_builtin import register_builtin_analyzers

    registry = AnalyzerRegistry()
    register_builtin_analyzers(registry)
    return registry
