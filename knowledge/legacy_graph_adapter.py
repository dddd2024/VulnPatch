"""Compatibility adapter for the repository's vulnerability knowledge graph.

Older integrations import ``LegacyGraphAdapter`` from ``knowledge`` while the
actual implementation now lives in :mod:`graph.vuln_knowledge_graph`.  This
adapter normalizes current AuditResult/RawFinding objects and delegates to that
real graph builder instead of returning an empty placeholder.
"""
from __future__ import annotations

from typing import Any, Iterable

from graph.vuln_knowledge_graph import build_vulnerability_knowledge_graph


class LegacyGraphAdapter:
    """Bridge legacy callers to the maintained vulnerability graph builder."""

    @staticmethod
    def _as_mapping(item: Any) -> dict[str, Any]:
        if isinstance(item, dict):
            return dict(item)
        dumper = getattr(item, "model_dump", None)
        if callable(dumper):
            return dict(dumper(mode="json"))
        return {
            key: getattr(item, key)
            for key in (
                "type", "cwe", "severity", "file_path", "start_line", "risk_score", "metadata"
            )
            if hasattr(item, key)
        }

    @classmethod
    def _normalize(cls, source: Any) -> list[dict[str, Any]]:
        if source is None:
            return []
        if isinstance(source, dict) and "findings" in source:
            source = source["findings"]
        elif hasattr(source, "findings"):
            source = getattr(source, "findings")

        if isinstance(source, (str, bytes)):
            raise TypeError("vulnerability graph input must be findings, not text")
        if isinstance(source, dict) or not isinstance(source, Iterable):
            source = [source]

        normalized: list[dict[str, Any]] = []
        for item in source:
            data = cls._as_mapping(item)
            metadata = data.get("metadata") if isinstance(data.get("metadata"), dict) else {}
            normalized.append(
                {
                    "type": data.get("type") or "Unknown",
                    "cwe": data.get("cwe"),
                    "severity": data.get("severity") or "UNKNOWN",
                    "risk_score": data.get("risk_score") or metadata.get("risk_score") or 0,
                    "file": data.get("file") or data.get("file_path") or "",
                    "line": data.get("line") or data.get("start_line") or 0,
                }
            )
        return normalized

    def build(
        self,
        vulnerabilities: Any = None,
        *,
        ai_mode: str = "rule",
        model_name: str | None = None,
        api_key: str | None = None,
    ) -> dict[str, Any]:
        """Build the real vulnerability knowledge graph for current findings.

        Empty input returns a valid empty graph.  Non-empty input delegates to
        ``build_vulnerability_knowledge_graph`` so nodes, CWE edges, insights,
        reference cases and fix-pattern edges are produced by one maintained
        implementation.
        """
        normalized = self._normalize(vulnerabilities)
        if not normalized:
            return {
                "nodes": [],
                "edges": [],
                "summary": {
                    "vulnerability_count": 0,
                    "node_count": 0,
                    "edge_count": 0,
                    "ai_mode": ai_mode,
                    "model_name": (model_name or "").strip() or None,
                },
            }
        return build_vulnerability_knowledge_graph(
            normalized,
            ai_mode=ai_mode,
            model_name=model_name,
            api_key=api_key,
        )
