"""Compatibility search facade for the built-in vulnerability knowledge base.

The original package exported this module but the file was absent.  Keep one
canonical dataset by adapting ``RagRetriever`` instead of duplicating content.
"""
from __future__ import annotations

from typing import Any
from knowledge.rag_retriever import RagRetriever, VULNERABILITY_KNOWLEDGE_BASE

EXPANDED_KNOWLEDGE_BASE = VULNERABILITY_KNOWLEDGE_BASE


class ExpandedKnowledgeSearcher:
    def __init__(self) -> None:
        self._retriever = RagRetriever()

    def search(self, query: str, top_k: int = 5) -> list[dict[str, Any]]:
        return self._retriever.retrieve(query, top_k=top_k)


_SEARCHER = ExpandedKnowledgeSearcher()


def get_searcher() -> ExpandedKnowledgeSearcher:
    return _SEARCHER


def search_knowledge(query: str, top_k: int = 5) -> list[dict[str, Any]]:
    return _SEARCHER.search(query, top_k=top_k)


def get_knowledge_statistics() -> dict[str, Any]:
    cwes = sorted({item.get("cwe_id") for item in EXPANDED_KNOWLEDGE_BASE if item.get("cwe_id")})
    return {"total": len(EXPANDED_KNOWLEDGE_BASE), "cwe_count": len(cwes), "cwes": cwes}
