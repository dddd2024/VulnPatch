"""
VulnPatch Knowledge Module.

Provides vulnerability knowledge base, CWE mapping, RAG retrieval,
and vulnerability graph construction for security audit analysis.
"""

from knowledge.expanded_knowledge import (
    EXPANDED_KNOWLEDGE_BASE,
    ExpandedKnowledgeSearcher,
    get_searcher,
    get_knowledge_statistics,
    search_knowledge,
)
from knowledge.cwe_mapper import (
    map_cwe,
    get_cwe_id,
    get_all_cwe_mappings,
    is_known_vulnerability_type,
)
from knowledge.rag_retriever import RagRetriever
from knowledge.vuln_graph import VulnerabilityGraph
from knowledge.case_models import RepairCase, CaseEvent, CaseMatch, VerificationResult, VerificationCheck
from knowledge.case_store import CaseStore
from knowledge.case_retriever import CaseRetriever
from knowledge.case_evolver import CaseEvolver

__all__ = [
    # Expanded knowledge base
    "EXPANDED_KNOWLEDGE_BASE",
    "ExpandedKnowledgeSearcher",
    "get_searcher",
    "get_knowledge_statistics",
    "search_knowledge",
    # CWE mapping
    "map_cwe",
    "get_cwe_id",
    "get_all_cwe_mappings",
    "is_known_vulnerability_type",
    # RAG retrieval
    "RagRetriever",
    # Vulnerability graph
    "VulnerabilityGraph",
    "RepairCase",
    "CaseEvent",
    "CaseMatch",
    "VerificationResult",
    "VerificationCheck",
    "CaseStore",
    "CaseRetriever",
    "CaseEvolver",
]
