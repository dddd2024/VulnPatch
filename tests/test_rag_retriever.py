"""
Tests for RagRetriever.

Verifies:
- Empty query returns []
- SQL injection query retrieves CWE-89
- Path traversal query retrieves CWE-22
- top_k limits result count
- Score sorting from high to low
- JSON serializability
"""

import pytest
import json
from knowledge.rag_retriever import RagRetriever


class TestRagRetrieverBasic:
    """Basic functionality tests."""

    def test_empty_query_returns_empty_list(self):
        """Empty query should return empty list."""
        retriever = RagRetriever()
        results = retriever.retrieve("")
        assert results == []

    def test_none_query_returns_empty_list(self):
        """None query should return empty list."""
        retriever = RagRetriever()
        results = retriever.retrieve(None)
        assert results == []

    def test_top_k_zero_returns_empty_list(self):
        """top_k <= 0 should return empty list."""
        retriever = RagRetriever()
        results = retriever.retrieve("sql injection", top_k=0)
        assert results == []

    def test_top_k_negative_returns_empty_list(self):
        """top_k < 0 should return empty list."""
        retriever = RagRetriever()
        results = retriever.retrieve("sql injection", top_k=-1)
        assert results == []


class TestRagRetrieverSQLInjection:
    """SQL Injection retrieval tests."""

    def test_sql_injection_retrieves_cwe_89(self):
        """SQL injection query should retrieve CWE-89."""
        retriever = RagRetriever()
        results = retriever.retrieve("sql injection")
        
        assert len(results) > 0
        
        # Check that CWE-89 is in results
        cwe_ids = [r["cwe_id"] for r in results]
        assert "CWE-89" in cwe_ids

    def test_sql_query_contains_required_fields(self):
        """Results should contain all required fields."""
        retriever = RagRetriever()
        results = retriever.retrieve("sql injection")
        
        assert len(results) > 0
        
        result = results[0]
        assert "id" in result
        assert "title" in result
        assert "vulnerability_type" in result
        assert "cwe_id" in result
        assert "summary" in result
        assert "remediation" in result
        assert "score" in result
        assert "matched_terms" in result


class TestRagRetrieverPathTraversal:
    """Path Traversal retrieval tests."""

    def test_path_traversal_retrieves_cwe_22(self):
        """Path traversal query should retrieve CWE-22."""
        retriever = RagRetriever()
        results = retriever.retrieve("path traversal")
        
        assert len(results) > 0
        
        # Check that CWE-22 is in results
        cwe_ids = [r["cwe_id"] for r in results]
        assert "CWE-22" in cwe_ids


class TestRagRetrieverTopK:
    """top_k limiting tests."""

    def test_top_k_limits_result_count(self):
        """top_k should limit the number of results."""
        retriever = RagRetriever()
        
        # Get all results (top_k=10)
        all_results = retriever.retrieve("security vulnerability", top_k=10)
        
        # Get limited results (top_k=2)
        limited_results = retriever.retrieve("security vulnerability", top_k=2)
        
        # Limited should have at most 2 results
        assert len(limited_results) <= 2
        assert len(limited_results) <= len(all_results)

    def test_top_k_one_returns_single_result(self):
        """top_k=1 should return at most 1 result."""
        retriever = RagRetriever()
        results = retriever.retrieve("sql injection", top_k=1)
        
        assert len(results) <= 1
        if len(results) == 1:
            assert results[0]["cwe_id"] == "CWE-89"


class TestRagRetrieverSorting:
    """Score sorting tests."""

    def test_results_sorted_by_score_descending(self):
        """Results should be sorted by score from high to low."""
        retriever = RagRetriever()
        results = retriever.retrieve("sql injection cursor execute", top_k=5)
        
        if len(results) >= 2:
            scores = [r["score"] for r in results]
            # Check descending order
            for i in range(len(scores) - 1):
                assert scores[i] >= scores[i + 1]

    def test_higher_score_for_exact_match(self):
        """Exact matches should have higher scores."""
        retriever = RagRetriever()
        
        # Query with exact vulnerability type
        results = retriever.retrieve("SQL Injection")
        
        if results:
            # First result should have high score
            assert results[0]["score"] > 0.5


class TestRagRetrieverJSONSerialization:
    """JSON serialization tests."""

    def test_results_are_json_serializable(self):
        """Results should be JSON serializable."""
        retriever = RagRetriever()
        results = retriever.retrieve("sql injection")
        
        # Should not raise exception
        json_str = json.dumps(results)
        assert isinstance(json_str, str)
        
        # Should be parseable
        parsed = json.loads(json_str)
        assert isinstance(parsed, list)


class TestRagRetrieverOtherVulnerabilities:
    """Other vulnerability type tests."""

    def test_xss_retrieves_cwe_79(self):
        """XSS query should retrieve CWE-79."""
        retriever = RagRetriever()
        results = retriever.retrieve("xss cross site scripting")
        
        assert len(results) > 0
        cwe_ids = [r["cwe_id"] for r in results]
        assert "CWE-79" in cwe_ids

    def test_command_injection_retrieves_cwe_78(self):
        """Command injection query should retrieve CWE-78."""
        retriever = RagRetriever()
        results = retriever.retrieve("command injection os.system")
        
        assert len(results) > 0
        cwe_ids = [r["cwe_id"] for r in results]
        assert "CWE-78" in cwe_ids

    def test_ssrf_retrieves_cwe_918(self):
        """SSRF query should retrieve CWE-918."""
        retriever = RagRetriever()
        results = retriever.retrieve("ssrf server side request forgery")
        
        assert len(results) > 0
        cwe_ids = [r["cwe_id"] for r in results]
        assert "CWE-918" in cwe_ids


class TestRagRetrieverHelperMethods:
    """Helper method tests."""

    def test_get_knowledge_by_cwe_returns_correct_item(self):
        """get_knowledge_by_cwe should return correct item."""
        retriever = RagRetriever()
        item = retriever.get_knowledge_by_cwe("CWE-89")
        
        assert item is not None
        assert item["cwe_id"] == "CWE-89"
        assert "SQL Injection" in item["title"]

    def test_get_knowledge_by_cwe_unknown_returns_none(self):
        """get_knowledge_by_cwe for unknown CWE should return None."""
        retriever = RagRetriever()
        item = retriever.get_knowledge_by_cwe("CWE-99999")
        
        assert item is None

    def test_get_all_knowledge_returns_all_items(self):
        """get_all_knowledge should return all knowledge items."""
        retriever = RagRetriever()
        all_knowledge = retriever.get_all_knowledge()
        
        assert len(all_knowledge) == 8  # We have 8 vulnerability types
        
        # Check that all items have required fields
        for item in all_knowledge:
            assert "id" in item
            assert "title" in item
            assert "cwe_id" in item