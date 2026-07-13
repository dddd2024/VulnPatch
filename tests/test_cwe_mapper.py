"""
Tests for CWE Mapper.

Verifies:
- sql_injection maps to CWE-89
- Path Traversal maps to CWE-22
- unknown_type returns CWE-UNKNOWN
- Case-insensitive matching
- snake_case support
"""

import pytest
from knowledge.cwe_mapper import map_cwe, get_cwe_id, is_known_vulnerability_type, get_all_cwe_mappings


class TestCWEMapperBasic:
    """Basic mapping tests."""

    def test_sql_injection_maps_to_cwe_89(self):
        """sql_injection should map to CWE-89."""
        result = map_cwe("sql_injection")
        assert result["id"] == "CWE-89"
        assert "SQL Injection" in result["name"]

    def test_sql_injection_space_maps_to_cwe_89(self):
        """SQL Injection (with space) should map to CWE-89."""
        result = map_cwe("SQL Injection")
        assert result["id"] == "CWE-89"

    def test_path_traversal_maps_to_cwe_22(self):
        """path_traversal should map to CWE-22."""
        result = map_cwe("path_traversal")
        assert result["id"] == "CWE-22"
        assert "Path Traversal" in result["name"]

    def test_path_traversal_space_maps_to_cwe_22(self):
        """Path Traversal (with space) should map to CWE-22."""
        result = map_cwe("Path Traversal")
        assert result["id"] == "CWE-22"

    def test_unknown_type_returns_cwe_unknown(self):
        """Unknown type should return CWE-UNKNOWN."""
        result = map_cwe("unknown_type")
        assert result["id"] == "CWE-UNKNOWN"
        assert result["name"] == "unknown_type"


class TestCWEMapperCaseInsensitive:
    """Case-insensitive matching tests."""

    def test_uppercase_sql_injection(self):
        """SQL_INJECTION should map to CWE-89."""
        result = map_cwe("SQL_INJECTION")
        assert result["id"] == "CWE-89"

    def test_mixed_case_sql_injection(self):
        """Sql_Injection should map to CWE-89."""
        result = map_cwe("Sql_Injection")
        assert result["id"] == "CWE-89"

    def test_uppercase_path_traversal(self):
        """PATH_TRAVERSAL should map to CWE-22."""
        result = map_cwe("PATH_TRAVERSAL")
        assert result["id"] == "CWE-22"

    def test_xss_lowercase(self):
        """xss should map to CWE-79."""
        result = map_cwe("xss")
        assert result["id"] == "CWE-79"

    def test_xss_uppercase(self):
        """XSS should map to CWE-79."""
        result = map_cwe("XSS")
        assert result["id"] == "CWE-79"


class TestCWEMapperSnakeCase:
    """snake_case support tests."""

    def test_command_injection_snake_case(self):
        """command_injection should map to CWE-78."""
        result = map_cwe("command_injection")
        assert result["id"] == "CWE-78"

    def test_hardcoded_secret_snake_case(self):
        """hardcoded_secret should map to CWE-798."""
        result = map_cwe("hardcoded_secret")
        assert result["id"] == "CWE-798"

    def test_weak_crypto_snake_case(self):
        """weak_crypto should map to CWE-327."""
        result = map_cwe("weak_crypto")
        assert result["id"] == "CWE-327"

    def test_insecure_deserialization_snake_case(self):
        """insecure_deserialization should map to CWE-502."""
        result = map_cwe("insecure_deserialization")
        assert result["id"] == "CWE-502"

    def test_deserialization_snake_case(self):
        """deserialization should map to CWE-502."""
        result = map_cwe("deserialization")
        assert result["id"] == "CWE-502"


class TestCWEMapperAllRequiredTypes:
    """All required type mappings from task specification."""

    def test_all_required_types_map_correctly(self):
        """All required types from task should map correctly."""
        test_cases = [
            ("sql_injection", "CWE-89"),
            ("path_traversal", "CWE-22"),
            ("command_injection", "CWE-78"),
            ("xss", "CWE-79"),
            ("ssrf", "CWE-918"),
            ("hardcoded_secret", "CWE-798"),
            ("weak_crypto", "CWE-327"),
            ("deserialization", "CWE-502"),
            ("insecure_deserialization", "CWE-502"),
        ]
        
        for vuln_type, expected_cwe in test_cases:
            result = map_cwe(vuln_type)
            assert result["id"] == expected_cwe, f"Failed for {vuln_type}"


class TestCWEMapperGetCWEId:
    """get_cwe_id function tests."""

    def test_get_cwe_id_sql_injection(self):
        """get_cwe_id should return CWE-89 for sql_injection."""
        assert get_cwe_id("sql_injection") == "CWE-89"

    def test_get_cwe_id_path_traversal(self):
        """get_cwe_id should return CWE-22 for path_traversal."""
        assert get_cwe_id("path_traversal") == "CWE-22"

    def test_get_cwe_id_unknown(self):
        """get_cwe_id should return CWE-UNKNOWN for unknown type."""
        assert get_cwe_id("unknown_type") == "CWE-UNKNOWN"


class TestCWEMapperIsKnown:
    """is_known_vulnerability_type tests."""

    def test_is_known_returns_true_for_known_type(self):
        """is_known_vulnerability_type should return True for known types."""
        assert is_known_vulnerability_type("sql_injection") is True
        assert is_known_vulnerability_type("xss") is True

    def test_is_known_returns_false_for_unknown_type(self):
        """is_known_vulnerability_type should return False for unknown types."""
        assert is_known_vulnerability_type("unknown_type") is False
        assert is_known_vulnerability_type("not_a_real_vuln") is False

    def test_is_known_case_insensitive(self):
        """is_known_vulnerability_type should be case-insensitive."""
        assert is_known_vulnerability_type("SQL_INJECTION") is True
        assert is_known_vulnerability_type("Xss") is True


class TestCWEMapperResultStructure:
    """Result structure tests."""

    def test_result_has_required_fields(self):
        """Result should have id, name, description fields."""
        result = map_cwe("sql_injection")
        
        assert "id" in result
        assert "name" in result
        assert "description" in result

    def test_unknown_result_has_original_name(self):
        """Unknown type result should have original name."""
        result = map_cwe("custom_vulnerability")
        
        assert result["id"] == "CWE-UNKNOWN"
        assert result["name"] == "custom_vulnerability"


class TestCWEMapperEmptyInput:
    """Empty/None input tests."""

    def test_empty_string_returns_unknown(self):
        """Empty string should return CWE-UNKNOWN."""
        result = map_cwe("")
        assert result["id"] == "CWE-UNKNOWN"

    def test_none_returns_unknown(self):
        """None should return CWE-UNKNOWN."""
        result = map_cwe(None)
        assert result["id"] == "CWE-UNKNOWN"


class TestCWEMapperGetAllMappings:
    """get_all_cwe_mappings tests."""

    def test_get_all_mappings_returns_dict(self):
        """get_all_cwe_mappings should return a dictionary."""
        mappings = get_all_cwe_mappings()
        assert isinstance(mappings, dict)

    def test_get_all_mappings_contains_required_types(self):
        """get_all_cwe_mappings should contain all required types."""
        mappings = get_all_cwe_mappings()
        
        required_types = [
            "sql_injection",
            "path_traversal",
            "command_injection",
            "xss",
            "ssrf",
            "hardcoded_secret",
            "weak_crypto",
            "deserialization",
        ]
        
        for vuln_type in required_types:
            assert vuln_type in mappings or vuln_type.replace("_", " ") in mappings