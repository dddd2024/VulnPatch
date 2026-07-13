"""
Tests for ingest module.

Tests code loading and language detection.
"""

import pytest
import tempfile
import os
from pathlib import Path
from ingest.language_router import detect_language_by_path, is_supported_file
from ingest.code_unit_builder import build_code_unit_from_snippet, build_code_unit_from_file
from ingest.repo_loader import RepoLoader


class TestLanguageRouter:
    """Tests for language router."""
    
    def test_detect_python(self):
        """Test detecting Python files."""
        assert detect_language_by_path("test.py") == "python"
        assert detect_language_by_path("src/main.py") == "python"
    
    def test_detect_javascript(self):
        """Test detecting JavaScript files."""
        assert detect_language_by_path("app.js") == "javascript"
        assert detect_language_by_path("lib/utils.js") == "javascript"
    
    def test_detect_unknown(self):
        """Test detecting unknown files."""
        assert detect_language_by_path("README.md") == "unknown"
        assert detect_language_by_path("Dockerfile") == "unknown"
    
    def test_is_supported_file(self):
        """Test checking if file is supported."""
        assert is_supported_file("test.py") is True
        assert is_supported_file("app.js") is True
        assert is_supported_file("README.md") is False


class TestCodeUnitBuilder:
    """Tests for code unit builder."""
    
    def test_build_from_snippet(self):
        """Test building CodeUnit from snippet."""
        code = "def hello():\n    return 'world'"
        unit = build_code_unit_from_snippet(code, language_hint="python")
        
        assert unit.path == "<snippet>"
        assert unit.language == "python"
        assert unit.content == code
        assert unit.metadata.get("is_snippet") is True
    
    def test_build_from_file(self):
        """Test building CodeUnit from file."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write("def hello():\n    pass\n")
            temp_path = f.name
        
        try:
            unit = build_code_unit_from_file(Path(temp_path))
            assert unit.language == "python"
            assert "hello" in unit.content
        finally:
            os.unlink(temp_path)


class TestRepoLoader:
    """Tests for repo loader."""
    
    def test_load_code_snippet(self):
        """Test loading code snippet."""
        loader = RepoLoader()
        units = loader.load_code_snippet("def hello(): pass", "python")
        
        assert len(units) == 1
        assert units[0].language == "python"
    
    def test_load_local_repo_empty(self):
        """Test loading empty repository."""
        with tempfile.TemporaryDirectory() as tmpdir:
            loader = RepoLoader()
            units = loader.load_local_repo(tmpdir)
            assert len(units) == 0
    
    def test_load_local_repo_with_python(self):
        """Test loading repository with Python files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a Python file
            with open(os.path.join(tmpdir, "test.py"), "w") as f:
                f.write("def hello():\n    pass\n")
            
            loader = RepoLoader()
            units = loader.load_local_repo(tmpdir)
            
            assert len(units) == 1
            assert units[0].language == "python"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
