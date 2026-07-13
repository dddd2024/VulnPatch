"""
Tests for GitHub repository loader.

Uses mock functions to simulate clone/download without real network access.
"""

import tempfile
import shutil
from pathlib import Path

import pytest

from ingest.github_loader import GitHubLoader, load_github_repo


@pytest.fixture
def mock_repo():
    """
    Create a mock repository structure in a temp directory.
    
    Returns:
        Path to the mock repository
    """
    temp_dir = tempfile.mkdtemp(prefix="mock_repo_")
    
    # Create some files
    (Path(temp_dir) / "main.py").write_text("print('hello')")
    (Path(temp_dir) / "utils.py").write_text("def helper(): pass")
    
    # Create a subdirectory
    subdir = Path(temp_dir) / "lib"
    subdir.mkdir()
    (subdir / "config.py").write_text("CONFIG = {}")
    
    yield Path(temp_dir)
    
    # Cleanup
    shutil.rmtree(temp_dir, ignore_errors=True)


@pytest.fixture
def mock_clone_func(mock_repo):
    """
    Create a mock clone function that returns the mock repo.
    """
    def clone(owner: str, repo: str, branch: str | None) -> Path:
        return mock_repo
    return clone


@pytest.fixture
def mock_download_func(mock_repo):
    """
    Create a mock download function that returns the mock repo.
    """
    def download(owner: str, repo: str, branch: str | None) -> Path:
        return mock_repo
    return download


class TestGitHubLoader:
    """Tests for GitHubLoader class."""
    
    def test_parse_github_url_valid(self):
        """Test parsing valid GitHub URLs."""
        loader = GitHubLoader()
        
        owner, repo = loader._parse_github_url("https://github.com/user/repo")
        assert owner == "user"
        assert repo == "repo"
        
        owner, repo = loader._parse_github_url("https://github.com/user/repo.git")
        assert owner == "user"
        assert repo == "repo"
        
        owner, repo = loader._parse_github_url("https://github.com/user/repo/tree/main")
        assert owner == "user"
        assert repo == "repo"
    
    def test_parse_github_url_invalid(self):
        """Test parsing invalid GitHub URLs."""
        loader = GitHubLoader()
        
        with pytest.raises(ValueError):
            loader._parse_github_url("https://gitlab.com/user/repo")
        
        with pytest.raises(ValueError):
            loader._parse_github_url("not-a-url")
    
    def test_load_repo_with_mock_clone(self, mock_clone_func):
        """Test loading repo with mock clone function."""
        loader = GitHubLoader(clone_func=mock_clone_func)
        
        repo_path, files = loader.load_repo("https://github.com/test/test_repo")
        
        assert repo_path.exists()
        assert len(files) >= 3  # main.py, utils.py, lib/config.py
        
        # Check that files have correct extensions
        for f in files:
            assert f.suffix in {".py", ".js", ".ts", ".java", ".go"}
    
    def test_load_repo_with_mock_download(self, mock_download_func):
        """Test loading repo with mock download function."""
        loader = GitHubLoader(download_func=mock_download_func)
        
        # Force download by making clone fail
        def failing_clone(owner, repo, branch):
            raise RuntimeError("Clone failed")
        
        loader = GitHubLoader(
            clone_func=failing_clone,
            download_func=mock_download_func
        )
        
        repo_path, files = loader.load_repo("https://github.com/test/test_repo")
        
        assert repo_path.exists()
        assert len(files) >= 3
    
    def test_cleanup_does_not_delete_external_mock_repo(self, mock_clone_func, mock_repo):
        """cleanup() must NOT delete directories returned by an injected clone_func."""
        loader = GitHubLoader(clone_func=mock_clone_func, cleanup=True)

        repo_path, files = loader.load_repo("https://github.com/test/test_repo")
        assert repo_path == mock_repo

        loader.cleanup()

        # The external mock repo must still exist
        assert mock_repo.exists(), (
            "cleanup() deleted a directory that belongs to an external mock"
        )
        # No owned dirs should have been tracked
        assert loader._owned_temp_dirs == []
        assert loader._temp_dirs == []

    def test_cleanup_does_not_delete_external_mock_download(self, mock_download_func, mock_repo):
        """cleanup() must NOT delete directories returned by an injected download_func."""
        failing_clone = lambda owner, repo, branch: (_ for _ in ()).throw(RuntimeError("fail"))
        loader = GitHubLoader(
            clone_func=failing_clone,
            download_func=mock_download_func,
            cleanup=True,
        )

        repo_path, files = loader.load_repo("https://github.com/test/test_repo")
        assert repo_path == mock_repo

        loader.cleanup()

        assert mock_repo.exists(), (
            "cleanup() deleted a directory that belongs to an external mock"
        )
        assert loader._owned_temp_dirs == []

    def test_cleanup_clears_tracking_lists(self, mock_clone_func):
        """After cleanup(), both tracking lists should be empty."""
        loader = GitHubLoader(clone_func=mock_clone_func, cleanup=True)
        loader.load_repo("https://github.com/test/test_repo")
        loader.cleanup()
        assert len(loader._temp_dirs) == 0
        assert len(loader._owned_temp_dirs) == 0
    
    def test_scan_directory_ignores_dirs(self, mock_repo):
        """Test that scan ignores certain directories."""
        loader = GitHubLoader()
        
        # Create ignored directories
        (mock_repo / ".git").mkdir()
        (mock_repo / ".git" / "config").write_text("git config")
        (mock_repo / "node_modules").mkdir()
        (mock_repo / "node_modules" / "package.js").write_text("module.exports = {}")
        
        files = loader._scan_directory(mock_repo)
        
        # Should not include files from ignored dirs
        for f in files:
            assert ".git" not in f.parts
            assert "node_modules" not in f.parts


class TestLoadGitHubRepo:
    """Tests for the convenience function."""
    
    def test_load_github_repo_with_mock(self, mock_clone_func):
        """Test convenience function with mock."""
        loader = GitHubLoader(clone_func=mock_clone_func)
        
        repo_path, files = load_github_repo(
            "https://github.com/test/test_repo",
            loader=loader
        )
        
        assert repo_path.exists()
        assert len(files) >= 3


class TestGitHubLoaderIntegration:
    """Integration tests (would require real network access)."""
    
    def test_url_validation_before_network(self):
        """Test that URL is validated before network access."""
        loader = GitHubLoader()
        
        # Invalid URL should raise ValueError before any network access
        with pytest.raises(ValueError, match="Not a valid GitHub URL"):
            loader.load_repo("https://notgithub.com/user/repo")
    
    def test_branch_parameter(self, mock_clone_func):
        """Test that branch parameter is passed correctly."""
        calls = []
        
        def tracking_clone(owner, repo, branch):
            calls.append((owner, repo, branch))
            temp_dir = tempfile.mkdtemp()
            (Path(temp_dir) / "main.py").write_text("print('hello')")
            return Path(temp_dir)
        
        loader = GitHubLoader(clone_func=tracking_clone)
        
        loader.load_repo("https://github.com/user/repo", branch="develop")
        
        assert calls[0] == ("user", "repo", "develop")
        
        loader.cleanup()