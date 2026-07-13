"""
Tests for AuditOrchestrator GitHub scanning.

Uses mock to simulate GitHub repo loading without real network access.
"""

import tempfile
import shutil
from pathlib import Path

import pytest

from audit_core.orchestrator import AuditOrchestrator
from audit_core.models import AuditResult, AuditSummary
from ingest.repo_loader import RepoLoader
from ingest.github_loader import GitHubLoader


@pytest.fixture
def mock_github_repo():
    """
    Create a mock GitHub repository structure with known-detectable
    vulnerabilities so that assertions can be strict (``> 0``).

    The following vulnerabilities are constructed to be reliably detected
    by the legacy detector / pattern analyzer:

    * **SQL Injection** (CWE-89) — f-string in ``cursor.execute()``
    * **Command Injection** (CWE-78) — ``os.system()`` with string concat
    * **Hardcoded Secret** (CWE-798) — ``password = "..."``
    * **Weak Cryptography** (CWE-327) — ``hashlib.md5()``
    * **Dangerous Code Execution** (CWE-95) — ``eval()``
    * **Path Traversal** (CWE-22) — ``open(request.args.get(...))``
    * **Insecure TLS** (CWE-295) — ``requests.get(..., verify=False)``
    """
    temp_dir = tempfile.mkdtemp(prefix="mock_github_")

    # --- app.py: SQL Injection + Path Traversal + Insecure TLS ---
    (Path(temp_dir) / "app.py").write_text("""
import sqlite3
import requests
from flask import Flask, request

app = Flask(__name__)

@app.route('/search')
def search():
    query = request.args.get('q')
    # SQL injection vulnerability (f-string in execute)
    conn = sqlite3.connect("db.sqlite3")
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE name = '{query}'")
    return cursor.fetchall()

@app.route('/read')
def read_file():
    # Path traversal vulnerability
    filename = request.args.get('file')
    with open(filename, 'r') as f:
        return f.read()

@app.route('/fetch')
def fetch_data():
    # Insecure TLS
    url = request.args.get('url')
    return requests.get(url, verify=False).text
""")

    # --- utils.py: Command Injection + Hardcoded Secret + Weak Crypto ---
    (Path(temp_dir) / "utils.py").write_text("""
import os
import hashlib

# Hardcoded secret
DB_PASSWORD = "super_secret_123"
API_KEY = "sk-abc123def456"

def run_command(user_input):
    # Command injection vulnerability
    os.system("ls " + user_input)

def hash_password(password):
    # Weak cryptography
    return hashlib.md5(password.encode()).hexdigest()
""")

    # --- danger.py: Dangerous Code Execution ---
    (Path(temp_dir) / "danger.py").write_text("""
def execute_user_code(user_input):
    # Dangerous code execution
    eval(user_input)
""")

    yield Path(temp_dir)

    # Cleanup
    shutil.rmtree(temp_dir, ignore_errors=True)


@pytest.fixture
def mock_clone_func(mock_github_repo):
    """
    Create a mock clone function that returns the mock repo.
    """
    def clone(owner: str, repo: str, branch: str | None) -> Path:
        return mock_github_repo
    return clone


@pytest.fixture
def mock_github_loader(mock_clone_func):
    """
    Create a GitHubLoader with mock clone function.
    """
    return GitHubLoader(clone_func=mock_clone_func)


@pytest.fixture
def mock_repo_loader(mock_github_loader):
    """
    Create a RepoLoader with mock GitHubLoader.
    """
    return RepoLoader(github_loader=mock_github_loader)


@pytest.fixture
def orchestrator(mock_repo_loader):
    """
    Create an AuditOrchestrator with mock repo loader.
    """
    orch = AuditOrchestrator()
    orch.repo_loader = mock_repo_loader
    return orch


class TestOrchestratorGitHub:
    """Tests for AuditOrchestrator GitHub scanning."""
    
    def test_scan_github_returns_result(self, orchestrator):
        """Test that scan_github returns an AuditResult."""
        result = orchestrator.scan_github("https://github.com/test/test_repo")
        
        assert isinstance(result, AuditResult)
        assert isinstance(result.summary, AuditSummary)
    
    def test_scan_github_no_metadata_error(self, orchestrator):
        """Test that scan_github does not return metadata error."""
        result = orchestrator.scan_github("https://github.com/test/test_repo")
        
        # Should NOT have the old "not implemented" error
        assert "error" not in result.metadata or \
               result.metadata.get("error") != "GitHub repo scanning not yet implemented"
    
    def test_scan_github_loads_code_units(self, orchestrator):
        """Test that scan_github loads code units from the repo."""
        result = orchestrator.scan_github("https://github.com/test/test_repo")
        
        # Should have loaded the mock files
        assert result.summary.total_code_units >= 2
    
    def test_scan_github_detects_vulnerabilities(self, orchestrator):
        """Test that scan_github detects specific vulnerability types."""
        result = orchestrator.scan_github("https://github.com/test/test_repo")

        # Must have at least one finding — the mock repo has 7 known vulns
        assert result.summary.total_findings > 0, (
            "Expected at least 1 finding from the mock repo that contains "
            "SQL injection, command injection, hardcoded secrets, etc."
        )

        # At least one finding should match a known vulnerability type
        known_types = {"SQL", "Command Injection", "Hardcoded Secret",
                       "Weak", "Path Traversal", "Insecure", "eval", "Dangerous"}
        finding_types = {f.type for f in result.findings}
        matched = [t for t in finding_types if any(k in t for k in known_types)]
        assert len(matched) > 0, (
            f"Expected findings with recognizable vulnerability types, "
            f"but got: {finding_types}"
        )

    def test_evidence_bundles_match_findings(self, orchestrator):
        """Evidence bundle count should be consistent with findings."""
        result = orchestrator.scan_github("https://github.com/test/test_repo")

        # If there are findings, there should be a corresponding number of
        # evidence bundles (at least 1 per finding that generated evidence).
        if result.summary.total_findings > 0:
            assert result.summary.total_evidence_bundles > 0, (
                "Findings exist but no evidence bundles were generated"
            )
            # Each evidence bundle should reference a finding
            for bundle in result.evidence:
                assert bundle.finding is not None, (
                    "Evidence bundle is missing its finding reference"
                )
    
    def test_scan_input_type_github(self, orchestrator):
        """Test that scan() with input_type='github' works."""
        result = orchestrator.scan(
            input_type="github",
            repo_url="https://github.com/test/test_repo"
        )
        
        assert isinstance(result, AuditResult)
        assert "error" not in result.metadata or \
               result.metadata.get("error") != "GitHub repo scanning not yet implemented"
    
    def test_scan_input_type_github_requires_repo_url(self, orchestrator):
        """Test that scan() with input_type='github' requires repo_url."""
        with pytest.raises(ValueError, match="repo_url is required"):
            orchestrator.scan(input_type="github")
    
    def test_scan_github_invalid_url(self, orchestrator):
        """Test that scan_github raises error for invalid URL."""
        with pytest.raises(ValueError, match="Not a valid GitHub URL"):
            orchestrator.scan_github("https://notgithub.com/user/repo")
    
    def test_scan_github_with_branch(self, mock_clone_func):
        """Test that scan_github passes branch parameter."""
        calls = []
        
        def tracking_clone(owner, repo, branch):
            calls.append((owner, repo, branch))
            temp_dir = tempfile.mkdtemp()
            (Path(temp_dir) / "main.py").write_text("print('hello')")
            return Path(temp_dir)
        
        loader = GitHubLoader(clone_func=tracking_clone)
        repo_loader = RepoLoader(github_loader=loader)
        orchestrator = AuditOrchestrator()
        orchestrator.repo_loader = repo_loader
        
        result = orchestrator.scan_github(
            "https://github.com/user/repo",
            branch="develop"
        )
        
        assert calls[0] == ("user", "repo", "develop")
        
        # Cleanup
        loader.cleanup()


class TestOrchestratorGitHubIntegration:
    """Integration tests for GitHub scanning."""
    
    def test_full_pipeline_with_mock_repo(self, mock_github_repo, mock_clone_func):
        """Test full audit pipeline with mock GitHub repo."""
        loader = GitHubLoader(clone_func=mock_clone_func)
        repo_loader = RepoLoader(github_loader=loader)
        orchestrator = AuditOrchestrator()
        orchestrator.repo_loader = repo_loader
        
        result = orchestrator.scan_github("https://github.com/test/vuln_repo")
        
        # Verify result structure
        assert result.summary is not None
        assert result.findings is not None
        assert result.evidence is not None
        assert result.agent_logs is not None
        
        # Verify summary fields
        assert result.summary.total_code_units >= 0
        assert result.summary.total_findings >= 0
        assert result.summary.total_evidence_bundles >= 0
        assert result.summary.risk_score >= 0
        
        # Cleanup
        loader.cleanup()
    
    def test_cleanup_after_scan(self, mock_clone_func):
        """Test that temporary directories are cleaned up after scan."""
        loader = GitHubLoader(clone_func=mock_clone_func)
        repo_loader = RepoLoader(github_loader=loader)
        orchestrator = AuditOrchestrator()
        orchestrator.repo_loader = repo_loader
        
        result = orchestrator.scan_github("https://github.com/test/test_repo")
        
        # Owned temp dirs should be empty (mock dirs are not owned)
        assert len(loader._owned_temp_dirs) == 0
        assert len(loader._temp_dirs) == 0

    def test_cleanup_does_not_delete_external_mock_repo(self, mock_clone_func, mock_github_repo):
        """cleanup() must NOT delete the directory returned by an external mock."""
        loader = GitHubLoader(clone_func=mock_clone_func)
        repo_loader = RepoLoader(github_loader=loader)
        orchestrator = AuditOrchestrator()
        orchestrator.repo_loader = repo_loader

        orchestrator.scan_github("https://github.com/test/test_repo")
        loader.cleanup()

        # The external mock repo must still exist
        assert mock_github_repo.exists(), (
            "cleanup() deleted a directory that belongs to an external mock"
        )