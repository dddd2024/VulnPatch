"""
GitHub repository loader for cloning or downloading repositories.

Supports:
- Git clone (requires git installed)
- ZIP download (fallback when git is not available)
- Automatic cleanup of temporary directories
"""

import os
import re
import shutil
import tempfile
import zipfile
from pathlib import Path
from typing import Callable
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError


# GitHub URL patterns
GITHUB_URL_PATTERN = re.compile(
    r"https?://github\.com/([^/]+)/([^/]+)(?:/.*)?"
)
GITHUB_SSH_PATTERN = re.compile(
    r"git@github\.com:([^/]+)/([^/]+?)(?:\.git)?$"
)

# Directories to ignore when scanning repositories
IGNORED_DIRS = {
    ".git",
    "node_modules",
    "dist",
    "build",
    "__pycache__",
    ".venv",
    "venv",
    "target",
    ".idea",
    ".vscode",
    ".settings",
    "vendor",
    "third_party",
    ".pytest_cache",
    ".mypy_cache",
    ".tox",
    "*.egg-info",
}


class GitHubLoader:
    """
    Loader for GitHub repositories.
    
    Supports cloning via git or downloading as ZIP archive.
    Automatically manages temporary directories and cleanup.

    Only temporary directories **created by this loader itself** (via the
    built-in ``_try_clone`` or ``_download_zip`` methods) are tracked for
    automatic cleanup.  Directories returned by externally injected
    ``clone_func`` / ``download_func`` callables are **never** deleted by
    ``cleanup()``, because the loader does not own them.
    """
    
    def __init__(
        self,
        clone_func: Callable | None = None,
        download_func: Callable | None = None,
        cleanup: bool = True,
        github_token: str | None = None
    ):
        """
        Initialize the GitHub loader.
        
        Args:
            clone_func: Optional function to use for cloning (for mocking).
                When provided, directories returned by this function are
                **not** tracked for automatic cleanup.
            download_func: Optional function to use for downloading (for mocking).
                When provided, directories returned by this function are
                **not** tracked for automatic cleanup.
            cleanup: Whether to clean up owned temporary directories after loading
            github_token: Optional GitHub personal access token.
                When not provided, reads from the ``GITHUB_TOKEN`` environment
                variable.  The token is used for authenticated clone/download.
        """
        self._clone_func = clone_func
        self._download_func = download_func
        self._cleanup = cleanup
        self._token = github_token if github_token is not None else os.environ.get("GITHUB_TOKEN")
        # Only directories created by the loader itself are tracked here.
        self._owned_temp_dirs: list[str] = []
        # Kept for backward compatibility; always a subset of _owned_temp_dirs.
        self._temp_dirs: list[str] = []
    
    def load_repo(
        self,
        repo_url: str,
        branch: str | None = None
    ) -> tuple[Path, list[Path]]:
        """
        Load a GitHub repository.
        
        Args:
            repo_url: GitHub repository URL (e.g., "https://github.com/user/repo")
            branch: Optional branch name (defaults to main/master)
            
        Returns:
            Tuple of (repo_path, list of file paths)
            
        Raises:
            ValueError: If the URL is not a valid GitHub URL
            RuntimeError: If both clone and download fail
        """
        # Parse GitHub URL
        owner, repo = self._parse_github_url(repo_url)
        
        # Try clone first, fall back to ZIP download
        repo_path: Path
        is_owned = False  # whether the loader created this directory itself

        try:
            if self._clone_func:
                repo_path = self._clone_func(owner, repo, branch)
            else:
                repo_path = self._try_clone(owner, repo, branch)
                is_owned = True
        except Exception:
            # Fall back to ZIP download
            if self._download_func:
                repo_path = self._download_func(owner, repo, branch)
            else:
                repo_path = self._download_zip(owner, repo, branch)
                is_owned = True
        
        # Track temp directory for cleanup — only if the loader owns it
        if is_owned:
            self._owned_temp_dirs.append(str(repo_path))
            self._temp_dirs.append(str(repo_path))
        
        # Scan for files
        files = self._scan_directory(repo_path)
        
        return repo_path, files
    
    def cleanup(self):
        """Clean up only the temporary directories that this loader created."""
        for temp_dir in self._owned_temp_dirs:
            try:
                shutil.rmtree(temp_dir, ignore_errors=True)
            except Exception:
                pass
        self._owned_temp_dirs.clear()
        self._temp_dirs.clear()
    
    def _parse_github_url(self, repo_url: str) -> tuple[str, str]:
        """
        Parse a GitHub URL to extract owner and repo name.
        
        Args:
            repo_url: GitHub repository URL
            
        Returns:
            Tuple of (owner, repo_name)
            
        Raises:
            ValueError: If the URL is not a valid GitHub URL
        """
        match = GITHUB_URL_PATTERN.match(repo_url)
        if not match:
            match = GITHUB_SSH_PATTERN.match(repo_url)
        if not match:
            raise ValueError(f"Not a valid GitHub URL: {repo_url}")
        
        owner = match.group(1)
        repo = match.group(2)
        
        # Remove .git suffix if present
        if repo.endswith(".git"):
            repo = repo[:-4]
        
        return owner, repo
    
    def _try_clone(self, owner: str, repo: str, branch: str | None) -> Path:
        """
        Try to clone the repository using git.
        
        Args:
            owner: Repository owner
            repo: Repository name
            branch: Optional branch name
            
        Returns:
            Path to the cloned repository
            
        Raises:
            RuntimeError: If git is not available or clone fails
        """
        import subprocess
        
        # Check if git is available
        try:
            subprocess.run(
                ["git", "--version"],
                capture_output=True,
                check=True
            )
        except (subprocess.CalledProcessError, FileNotFoundError):
            raise RuntimeError("Git is not available")
        
        # Create temp directory
        temp_dir = tempfile.mkdtemp(prefix=f"vulnpatch_{repo}_")
        
        # Build clone URL
        if self._token:
            clone_url = f"https://{self._token}@github.com/{owner}/{repo}.git"
        else:
            clone_url = f"https://github.com/{owner}/{repo}.git"
        
        # Clone command
        cmd = ["git", "clone", "--depth", "1"]
        if branch:
            cmd.extend(["--branch", branch])
        cmd.extend([clone_url, temp_dir])
        
        # Run clone
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode != 0:
            shutil.rmtree(temp_dir, ignore_errors=True)
            raise RuntimeError(f"Git clone failed: {result.stderr}")
        
        return Path(temp_dir)
    
    def _download_zip(self, owner: str, repo: str, branch: str | None) -> Path:
        """
        Download the repository as a ZIP archive.
        
        Args:
            owner: Repository owner
            repo: Repository name
            branch: Optional branch name (defaults to 'main', then 'master')
            
        Returns:
            Path to the extracted repository
            
        Raises:
            RuntimeError: If download or extraction fails
        """
        # Default branch to 'main'
        branch = branch or "main"
        
        # Build ZIP URL
        zip_url = f"https://github.com/{owner}/{repo}/archive/refs/heads/{branch}.zip"
        
        # Create temp directory
        temp_dir = tempfile.mkdtemp(prefix=f"vulnpatch_{repo}_")
        zip_path = Path(temp_dir) / "repo.zip"
        
        # Build request headers
        headers = {"User-Agent": "VulnPatch/1.0"}
        if self._token:
            headers["Authorization"] = f"token {self._token}"
        
        try:
            # Download ZIP
            request = Request(zip_url, headers=headers)
            response = urlopen(request, timeout=60)
            
            with open(zip_path, "wb") as f:
                f.write(response.read())
            
            # Extract ZIP
            with zipfile.ZipFile(zip_path, "r") as zf:
                zf.extractall(temp_dir)
            
            # Remove ZIP file
            zip_path.unlink()
            
            # Find extracted directory (usually repo-branch)
            extracted_dirs = [
                p for p in Path(temp_dir).iterdir()
                if p.is_dir() and not p.name.startswith(".")
            ]
            
            if not extracted_dirs:
                raise RuntimeError("No directory found after extraction")
            
            # Return the extracted repo directory
            return extracted_dirs[0]
            
        except HTTPError as e:
            # If 404 and we used the default branch, try 'master' as fallback
            if e.code == 404 and branch == "main":
                shutil.rmtree(temp_dir, ignore_errors=True)
                return self._download_zip(owner, repo, "master")
            shutil.rmtree(temp_dir, ignore_errors=True)
            raise RuntimeError(f"Failed to download ZIP: {e}")
        except (URLError, HTTPError) as e:
            shutil.rmtree(temp_dir, ignore_errors=True)
            raise RuntimeError(f"Failed to download ZIP: {e}")
        except zipfile.BadZipFile as e:
            shutil.rmtree(temp_dir, ignore_errors=True)
            raise RuntimeError(f"Failed to extract ZIP: {e}")
    
    def _scan_directory(self, root: Path) -> list[Path]:
        """
        Scan a directory for supported code files.
        
        Args:
            root: Root directory to scan
            
        Returns:
            List of paths to supported files
        """
        from ingest.language_router import is_supported_file

        files = []
        
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            
            # Check if any parent directory should be ignored
            relative_parts = path.relative_to(root).parts[:-1]
            if any(part in IGNORED_DIRS for part in relative_parts):
                continue
            
            # Check if file has supported extension
            if is_supported_file(str(path)):
                files.append(path)
        
        return sorted(files)


def load_github_repo(
    repo_url: str,
    branch: str | None = None,
    loader: GitHubLoader | None = None
) -> tuple[Path, list[Path]]:
    """
    Convenience function to load a GitHub repository.
    
    Args:
        repo_url: GitHub repository URL
        branch: Optional branch name
        loader: Optional GitHubLoader instance
        
    Returns:
        Tuple of (repo_path, list of file paths)
    """
    if loader is None:
        loader = GitHubLoader()
    return loader.load_repo(repo_url, branch)