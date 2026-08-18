"""Unified repository/snippet ingestion facade used by the audit orchestrator."""
from __future__ import annotations

from pathlib import Path

from ingest.code_unit_builder import build_code_unit_from_file, build_code_unit_from_snippet
from ingest.language_router import is_supported_file
from ingest.github_loader import GitHubLoader
from ingest.gitlab_loader import GitLabLoader
from ingest.gitea_loader import GiteaLoader
from ingest.zip_loader import ZipLoader


class RepoLoader:
    def __init__(
        self,
        github_loader: GitHubLoader | None = None,
        gitlab_loader: GitLabLoader | None = None,
        gitea_loader: GiteaLoader | None = None,
        zip_loader: ZipLoader | None = None,
    ) -> None:
        self.github_loader = github_loader or GitHubLoader()
        self.gitlab_loader = gitlab_loader or GitLabLoader()
        self.gitea_loader = gitea_loader or GiteaLoader()
        self.zip_loader = zip_loader or ZipLoader()

    def load_code_snippet(self, code: str, language: str | None = None):
        return [build_code_unit_from_snippet(code, language_hint=language)]

    def load_local_repo(self, repo_path: str | Path):
        root = Path(repo_path)
        if not root.exists() or not root.is_dir():
            raise ValueError(f"Repository path does not exist: {repo_path}")
        units = []
        ignored = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build", "target"}
        for path in root.rglob("*"):
            if not path.is_file() or any(part in ignored for part in path.parts):
                continue
            if not is_supported_file(str(path)):
                continue
            try:
                units.append(build_code_unit_from_file(path, root=root))
            except (OSError, UnicodeError):
                continue
        return units

    def _units_from_remote_loader(self, loader, repo_url: str, branch: str | None = None):
        repo_path, files = loader.load_repo(repo_url, branch)
        try:
            units = []
            for path in files:
                try:
                    units.append(build_code_unit_from_file(Path(path), root=Path(repo_path)))
                except (OSError, UnicodeError):
                    continue
            return units
        finally:
            # Loader cleanup only removes directories it owns; injected test repos are preserved.
            loader.cleanup()

    def load_github_repo(self, repo_url: str, branch: str | None = None):
        return self._units_from_remote_loader(self.github_loader, repo_url, branch)

    def load_gitlab_repo(self, repo_url: str, branch: str | None = None):
        return self._units_from_remote_loader(self.gitlab_loader, repo_url, branch)

    def load_gitea_repo(self, repo_url: str, branch: str | None = None):
        return self._units_from_remote_loader(self.gitea_loader, repo_url, branch)

    def load_zip(self, zip_path: str | Path):
        return self.zip_loader.load_zip_as_code_units(Path(zip_path))
