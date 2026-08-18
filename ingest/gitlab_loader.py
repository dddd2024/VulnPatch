"""GitLab repository loader with clone/download fallback and safe cleanup."""

from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess
import tempfile
import zipfile
from pathlib import Path
from typing import Callable
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlparse
from urllib.request import Request, urlopen

logger = logging.getLogger(__name__)

GITLAB_URL_PATTERN = re.compile(r"https?://gitlab\.com/([^/]+)/([^/]+?)(?:\.git)?(?:/.*)?$")
GITLAB_SSH_PATTERN = re.compile(r"git@gitlab\.com:([^/]+)/([^/]+?)(?:\.git)?$")

IGNORED_DIRS = {
    ".git", "node_modules", "dist", "build", "__pycache__", ".venv", "venv",
    "target", ".idea", ".vscode", ".settings", "vendor", "third_party",
    ".pytest_cache", ".mypy_cache", ".tox",
}


class GitLabLoader:
    """Load repositories from GitLab.com or a configured self-hosted GitLab."""

    def __init__(
        self,
        clone_func: Callable | None = None,
        download_func: Callable | None = None,
        cleanup: bool = True,
        gitlab_token: str | None = None,
        gitlab_url: str | None = None,
    ) -> None:
        self._clone_func = clone_func
        self._download_func = download_func
        self._cleanup = cleanup
        self._token = gitlab_token if gitlab_token is not None else os.environ.get("GITLAB_TOKEN")
        self._gitlab_url = (gitlab_url or os.environ.get("GITLAB_URL") or "https://gitlab.com").rstrip("/")
        self._owned_temp_dirs: list[str] = []
        self._temp_dirs: list[str] = []

    def load_repo(self, repo_url: str, branch: str | None = None) -> tuple[Path, list[Path]]:
        owner, repo = self._parse_gitlab_url(repo_url)
        logger.info("Loading GitLab repository %s/%s", owner, repo)
        is_owned = False
        try:
            if self._clone_func:
                repo_path = Path(self._clone_func(owner, repo, branch))
            else:
                repo_path = self._try_clone(owner, repo, branch)
                is_owned = True
        except Exception as clone_error:
            logger.warning("GitLab clone failed; using archive fallback: %s", clone_error)
            if self._download_func:
                repo_path = Path(self._download_func(owner, repo, branch))
            else:
                repo_path = self._download_zip(owner, repo, branch)
                is_owned = True

        if is_owned:
            self._owned_temp_dirs.append(str(repo_path))
            self._temp_dirs.append(str(repo_path))
        return repo_path, self._scan_directory(repo_path)

    def load_repo_as_code_units(self, repo_url: str, branch: str | None = None) -> list:
        from ingest.code_unit_builder import build_code_unit_from_file

        repo_path, files = self.load_repo(repo_url, branch)
        try:
            units = []
            for path in files:
                try:
                    units.append(build_code_unit_from_file(path, root=repo_path))
                except (UnicodeDecodeError, OSError):
                    continue
            return units
        finally:
            if self._cleanup:
                self.cleanup()

    def cleanup(self) -> None:
        for temp_dir in list(self._owned_temp_dirs):
            shutil.rmtree(temp_dir, ignore_errors=True)
        self._owned_temp_dirs.clear()
        self._temp_dirs.clear()

    def _parse_gitlab_url(self, repo_url: str) -> tuple[str, str]:
        match = GITLAB_SSH_PATTERN.match(repo_url)
        if match:
            return match.group(1), match.group(2).removesuffix(".git")

        parsed = urlparse(repo_url)
        configured = urlparse(self._gitlab_url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError(f"Not a valid GitLab URL: {repo_url}")
        allowed_hosts = {"gitlab.com"}
        if configured.hostname:
            allowed_hosts.add(configured.hostname.lower())
        if parsed.hostname.lower() not in allowed_hosts:
            raise ValueError(f"Not a configured GitLab host: {parsed.hostname}")
        parts = [p for p in parsed.path.split("/") if p]
        if len(parts) < 2:
            raise ValueError(f"Not a valid GitLab repository URL: {repo_url}")
        # GitLab supports nested namespaces.  The final component is the repo;
        # everything before it is the namespace used in clone/archive URLs.
        repo = parts[-1].removesuffix(".git")
        owner = "/".join(parts[:-1])
        return owner, repo

    @property
    def _host_base(self) -> str:
        return self._gitlab_url

    def _try_clone(self, owner: str, repo: str, branch: str | None) -> Path:
        try:
            subprocess.run(["git", "--version"], capture_output=True, check=True)
        except (subprocess.CalledProcessError, FileNotFoundError) as exc:
            raise RuntimeError("Git is not available") from exc

        temp_dir = tempfile.mkdtemp(prefix=f"vulnpatch_gitlab_{repo}_")
        parsed = urlparse(self._host_base)
        host = parsed.netloc or "gitlab.com"
        scheme = parsed.scheme or "https"
        if self._token and scheme == "https":
            clone_url = f"https://oauth2:{self._token}@{host}/{owner}/{repo}.git"
        else:
            clone_url = f"{scheme}://{host}/{owner}/{repo}.git"
        cmd = ["git", "clone", "--depth", "1"]
        if branch:
            cmd.extend(["--branch", branch])
        cmd.extend([clone_url, temp_dir])
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            shutil.rmtree(temp_dir, ignore_errors=True)
            raise RuntimeError(f"Git clone failed: {result.stderr.strip()}")
        return Path(temp_dir)

    def _download_zip(self, owner: str, repo: str, branch: str | None) -> Path:
        branch = branch or "main"
        encoded_branch = quote(branch, safe="")
        url = f"{self._host_base}/{owner}/{repo}/-/archive/{encoded_branch}/{repo}-{encoded_branch}.zip"
        temp_dir = tempfile.mkdtemp(prefix=f"vulnpatch_gitlab_{repo}_")
        zip_path = Path(temp_dir) / "repo.zip"
        headers = {"User-Agent": "VulnPatch/1.0"}
        if self._token:
            headers["PRIVATE-TOKEN"] = self._token
        try:
            with urlopen(Request(url, headers=headers), timeout=60) as response, zip_path.open("wb") as fh:
                shutil.copyfileobj(response, fh)
            with zipfile.ZipFile(zip_path, "r") as archive:
                archive.extractall(temp_dir)
            zip_path.unlink(missing_ok=True)
            dirs = [p for p in Path(temp_dir).iterdir() if p.is_dir() and not p.name.startswith(".")]
            if not dirs:
                raise RuntimeError("No directory found after GitLab archive extraction")
            return dirs[0]
        except HTTPError as exc:
            shutil.rmtree(temp_dir, ignore_errors=True)
            if exc.code == 404 and branch == "main":
                return self._download_zip(owner, repo, "master")
            raise RuntimeError(f"Failed to download GitLab archive: {exc}") from exc
        except (URLError, zipfile.BadZipFile, OSError) as exc:
            shutil.rmtree(temp_dir, ignore_errors=True)
            raise RuntimeError(f"Failed to download/extract GitLab archive: {exc}") from exc

    def _scan_directory(self, root: Path) -> list[Path]:
        from ingest.language_router import is_supported_file

        root = Path(root)
        files: list[Path] = []
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            try:
                relative_parts = path.relative_to(root).parts[:-1]
            except ValueError:
                continue
            if any(part in IGNORED_DIRS for part in relative_parts):
                continue
            if is_supported_file(str(path)):
                files.append(path)
        return sorted(files)


def load_gitlab_repo(repo_url: str, branch: str | None = None, loader: GitLabLoader | None = None) -> tuple[Path, list[Path]]:
    loader = loader or GitLabLoader()
    return loader.load_repo(repo_url, branch)
