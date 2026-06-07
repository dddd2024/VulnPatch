"""
Gitea repository loader for cloning or downloading repositories.

Supports:
- Git clone (requires git installed)
- ZIP download (fallback when git is not available)
- Gitea API (compatible with Gitea/Gogs)
- Gitea Token authentication (environment variable GITEA_TOKEN)
- Automatic cleanup of temporary directories
"""

import logging
import os
import re
import shutil
import subprocess
import tempfile
import zipfile
from pathlib import Path
from typing import Callable
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError

logger = logging.getLogger(__name__)

# Gitea URL patterns (兼容 Gitea 和 Gogs)
GITEA_URL_PATTERN = re.compile(
    r"https?://([^/]+)/([^/]+)/([^/]+?)(?:\.git)?(?:/.*)?"
)
GITEA_SSH_PATTERN = re.compile(
    r"git@([^:]+):([^/]+)/([^/]+?)(?:\.git)?$"
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


class GiteaLoader:
    """
    Gitea 仓库加载器。

    支持通过 git clone 或 ZIP 下载方式获取 Gitea/Gogs 仓库代码。
    自动管理临时目录并在加载完成后清理。

    仅追踪由加载器自身创建的临时目录（通过内置的
    ``_try_clone`` 或 ``_download_zip`` 方法），外部注入的
    ``clone_func`` / ``download_func`` 返回的目录不会被 ``cleanup()`` 删除。
    """

    def __init__(
        self,
        clone_func: Callable | None = None,
        download_func: Callable | None = None,
        cleanup: bool = True,
        gitea_token: str | None = None,
        gitea_url: str | None = None,
    ):
        """
        初始化 Gitea 加载器。

        Args:
            clone_func: 可选的克隆函数（用于测试模拟）。
                当提供时，该函数返回的目录不会被自动清理。
            download_func: 可选的下载函数（用于测试模拟）。
                当提供时，该函数返回的目录不会被自动清理。
            cleanup: 是否在加载后清理临时目录
            gitea_token: 可选的 Gitea 个人访问令牌。
                未提供时从 ``GITEA_TOKEN`` 环境变量读取。
            gitea_url: 可选的 Gitea 实例 URL。
                未提供时从 ``GITEA_URL`` 环境变量读取或使用 https://gitea.com。
        """
        self._clone_func = clone_func
        self._download_func = download_func
        self._cleanup = cleanup
        self._token = gitea_token if gitea_token is not None else os.environ.get("GITEA_TOKEN")
        self._gitea_url = (gitea_url or os.environ.get("GITEA_URL") or "https://gitea.com").rstrip("/")
        # 仅追踪由加载器自身创建的目录
        self._owned_temp_dirs: list[str] = []
        # 向后兼容；始终是 _owned_temp_dirs 的子集
        self._temp_dirs: list[str] = []

    def load_repo(
        self,
        repo_url: str,
        branch: str | None = None,
    ) -> tuple[Path, list[Path]]:
        """
        加载 Gitea 仓库。

        Args:
            repo_url: Gitea 仓库 URL
                （例如 "https://gitea.com/user/repo" 或自托管实例 URL）
            branch: 可选的分支名称（默认为 main/master）

        Returns:
            元组 (仓库路径, 文件路径列表)

        Raises:
            ValueError: 如果 URL 不是有效的 Gitea URL
            RuntimeError: 如果克隆和下载都失败
        """
        # 解析 Gitea URL
        host, owner, repo = self._parse_gitea_url(repo_url)

        logger.info("正在加载 Gitea 仓库: %s/%s/%s (分支: %s)", host, owner, repo, branch or "默认")

        # 优先尝试 git clone，失败则回退到 ZIP 下载
        repo_path: Path
        is_owned = False

        try:
            if self._clone_func:
                repo_path = self._clone_func(host, owner, repo, branch)
            else:
                repo_path = self._try_clone(host, owner, repo, branch)
                is_owned = True
        except Exception as e:
            logger.warning("Git clone 失败，回退到 ZIP 下载: %s", e)
            # 回退到 ZIP 下载
            if self._download_func:
                repo_path = self._download_func(host, owner, repo, branch)
            else:
                repo_path = self._download_zip(host, owner, repo, branch)
                is_owned = True

        # 追踪临时目录用于清理
        if is_owned:
            self._owned_temp_dirs.append(str(repo_path))
            self._temp_dirs.append(str(repo_path))

        # 扫描文件
        files = self._scan_directory(repo_path)

        logger.info("仓库加载完成，共发现 %d 个支持文件", len(files))

        return repo_path, files

    def load_repo_as_code_units(
        self,
        repo_url: str,
        branch: str | None = None,
    ) -> list:
        """
        加载 Gitea 仓库并返回 CodeUnit 列表。

        Args:
            repo_url: Gitea 仓库 URL
            branch: 可选的分支名称

        Returns:
            CodeUnit 对象列表

        Raises:
            ValueError: 如果 URL 不是有效的 Gitea URL
            RuntimeError: 如果加载失败
        """
        from ingest.code_unit_builder import build_code_unit_from_file

        repo_path, files = self.load_repo(repo_url, branch)

        try:
            code_units = []
            for file_path in files:
                try:
                    unit = build_code_unit_from_file(file_path, root=repo_path)
                    code_units.append(unit)
                except (UnicodeDecodeError, IOError):
                    # 跳过无法作为文本读取的文件
                    continue
            return code_units
        finally:
            # 清理临时目录
            if self._cleanup:
                self.cleanup()

    def cleanup(self):
        """清理由加载器创建的临时目录。"""
        for temp_dir in self._owned_temp_dirs:
            try:
                shutil.rmtree(temp_dir, ignore_errors=True)
                logger.debug("已清理临时目录: %s", temp_dir)
            except Exception:
                pass
        self._owned_temp_dirs.clear()
        self._temp_dirs.clear()

    def _parse_gitea_url(self, repo_url: str) -> tuple[str, str, str]:
        """
        解析 Gitea URL 以提取 host、owner 和仓库名。

        Args:
            repo_url: Gitea 仓库 URL

        Returns:
            元组 (host, owner, repo_name)

        Raises:
            ValueError: 如果 URL 不是有效的 Gitea URL
        """
        # 尝试匹配 HTTPS URL
        match = GITEA_URL_PATTERN.match(repo_url)
        if match:
            host = match.group(1)
            owner = match.group(2)
            repo = match.group(3)
        else:
            # 尝试匹配 SSH URL
            match = GITEA_SSH_PATTERN.match(repo_url)
            if match:
                host = match.group(1)
                owner = match.group(2)
                repo = match.group(3)
            else:
                raise ValueError(f"不是有效的 Gitea URL: {repo_url}")

        # 移除 .git 后缀
        if repo.endswith(".git"):
            repo = repo[:-4]

        return host, owner, repo

    def _try_clone(self, host: str, owner: str, repo: str, branch: str | None) -> Path:
        """
        尝试使用 git clone 克隆仓库。

        Args:
            host: Gitea 实例主机名
            owner: 仓库所有者/组织
            repo: 仓库名称
            branch: 可选的分支名称

        Returns:
            克隆仓库的路径

        Raises:
            RuntimeError: 如果 git 不可用或克隆失败
        """
        # 检查 git 是否可用
  