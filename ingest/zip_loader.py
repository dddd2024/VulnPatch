"""
ZIP archive loader for extracting and loading code from ZIP files.

Supports:
- Uploading and extracting ZIP files
- Safe extraction (prevents path traversal attacks)
- Automatic language detection
- Integration with code_unit_builder for CodeUnit generation
- Automatic cleanup of temporary directories
"""

import logging
import os
import shutil
import tempfile
import zipfile
from pathlib import Path

logger = logging.getLogger(__name__)

# Directories to ignore when scanning extracted archives
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

# ZIP 文件最大允许大小（默认 500MB）
MAX_ZIP_SIZE = 500 * 1024 * 1024

# ZIP 文件内最大允许的文件数量
MAX_FILE_COUNT = 10000


class ZipLoader:
    """
    ZIP 包加载器。

    支持上传的 ZIP 文件解压并加载为 CodeUnit 列表。
    包含安全解压机制以防止路径遍历攻击（Zip Slip）。
    自动管理临时目录并在加载完成后清理。
    """

    def __init__(
        self,
        cleanup: bool = True,
        max_zip_size: int = MAX_ZIP_SIZE,
        max_file_count: int = MAX_FILE_COUNT,
    ):
        """
        初始化 ZIP 加载器。

        Args:
            cleanup: 是否在加载后清理临时目录
            max_zip_size: ZIP 文件最大允许大小（字节）
            max_file_count: ZIP 文件内最大允许的文件数量
        """
        self._cleanup = cleanup
        self._max_zip_size = max_zip_size
        self._max_file_count = max_file_count
        # 追踪由加载器创建的临时目录
        self._owned_temp_dirs: list[str] = []
        self._temp_dirs: list[str] = []

    def load_zip(self, zip_path: str | Path) -> tuple[Path, list[Path]]:
        """
        加载 ZIP 文件。

        Args:
            zip_path: ZIP 文件路径

        Returns:
            元组 (解压目录路径, 文件路径列表)

        Raises:
            FileNotFoundError: 如果 ZIP 文件不存在
            ValueError: 如果 ZIP 文件无效或超过大小限制
            RuntimeError: 如果解压失败
        """
        zip_path = Path(zip_path)

        if not zip_path.exists():
            raise FileNotFoundError(f"ZIP 文件不存在: {zip_path}")

        if not zip_path.is_file():
            raise ValueError(f"路径不是文件: {zip_path}")

        # 检查文件大小
        file_size = zip_path.stat().st_size
        if file_size > self._max_zip_size:
            raise ValueError(
                f"ZIP 文件过大: {file_size} 字节 (最大允许: {self._max_zip_size} 字节)"
            )

        logger.info("正在加载 ZIP 文件: %s (大小: %d 字节)", zip_path.name, file_size)

        # 创建临时目录
        temp_dir = tempfile.mkdtemp(prefix="vulnpatch_zip_")
        self._owned_temp_dirs.append(str(temp_dir))
        self._temp_dirs.append(str(temp_dir))

        try:
            # 安全解压 ZIP
            extracted_dir = self._safe_extract(zip_path, temp_dir)

            # 扫描文件
            files = self._scan_directory(extracted_dir)

            logger.info("ZIP 加载完成，共发现 %d 个支持文件", len(files))

            return extracted_dir, files

        except Exception:
            # 解压失败时清理临时目录
            self._cleanup_dir(temp_dir)
            raise

    def load_zip_as_code_units(self, zip_path: str | Path) -> list:
        """
        加载 ZIP 文件并返回 CodeUnit 列表。

        Args:
            zip_path: ZIP 文件路径

        Returns:
            CodeUnit 对象列表

        Raises:
            FileNotFoundError: 如果 ZIP 文件不存在
            ValueError: 如果 ZIP 文件无效
            RuntimeError: 如果加载失败
        """
        from ingest.code_unit_builder import build_code_unit_from_file

        extracted_dir, files = self.load_zip(zip_path)

        try:
            code_units = []
            for file_path in files:
                try:
                    unit = build_code_unit_from_file(file_path, root=extracted_dir)
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
            self._cleanup_dir(temp_dir)
        self._owned_temp_dirs.clear()
        self._temp_dirs.clear()

    def _safe_extract(self, zip_path: Path, target_dir: str) -> Path:
        """
        安全解压 ZIP 文件，防止路径遍历攻击（Zip Slip）。

        检查每个条目的目标路径，确保不会解压到目标目录之外。
        同时检查符号链接和绝对路径。

        Args:
            zip_path: ZIP 文件路径
            target_dir: 目标解压目录

        Returns:
            解压后的根目录路径

        Raises:
            RuntimeError: 如果检测到路径遍历攻击或解压失败
        """
        target = Path(target_dir).resolve()

        try:
            with zipfile.ZipFile(zip_path, "r") as zf:
                # 检查文件数量
                file_count = sum(1 for entry in zf.infolist() if not entry.is_dir())
                if file_count > self._max_file_count:
                    raise RuntimeError(
                        f"ZIP 文件包含过多文件: {file_count} (最大允许: {self._max_file_c