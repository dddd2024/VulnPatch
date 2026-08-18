"""Safe ZIP archive loader used by VulnPatch ingest."""

from __future__ import annotations

import logging
import shutil
import stat
import tempfile
import zipfile
from pathlib import Path, PurePosixPath

logger = logging.getLogger(__name__)

IGNORED_DIRS = {
    ".git", "node_modules", "dist", "build", "__pycache__", ".venv", "venv",
    "target", ".idea", ".vscode", ".settings", "vendor", "third_party",
    ".pytest_cache", ".mypy_cache", ".tox",
}
MAX_ZIP_SIZE = 500 * 1024 * 1024
MAX_FILE_COUNT = 10000


class ZipLoader:
    """Extract ZIP archives defensively and expose supported source files."""

    def __init__(self, cleanup: bool = True, max_zip_size: int = MAX_ZIP_SIZE, max_file_count: int = MAX_FILE_COUNT) -> None:
        self._cleanup = cleanup
        self._max_zip_size = max_zip_size
        self._max_file_count = max_file_count
        self._owned_temp_dirs: list[str] = []
        self._temp_dirs: list[str] = []

    def load_zip(self, zip_path: str | Path) -> tuple[Path, list[Path]]:
        zip_path = Path(zip_path)
        if not zip_path.exists():
            raise FileNotFoundError(f"ZIP file does not exist: {zip_path}")
        if not zip_path.is_file():
            raise ValueError(f"ZIP path is not a file: {zip_path}")
        if zip_path.stat().st_size > self._max_zip_size:
            raise ValueError(f"ZIP file is too large: {zip_path.stat().st_size} bytes")
        if not zipfile.is_zipfile(zip_path):
            raise ValueError(f"Invalid ZIP archive: {zip_path}")

        temp_dir = tempfile.mkdtemp(prefix="vulnpatch_zip_")
        self._owned_temp_dirs.append(temp_dir)
        self._temp_dirs.append(temp_dir)
        try:
            extracted = self._safe_extract(zip_path, temp_dir)
            return extracted, self._scan_directory(extracted)
        except Exception:
            self._cleanup_dir(temp_dir)
            if temp_dir in self._owned_temp_dirs:
                self._owned_temp_dirs.remove(temp_dir)
            if temp_dir in self._temp_dirs:
                self._temp_dirs.remove(temp_dir)
            raise

    def load_zip_as_code_units(self, zip_path: str | Path) -> list:
        from ingest.code_unit_builder import build_code_unit_from_file

        root, files = self.load_zip(zip_path)
        try:
            units = []
            for path in files:
                try:
                    units.append(build_code_unit_from_file(path, root=root))
                except (UnicodeDecodeError, OSError):
                    continue
            return units
        finally:
            if self._cleanup:
                self.cleanup()

    def cleanup(self) -> None:
        for temp_dir in list(self._owned_temp_dirs):
            self._cleanup_dir(temp_dir)
        self._owned_temp_dirs.clear()
        self._temp_dirs.clear()

    @staticmethod
    def _cleanup_dir(path: str | Path) -> None:
        shutil.rmtree(str(path), ignore_errors=True)

    @staticmethod
    def _is_symlink(info: zipfile.ZipInfo) -> bool:
        mode = (info.external_attr >> 16) & 0xFFFF
        return stat.S_ISLNK(mode)

    def _safe_extract(self, zip_path: Path, target_dir: str) -> Path:
        target = Path(target_dir).resolve()
        try:
            with zipfile.ZipFile(zip_path, "r") as archive:
                infos = archive.infolist()
                file_count = sum(1 for info in infos if not info.is_dir())
                if file_count > self._max_file_count:
                    raise RuntimeError(
                        f"ZIP contains too many files: {file_count} (limit: {self._max_file_count})"
                    )

                for info in infos:
                    name = info.filename.replace("\\", "/")
                    pure = PurePosixPath(name)
                    if pure.is_absolute() or ".." in pure.parts:
                        raise RuntimeError(f"Unsafe ZIP entry (path traversal): {info.filename}")
                    if self._is_symlink(info):
                        raise RuntimeError(f"Unsafe ZIP entry (symbolic link): {info.filename}")
                    destination = (target / Path(*pure.parts)).resolve()
                    try:
                        destination.relative_to(target)
                    except ValueError as exc:
                        raise RuntimeError(f"Unsafe ZIP entry outside target: {info.filename}") from exc

                # Extraction is safe after every member has been validated.
                archive.extractall(target)
        except zipfile.BadZipFile as exc:
            raise RuntimeError(f"Invalid ZIP archive: {exc}") from exc

        top_level = [p for p in target.iterdir() if p.is_dir() and not p.name.startswith(".")]
        top_files = [p for p in target.iterdir() if p.is_file()]
        return top_level[0] if len(top_level) == 1 and not top_files else target

    def _scan_directory(self, root: Path) -> list[Path]:
        from ingest.language_router import is_supported_file

        root = Path(root)
        files: list[Path] = []
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            relative_parts = path.relative_to(root).parts[:-1]
            if any(part in IGNORED_DIRS for part in relative_parts):
                continue
            if is_supported_file(str(path)):
                files.append(path)
        return sorted(files)


def load_zip(zip_path: str | Path, loader: ZipLoader | None = None) -> tuple[Path, list[Path]]:
    loader = loader or ZipLoader()
    return loader.load_zip(zip_path)
