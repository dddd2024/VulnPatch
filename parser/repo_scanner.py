from pathlib import Path
from typing import Iterable

SUPPORTED = (".py", ".js", ".java", ".ts")


def scan_repo(root: str = "repo", exts: Iterable[str] = SUPPORTED) -> list[str]:
    base = Path(root)
    if not base.exists():
        raise FileNotFoundError(f"Repository path does not exist: {base}")
    files: list[str] = []
    for path in base.rglob("*"):
        if path.is_file() and path.suffix in exts:
            files.append(str(path))
    return files

