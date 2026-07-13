"""
Code unit builder for constructing CodeUnit objects from files and snippets.
"""

from pathlib import Path
from audit_core.models import CodeUnit
from ingest.language_router import detect_language_by_path


def build_code_unit_from_file(path: Path, root: Path | None = None) -> CodeUnit:
    """
    Build a CodeUnit from a file.
    
    Args:
        path: Path to the file
        root: Optional root directory for calculating relative paths
        
    Returns:
        CodeUnit representing the file
        
    Raises:
        FileNotFoundError: If the file doesn't exist
        UnicodeDecodeError: If the file can't be decoded as text
    """
    path = Path(path)
    
    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")
    
    # Read file content
    content = path.read_text(encoding="utf-8", errors="replace")
    
    # Determine relative path
    if root:
        try:
            file_path = str(path.relative_to(root))
        except ValueError:
            file_path = str(path)
    else:
        file_path = str(path)
    
    # Detect language
    language = detect_language_by_path(str(path))
    
    # Count lines
    lines = content.split("\n")
    end_line = len(lines)
    
    return CodeUnit(
        path=file_path,
        language=language,
        content=content,
        start_line=1,
        end_line=end_line,
        metadata={
            "absolute_path": str(path.absolute()),
            "size_bytes": path.stat().st_size
        }
    )


def build_code_unit_from_snippet(code: str, language_hint: str | None = None) -> CodeUnit:
    """
    Build a CodeUnit from a code snippet.
    
    Args:
        code: The code snippet
        language_hint: Optional language hint (e.g., "python", "javascript")
        
    Returns:
        CodeUnit representing the snippet
    """
    language = language_hint or "unknown"
    lines = code.split("\n")
    end_line = len(lines)
    
    return CodeUnit(
        path="<snippet>",
        language=language,
        content=code,
        start_line=1,
        end_line=end_line,
        metadata={
            "is_snippet": True,
            "line_count": end_line
        }
    )
