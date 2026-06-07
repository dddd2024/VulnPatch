"""
Language router for detecting programming languages from file paths.

This module provides functions to identify programming languages
based on file extensions.
"""

from pathlib import Path


# Mapping of file extensions to programming languages
EXTENSION_MAP = {
    # Python
    ".py": "python",
    ".pyw": "python",
    ".pyi": "python",
    # JavaScript
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    # TypeScript
    ".ts": "typescript",
    ".tsx": "typescript",
    ".mts": "typescript",
    ".cts": "typescript",
    # Java
    ".java": "java",
    # C
    ".c": "c",
    ".h": "c",
    # C++
    ".cpp": "cpp",
    ".cc": "cpp",
    ".cxx": "cpp",
    ".hpp": "cpp",
    ".hh": "cpp",
    # Go
    ".go": "go",
    # Rust
    ".rs": "rust",
    # PHP
    ".php": "php",
    ".phtml": "php",
}


def detect_language_by_path(path: str) -> str:
    """
    Detect programming language from a file path.
    
    Args:
        path: File path to analyze
        
    Returns:
        Programming language name or "unknown" if not recognized
        
    Examples:
        >>> detect_language_by_path("src/main.py")
        'python'
        >>> detect_language_by_path("app.js")
        'javascript'
        >>> detect_language_by_path("README.md")
        'unknown'
    """
    ext = Path(path).suffix.lower()
    return EXTENSION_MAP.get(ext, "unknown")


def get_supported_extensions() -> list[str]:
    """
    Get list of supported file extensions.
    
    Returns:
        List of supported file extensions
    """
    return list(EXTENSION_MAP.keys())


def is_supported_file(path: str) -> bool:
    """
    Check if a file path has a supported extension.
    
    Args:
        path: File path to check
        
    Returns:
        True if the file extension is supported
    """
    return detect_language_by_path(path) != "unknown"
