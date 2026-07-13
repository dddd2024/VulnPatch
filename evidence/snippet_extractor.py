"""
Code snippet extractor for evidence building.

Extracts relevant code snippets around vulnerability locations.
"""

from audit_core.models import CodeUnit


def extract_snippet(
    code_unit: CodeUnit,
    start_line: int,
    end_line: int | None = None,
    context_lines: int = 3
) -> dict:
    """
    Extract a code snippet with context.
    
    Args:
        code_unit: The code unit containing the snippet
        start_line: Starting line of the vulnerable code
        end_line: Ending line of the vulnerable code (optional)
        context_lines: Number of context lines to include before and after
        
    Returns:
        Dictionary with snippet information:
        - file_path: Path to the file
        - start_line: Starting line number (with context)
        - end_line: Ending line number (with context)
        - content: The snippet content
        - vulnerability_start: Line where vulnerability starts
        - vulnerability_end: Line where vulnerability ends
    """
    if end_line is None:
        end_line = start_line
    
    # Calculate context boundaries
    snippet_start = max(1, start_line - context_lines)
    snippet_end = min(code_unit.end_line or len(code_unit.content.split("\n")), end_line + context_lines)
    
    # Get content lines
    lines = code_unit.content.split("\n")
    
    # Handle edge cases
    if not lines or start_line < 1 or start_line > len(lines):
        return {
            "file_path": code_unit.path,
            "start_line": start_line,
            "end_line": end_line,
            "content": "",
            "vulnerability_start": start_line,
            "vulnerability_end": end_line
        }
    
    # Extract snippet lines (1-indexed to 0-indexed)
    snippet_lines = lines[snippet_start - 1:snippet_end]
    content = "\n".join(snippet_lines)
    
    return {
        "file_path": code_unit.path,
        "start_line": snippet_start,
        "end_line": snippet_end,
        "content": content,
        "vulnerability_start": start_line,
        "vulnerability_end": end_line
    }
