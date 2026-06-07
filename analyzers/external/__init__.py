"""
External tool analyzers for VulnPatch.

Integrates industry-standard security tools (Semgrep, Bandit, ESLint Security)
into the VulnPatch audit pipeline. Each tool is wrapped as a BaseAnalyzer
subclass, so results flow naturally into the existing pipeline
(Merge → Analysis Agent → Judge Agent → Evidence).

Tools are invoked via their CLI and JSON output is parsed into RawFinding objects.
If a tool is not installed, the analyzer gracefully skips (no crash).

Usage:
    Tools are auto-registered by register_builtin_analyzers().
    No code changes needed in orchestrator or pipeline.
"""
