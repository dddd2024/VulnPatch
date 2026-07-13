"""
Smoke tests for analyzers module.

Analyzer & Taint Engine member is responsible for:
  - analyzers/
  - analyzers/taint/
"""

import pytest


class TestAnalyzersSmoke:
    """Smoke tests for analyzers — verify registry and basic analysis."""

    def test_default_registry_has_analyzers(self):
        """Default registry should contain multiple analyzers."""
        from audit_core.registry import build_default_registry
        r = build_default_registry()
        analyzers = r.get_analyzers()
        assert len(analyzers) >= 5

    def test_python_analyzer_registered(self):
        """PythonAnalyzer should be in default registry."""
        from audit_core.registry import build_default_registry
        r = build_default_registry()
        pa = r.get("python")
        assert pa is not None

    def test_pattern_analyzer_registered(self):
        """PatternAnalyzer should be in default registry."""
        from audit_core.registry import build_default_registry
        r = build_default_registry()
        pa = r.get("pattern")
        assert pa is not None

    def test_analyzer_returns_raw_findings(self):
        """Analyzer should return list of RawFinding on analyze()."""
        from audit_core.registry import build_default_registry
        from audit_core.models import CodeUnit
        r = build_default_registry()
        analyzers = r.get_analyzers_for_language("python")
        assert len(analyzers) > 0

        unit = CodeUnit(path="test.py", language="python", content="x=1")
        for a in analyzers:
            # All analyzers expect list of CodeUnits
            findings = a.analyze([unit])
            assert isinstance(findings, list)

    def test_analyzer_does_not_import_agents(self):
        """Analyzer module should not import agents."""
        import analyzers.pattern_analyzer as mod
        source = open(mod.__file__, encoding="utf-8").read()
        assert "from agents" not in source
        assert "import agents" not in source

    def test_taint_analyzer_registered(self):
        """TaintAnalyzer should be in default registry."""
        from audit_core.registry import build_default_registry
        r = build_default_registry()
        ta = r.get("taint")
        assert ta is not None

    def test_java_analyzer_registered(self):
        """JavaPatternAnalyzer should be in default registry."""
        from audit_core.registry import build_default_registry
        r = build_default_registry()
        ja = r.get("java_pattern")
        assert ja is not None

    def test_js_analyzer_registered(self):
        """JSPatternAnalyzer should be in default registry."""
        from audit_core.registry import build_default_registry
        r = build_default_registry()
        jsa = r.get("js_pattern")
        assert jsa is not None

    def test_c_analyzer_registered(self):
        """CPatternAnalyzer should be in default registry."""
        from audit_core.registry import build_default_registry
        r = build_default_registry()
        ca = r.get("c_pattern")
        assert ca is not None
