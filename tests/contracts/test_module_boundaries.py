"""
Tests for module boundary enforcement.

Verifies that forbidden cross-module imports are not present.
"""

import ast
from pathlib import Path
import pytest


class TestModuleBoundaries:
    """Tests for module boundary enforcement."""
    
    def test_analyzers_do_not_import_agents(self):
        """Test that analyzers/ does not import agents."""
        project_root = Path(__file__).parent.parent.parent
        analyzers_dir = project_root / "analyzers"
        
        violations = []
        
        if analyzers_dir.exists():
            for py_file in analyzers_dir.rglob("*.py"):
                if py_file.name == "__init__.py":
                    continue
                
                imports = self._extract_imports(py_file)
                
                for imp in imports:
                    if "agents" in imp:
                        violations.append(f"{py_file}: imports '{imp}'")
        
        assert len(violations) == 0, f"Found forbidden imports: {violations}"
    
    def test_analyzers_do_not_import_llm(self):
        """Test that analyzers/ does not import llm."""
        project_root = Path(__file__).parent.parent.parent
        analyzers_dir = project_root / "analyzers"
        
        violations = []
        
        if analyzers_dir.exists():
            for py_file in analyzers_dir.rglob("*.py"):
                if py_file.name == "__init__.py":
                    continue
                
                imports = self._extract_imports(py_file)
                
                for imp in imports:
                    if imp == "llm" or imp.startswith("llm."):
                        violations.append(f"{py_file}: imports '{imp}'")
        
        assert len(violations) == 0, f"Found forbidden imports: {violations}"
    
    def test_api_does_not_import_analyzers_directly(self):
        """Test that api/ does not directly import analyzers."""
        project_root = Path(__file__).parent.parent.parent
        api_dir = project_root / "api"
        
        violations = []
        forbidden_patterns = [
            "analyzers.pattern_analyzer",
            "analyzers.ast_analyzer",
            "analyzers.taint"
        ]
        
        if api_dir.exists():
            for py_file in api_dir.rglob("*.py"):
                if py_file.name == "__init__.py":
                    continue
                
                imports = self._extract_imports(py_file)
                
                for imp in imports:
                    for pattern in forbidden_patterns:
                        if pattern in imp:
                            violations.append(f"{py_file}: imports '{imp}'")
        
        assert len(violations) == 0, f"Found forbidden imports: {violations}"
    
    def test_api_does_not_import_agents_directly(self):
        """Test that api/ does not directly import agents."""
        project_root = Path(__file__).parent.parent.parent
        api_dir = project_root / "api"
        
        violations = []
        forbidden_patterns = [
            "agents.recon_agent",
            "agents.analysis_agent",
            "agents.judge_agent"
        ]
        
        if api_dir.exists():
            for py_file in api_dir.rglob("*.py"):
                if py_file.name == "__init__.py":
                    continue
                
                imports = self._extract_imports(py_file)
                
                for imp in imports:
                    for pattern in forbidden_patterns:
                        if pattern in imp:
                            violations.append(f"{py_file}: imports '{imp}'")
        
        assert len(violations) == 0, f"Found forbidden imports: {violations}"
    
    def test_audit_core_models_exists(self):
        """Test that audit_core/models.py exists and is importable."""
        try:
            from audit_core.models import CodeUnit, RawFinding, AuditResult
            assert True
        except ImportError as e:
            pytest.fail(f"Failed to import from audit_core.models: {e}")
    
    def test_orchestrator_exists(self):
        """Test that AuditOrchestrator exists and is importable."""
        try:
            from audit_core.orchestrator import AuditOrchestrator
            assert True
        except ImportError as e:
            pytest.fail(f"Failed to import AuditOrchestrator: {e}")
    
    def _extract_imports(self, file_path: Path) -> list:
        """Extract all imports from a Python file."""
        imports = []
        
        try:
            content = file_path.read_text()
            tree = ast.parse(content)
            
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        imports.append(alias.name)
                elif isinstance(node, ast.ImportFrom):
                    module = node.module or ""
                    imports.append(module)
                    for alias in node.names:
                        imports.append(f"{module}.{alias.name}")
        except SyntaxError:
            pass
        
        return imports


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
