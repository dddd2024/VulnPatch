"""
Tests for data model contracts.

Verifies that core data models can be serialized to JSON and conform to JSON Schema.
"""

import json
import pytest
from pathlib import Path
from jsonschema import validate, ValidationError
from audit_core.models import (
    CodeUnit, RawFinding, AgentHypothesis, AgentLog,
    JudgeDecision, EvidenceBundle, AuditSummary, AuditResult
)


def load_schema(schema_name: str) -> dict:
    """Load JSON Schema from contracts directory."""
    schema_path = Path(__file__).parent.parent.parent / "contracts" / schema_name
    with open(schema_path, "r", encoding="utf-8") as f:
        return json.load(f)


def validate_with_refs(instance: dict, schema_name: str) -> None:
    """Validate instance against schema with proper reference resolution."""
    from jsonschema import Draft7Validator
    from referencing import Registry, Resource
    from pathlib import Path
    import json
    
    contracts_dir = Path(__file__).parent.parent.parent / "contracts"
    
    # Load all schemas into a registry
    schemas = {}
    for schema_file in contracts_dir.glob("*.schema.json"):
        with open(schema_file, "r", encoding="utf-8") as f:
            schemas[schema_file.name] = json.load(f)
    
    # Get the main schema
    schema = schemas[schema_name]
    
    # Build registry with all schemas
    registry = Registry()
    for name, s in schemas.items():
        uri = f"https://vulnpatch.local/schemas/{name}"
        registry = registry.with_resource(uri, Resource.from_contents(s))
    
    validator = Draft7Validator(schema, registry=registry)
    validator.validate(instance)


class TestCodeUnitContract:
    """Tests for CodeUnit serialization."""
    
    def test_code_unit_serializable(self):
        """Test that CodeUnit can be serialized to JSON."""
        unit = CodeUnit(
            path="test.py",
            language="python",
            content="def hello(): pass",
            start_line=1,
            end_line=3
        )
        
        # Should not raise
        data = unit.model_dump(mode="json")
        
        # Verify structure
        assert "id" in data
        assert data["path"] == "test.py"
        assert data["language"] == "python"
        assert data["content"] == "def hello(): pass"
        assert data["start_line"] == 1
        assert data["end_line"] == 3
        
        # Should be JSON serializable
        json_str = json.dumps(data)
        assert isinstance(json_str, str)
    
    def test_code_unit_conforms_to_schema(self):
        """Test that CodeUnit conforms to code_unit.schema.json."""
        unit = CodeUnit(
            path="test.py",
            language="python",
            content="def hello(): pass",
            start_line=1,
            end_line=3
        )
        
        data = unit.model_dump(mode="json")
        schema = load_schema("code_unit.schema.json")
        validate(instance=data, schema=schema)


class TestRawFindingContract:
    """Tests for RawFinding serialization."""
    
    def test_raw_finding_serializable(self):
        """Test that RawFinding can be serialized to JSON."""
        finding = RawFinding(
            rule_id="TEST_001",
            type="SQL Injection",
            severity="ERROR",
            confidence="high",
            file_path="test.py",
            start_line=10,
            message="Possible SQL injection",
            engine="pattern"
        )
        
        # Should not raise
        data = finding.model_dump(mode="json")
        
        # Verify structure
        assert "id" in data
        assert data["rule_id"] == "TEST_001"
        assert data["type"] == "SQL Injection"
        assert data["severity"] == "ERROR"
        assert data["confidence"] == "high"
        assert data["file_path"] == "test.py"
        assert data["start_line"] == 10
        assert data["message"] == "Possible SQL injection"
        assert data["engine"] == "pattern"
        
        # Should be JSON serializable
        json_str = json.dumps(data)
        assert isinstance(json_str, str)
    
    def test_raw_finding_conforms_to_schema(self):
        """Test that RawFinding conforms to raw_finding.schema.json."""
        finding = RawFinding(
            rule_id="TEST_001",
            type="SQL Injection",
            severity="ERROR",
            confidence="high",
            file_path="test.py",
            start_line=10,
            message="Possible SQL injection",
            engine="pattern"
        )
        
        data = finding.model_dump(mode="json")
        schema = load_schema("raw_finding.schema.json")
        validate(instance=data, schema=schema)


class TestEvidenceBundleContract:
    """Tests for EvidenceBundle serialization."""
    
    def test_evidence_bundle_serializable(self):
        """Test that EvidenceBundle can be serialized to JSON."""
        finding = RawFinding(
            rule_id="TEST_001",
            type="SQL Injection",
            severity="ERROR",
            confidence="high",
            file_path="test.py",
            start_line=10,
            message="Possible SQL injection",
            engine="pattern"
        )
        
        bundle = EvidenceBundle(
            finding=finding,
            snippets=[],
            agent_hypotheses=[],
            agent_logs=[]
        )
        
        # Should not raise
        data = bundle.model_dump(mode="json")
        
        # Verify structure
        assert "id" in data
        assert "finding" in data
        assert "snippets" in data
        assert "agent_hypotheses" in data
        assert "agent_logs" in data
        
        # Should be JSON serializable
        json_str = json.dumps(data)
        assert isinstance(json_str, str)
    
    def test_evidence_bundle_conforms_to_schema(self):
        """Test that EvidenceBundle conforms to evidence_bundle.schema.json."""
        from audit_core.models import CodeUnit
        
        code_unit = CodeUnit(
            path="test.py",
            language="python",
            content="def test(): pass",
            start_line=1
        )
        
        finding = RawFinding(
            rule_id="TEST_001",
            type="SQL Injection",
            severity="ERROR",
            confidence="high",
            file_path="test.py",
            start_line=10,
            message="Possible SQL injection",
            engine="pattern"
        )
        
        bundle = EvidenceBundle(
            finding=finding,
            code_unit=code_unit,
            snippets=[],
            agent_hypotheses=[],
            agent_logs=[]
        )
        
        data = bundle.model_dump(mode="json")
        validate_with_refs(data, "evidence_bundle.schema.json")


class TestAuditResultContract:
    """Tests for AuditResult serialization."""
    
    def test_audit_result_serializable(self):
        """Test that AuditResult can be serialized to JSON."""
        summary = AuditSummary(
            total_code_units=1,
            total_findings=0,
            total_evidence_bundles=0,
            risk_score=0.0,
            languages=["python"],
            scanned_files=["test.py"]
        )
        
        result = AuditResult(
            summary=summary,
            findings=[],
            evidence=[],
            agent_logs=[]
        )
        
        # Should not raise
        data = result.model_dump(mode="json")
        
        # Verify structure
        assert "summary" in data
        assert "findings" in data
        assert "evidence" in data
        assert "agent_logs" in data
        
        # Verify summary fields
        summary_data = data["summary"]
        assert summary_data["total_code_units"] == 1
        assert summary_data["total_findings"] == 0
        assert summary_data["total_evidence_bundles"] == 0
        assert summary_data["risk_score"] == 0.0
        assert summary_data["languages"] == ["python"]
        assert summary_data["scanned_files"] == ["test.py"]
        
        # Should be JSON serializable
        json_str = json.dumps(data)
        assert isinstance(json_str, str)
    
    def test_audit_result_conforms_to_schema(self):
        """Test that AuditResult conforms to audit_result.schema.json."""
        summary = AuditSummary(
            total_code_units=1,
            total_findings=0,
            total_evidence_bundles=0,
            risk_score=0.0,
            languages=["python"],
            scanned_files=["test.py"]
        )
        
        result = AuditResult(
            summary=summary,
            findings=[],
            evidence=[],
            agent_logs=[]
        )
        
        data = result.model_dump(mode="json")
        validate_with_refs(data, "audit_result.schema.json")


class TestModelRequiredFields:
    """Tests for model required fields."""
    
    def test_code_unit_required_fields(self):
        """Test that CodeUnit has all required fields."""
        unit = CodeUnit(
            path="test.py",
            language="python",
            content="def test(): pass",
            start_line=1
        )
        
        data = unit.model_dump(mode="json")
        required = ["id", "path", "language", "content", "start_line"]
        for field in required:
            assert field in data, f"Missing required field: {field}"
    
    def test_raw_finding_required_fields(self):
        """Test that RawFinding has all required fields."""
        finding = RawFinding(
            rule_id="TEST_001",
            type="SQL Injection",
            severity="ERROR",
            confidence="high",
            file_path="test.py",
            start_line=10,
            message="Test message",
            engine="pattern"
        )
        
        data = finding.model_dump(mode="json")
        required = ["id", "rule_id", "type", "severity", "confidence", 
                   "file_path", "start_line", "message", "engine"]
        for field in required:
            assert field in data, f"Missing required field: {field}"
    
    def test_audit_result_required_fields(self):
        """Test that AuditResult has all required fields."""
        summary = AuditSummary(
            total_code_units=1,
            total_findings=0,
            total_evidence_bundles=0,
            risk_score=0.0,
            languages=[],
            scanned_files=[]
        )
        
        result = AuditResult(
            summary=summary,
            findings=[],
            evidence=[],
            agent_logs=[]
        )
        
        data = result.model_dump(mode="json")
        required = ["summary", "findings", "evidence", "agent_logs"]
        for field in required:
            assert field in data, f"Missing required field: {field}"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
