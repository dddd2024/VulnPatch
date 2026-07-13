"""
Tests for /scan API response contract.

Verifies that /scan returns all required fields and conforms to JSON Schema.
"""

import json
import pytest
from pathlib import Path
from jsonschema import validate, ValidationError
from fastapi.testclient import TestClient

from api.server import app
from audit_core.orchestrator import AuditOrchestrator
from audit_core.models import AuditResult


client = TestClient(app)


def load_schema(schema_name: str) -> dict:
    """Load JSON Schema from contracts directory."""
    schema_path = Path(__file__).parent.parent.parent / "contracts" / schema_name
    with open(schema_path, "r", encoding="utf-8") as f:
        return json.load(f)


class TestScanResponseContract:
    """Tests for /scan response structure."""

    def test_scan_api_returns_valid_schema(self):
        """Test that POST /scan returns valid response conforming to JSON Schema."""
        code = 'def get_user(user_id):\n    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")'
        resp = client.post("/scan", json={
            "input_type": "code",
            "code": code,
            "language": "python",
        })
        assert resp.status_code == 200
        data = resp.json()

        # Load and validate against JSON Schema
        schema = load_schema("scan_response.schema.json")
        validate(instance=data, schema=schema)

    def test_scan_api_returns_scan_id(self):
        """Test that /scan returns scan_id field."""
        resp = client.post("/scan", json={
            "input_type": "code",
            "code": "def test(): pass",
            "language": "python",
        })
        assert resp.status_code == 200
        data = resp.json()

        assert "scan_id" in data
        assert isinstance(data["scan_id"], str)
        assert len(data["scan_id"]) > 0

    def test_scan_api_returns_unique_scan_ids(self):
        """Test that consecutive scans return different scan_ids."""
        resp1 = client.post("/scan", json={
            "input_type": "code",
            "code": "def test1(): pass",
            "language": "python",
        })
        resp2 = client.post("/scan", json={
            "input_type": "code",
            "code": "def test2(): pass",
            "language": "python",
        })

        assert resp1.status_code == 200
        assert resp2.status_code == 200

        scan_id1 = resp1.json()["scan_id"]
        scan_id2 = resp2.json()["scan_id"]

        assert scan_id1 != scan_id2

    def test_scan_api_returns_summary(self):
        """Test that /scan returns summary field."""
        resp = client.post("/scan", json={
            "input_type": "code",
            "code": "def test(): pass",
            "language": "python",
        })
        assert resp.status_code == 200
        data = resp.json()

        assert "summary" in data
        summary = data["summary"]
        assert "total_code_units" in summary
        assert "total_findings" in summary
        assert "total_evidence_bundles" in summary
        assert "risk_score" in summary
        assert "languages" in summary
        assert "scanned_files" in summary

    def test_scan_api_returns_findings(self):
        """Test that /scan returns findings field."""
        resp = client.post("/scan", json={
            "input_type": "code",
            "code": "def test(): pass",
            "language": "python",
        })
        assert resp.status_code == 200
        data = resp.json()

        assert "findings" in data
        assert isinstance(data["findings"], list)

    def test_scan_api_returns_evidence(self):
        """Test that /scan returns evidence field."""
        resp = client.post("/scan", json={
            "input_type": "code",
            "code": "def test(): pass",
            "language": "python",
        })
        assert resp.status_code == 200
        data = resp.json()

        assert "evidence" in data
        assert isinstance(data["evidence"], list)

    def test_scan_api_returns_agent_logs(self):
        """Test that /scan returns agent_logs field."""
        resp = client.post("/scan", json={
            "input_type": "code",
            "code": "def test(): pass",
            "language": "python",
        })
        assert resp.status_code == 200
        data = resp.json()

        assert "agent_logs" in data
        assert isinstance(data["agent_logs"], list)

    def test_scan_api_with_vulnerability(self):
        """Test scan response with actual vulnerability."""
        code = 'def get_user(user_id):\n    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")'
        resp = client.post("/scan", json={
            "input_type": "code",
            "code": code,
            "language": "python",
        })
        assert resp.status_code == 200
        data = resp.json()

        # Verify all required fields present
        assert "scan_id" in data
        assert "summary" in data
        assert "findings" in data
        assert "evidence" in data
        assert "agent_logs" in data

        # Verify summary fields
        summary = data["summary"]
        assert summary["total_code_units"] == 1
        assert summary["total_findings"] >= 0
        assert summary["total_evidence_bundles"] >= 0
        assert isinstance(summary["risk_score"], (int, float))
        assert isinstance(summary["languages"], list)
        assert isinstance(summary["scanned_files"], list)


class TestScanSessionEndpoints:
    """Tests for scan session endpoints (/scans/{scan_id}/*)."""

    def test_get_scan_findings_by_id(self):
        """Test GET /scans/{scan_id}/findings returns correct findings."""
        # Create a scan
        resp = client.post("/scan", json={
            "input_type": "code",
            "code": "def test(): pass",
            "language": "python",
        })
        assert resp.status_code == 200
        scan_id = resp.json()["scan_id"]

        # Get findings by scan_id
        findings_resp = client.get(f"/scans/{scan_id}/findings")
        assert findings_resp.status_code == 200
        assert isinstance(findings_resp.json(), list)

    def test_get_scan_evidence_by_id(self):
        """Test GET /scans/{scan_id}/evidence returns correct evidence."""
        resp = client.post("/scan", json={
            "input_type": "code",
            "code": "def test(): pass",
            "language": "python",
        })
        scan_id = resp.json()["scan_id"]

        evidence_resp = client.get(f"/scans/{scan_id}/evidence")
        assert evidence_resp.status_code == 200
        assert isinstance(evidence_resp.json(), list)

    def test_get_scan_agent_logs_by_id(self):
        """Test GET /scans/{scan_id}/agents/logs returns correct logs."""
        resp = client.post("/scan", json={
            "input_type": "code",
            "code": "def test(): pass",
            "language": "python",
        })
        scan_id = resp.json()["scan_id"]

        logs_resp = client.get(f"/scans/{scan_id}/agents/logs")
        assert logs_resp.status_code == 200
        assert isinstance(logs_resp.json(), list)

    def test_get_scan_report_json_by_id(self):
        """Test GET /scans/{scan_id}/report/json returns correct report."""
        resp = client.post("/scan", json={
            "input_type": "code",
            "code": "def test(): pass",
            "language": "python",
        })
        scan_id = resp.json()["scan_id"]

        report_resp = client.get(f"/scans/{scan_id}/report/json")
        assert report_resp.status_code == 200
        assert "summary" in report_resp.json()

    def test_get_scan_not_found(self):
        """Test 404 returned for non-existent scan_id."""
        resp = client.get("/scans/nonexistent123/findings")
        assert resp.status_code == 404
        assert "not found" in resp.json()["detail"].lower()

    def test_multiple_scans_isolated(self):
        """Test that multiple scans have isolated results."""
        # First scan
        resp1 = client.post("/scan", json={
            "input_type": "code",
            "code": "def scan1(): pass",
            "language": "python",
        })
        scan_id1 = resp1.json()["scan_id"]

        # Second scan
        resp2 = client.post("/scan", json={
            "input_type": "code",
            "code": "def scan2(): x = 1",
            "language": "python",
        })
        scan_id2 = resp2.json()["scan_id"]

        # Verify different scan_ids
        assert scan_id1 != scan_id2

        # Verify both can be accessed
        assert client.get(f"/scans/{scan_id1}/findings").status_code == 200
        assert client.get(f"/scans/{scan_id2}/findings").status_code == 200


class TestLegacyEndpointsBackwardCompatibility:
    """Tests that legacy endpoints still work (backward compatibility)."""

    def test_legacy_findings_returns_latest(self):
        """Test GET /findings still returns latest scan results."""
        # Create a scan
        resp = client.post("/scan", json={
            "input_type": "code",
            "code": "def test(): pass",
            "language": "python",
        })
        assert resp.status_code == 200

        # Legacy endpoint should work
        findings_resp = client.get("/findings")
        assert findings_resp.status_code == 200
        assert isinstance(findings_resp.json(), list)

    def test_legacy_evidence_returns_latest(self):
        """Test GET /evidence still returns latest scan results."""
        client.post("/scan", json={
            "input_type": "code",
            "code": "def test(): pass",
            "language": "python",
        })

        evidence_resp = client.get("/evidence")
        assert evidence_resp.status_code == 200
        assert isinstance(evidence_resp.json(), list)

    def test_legacy_agents_logs_returns_latest(self):
        """Test GET /agents/logs still returns latest scan results."""
        client.post("/scan", json={
            "input_type": "code",
            "code": "def test(): pass",
            "language": "python",
        })

        logs_resp = client.get("/agents/logs")
        assert logs_resp.status_code == 200
        assert isinstance(logs_resp.json(), list)

    def test_legacy_report_json_returns_latest(self):
        """Test GET /report/json still returns latest scan results."""
        client.post("/scan", json={
            "input_type": "code",
            "code": "def test(): pass",
            "language": "python",
        })

        report_resp = client.get("/report/json")
        assert report_resp.status_code == 200
        assert "summary" in report_resp.json()


class TestOrchestratorResponseContract:
    """Tests for orchestrator response structure (direct call)."""

    def test_scan_returns_summary(self):
        """Test that scan returns summary field."""
        orchestrator = AuditOrchestrator()
        result = orchestrator.scan_code("def test(): pass", language="python")

        data = result.model_dump(mode="json")
        assert "summary" in data

        summary = data["summary"]
        assert "total_code_units" in summary
        assert "total_findings" in summary
        assert "total_evidence_bundles" in summary
        assert "risk_score" in summary
        assert "languages" in summary
        assert "scanned_files" in summary

    def test_scan_returns_findings(self):
        """Test that scan returns findings field."""
        orchestrator = AuditOrchestrator()
        result = orchestrator.scan_code("def test(): pass", language="python")

        data = result.model_dump(mode="json")
        assert "findings" in data
        assert isinstance(data["findings"], list)

    def test_scan_returns_evidence(self):
        """Test that scan returns evidence field."""
        orchestrator = AuditOrchestrator()
        result = orchestrator.scan_code("def test(): pass", language="python")

        data = result.model_dump(mode="json")
        assert "evidence" in data
        assert isinstance(data["evidence"], list)

    def test_scan_returns_agent_logs(self):
        """Test that scan returns agent_logs field."""
        orchestrator = AuditOrchestrator()
        result = orchestrator.scan_code("def test(): pass", language="python")

        data = result.model_dump(mode="json")
        assert "agent_logs" in data
        assert isinstance(data["agent_logs"], list)


class TestScanResponseFieldTypes:
    """Tests for /scan response field types."""

    def test_summary_field_types(self):
        """Test that summary fields have correct types."""
        resp = client.post("/scan", json={
            "input_type": "code",
            "code": "def test(): pass",
            "language": "python",
        })
        assert resp.status_code == 200
        data = resp.json()
        summary = data["summary"]

        assert isinstance(summary["total_code_units"], int)
        assert isinstance(summary["total_findings"], int)
        assert isinstance(summary["total_evidence_bundles"], int)
        assert isinstance(summary["risk_score"], (int, float))
        assert isinstance(summary["languages"], list)
        assert isinstance(summary["scanned_files"], list)

    def test_scan_id_field_type(self):
        """Test that scan_id is a string."""
        resp = client.post("/scan", json={
            "input_type": "code",
            "code": "def test(): pass",
            "language": "python",
        })
        assert resp.status_code == 200
        data = resp.json()

        assert isinstance(data["scan_id"], str)
        assert len(data["scan_id"]) == 12  # UUID first 12 chars


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
