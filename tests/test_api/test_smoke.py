"""
Smoke tests for API module.

API / Report / UI member is responsible for:
  - api/
  - report/
  - ui/
"""

import pytest
from fastapi.testclient import TestClient


class TestAPISmoke:
    """Smoke tests for API — verify endpoints return expected fields."""

    @pytest.fixture(autouse=True)
    def _client(self):
        from api.server import app
        return TestClient(app)

    def test_health_endpoint(self, _client):
        """GET /health should return status ok."""
        resp = _client.get("/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"

    def test_scan_returns_scan_id(self, _client):
        """POST /scan should return scan_id field."""
        resp = _client.post("/scan", json={
            "input_type": "code",
            "code": "def test(): pass",
            "language": "python",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert "scan_id" in data
        assert isinstance(data["scan_id"], str)

    def test_scan_returns_summary(self, _client):
        """POST /scan should return summary field."""
        resp = _client.post("/scan", json={
            "input_type": "code",
            "code": "def test(): pass",
            "language": "python",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert "summary" in data
        assert "total_findings" in data["summary"]

    def test_scan_returns_findings(self, _client):
        """POST /scan should return findings field."""
        resp = _client.post("/scan", json={
            "input_type": "code",
            "code": "def test(): pass",
            "language": "python",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert "findings" in data
        assert isinstance(data["findings"], list)

    def test_scan_returns_evidence(self, _client):
        """POST /scan should return evidence field."""
        resp = _client.post("/scan", json={
            "input_type": "code",
            "code": "def test(): pass",
            "language": "python",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert "evidence" in data
        assert isinstance(data["evidence"], list)

    def test_scan_returns_agent_logs(self, _client):
        """POST /scan should return agent_logs field."""
        resp = _client.post("/scan", json={
            "input_type": "code",
            "code": "def test(): pass",
            "language": "python",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert "agent_logs" in data
        assert isinstance(data["agent_logs"], list)

    def test_scan_unique_ids(self, _client):
        """Consecutive scans should return different scan_ids."""
        resp1 = _client.post("/scan", json={
            "input_type": "code",
            "code": "def a(): pass",
            "language": "python",
        })
        resp2 = _client.post("/scan", json={
            "input_type": "code",
            "code": "def b(): pass",
            "language": "python",
        })
        assert resp1.json()["scan_id"] != resp2.json()["scan_id"]

    def test_legacy_findings_endpoint(self, _client):
        """GET /findings should return latest scan findings."""
        _client.post("/scan", json={
            "input_type": "code",
            "code": "def test(): pass",
            "language": "python",
        })
        resp = _client.get("/findings")
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    def test_scan_by_id_not_found(self, _client):
        """GET /scans/{invalid_id}/findings should return 404."""
        resp = _client.get("/scans/nonexistent123/findings")
        assert resp.status_code == 404
