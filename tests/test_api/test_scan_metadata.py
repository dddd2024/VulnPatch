"""
Tests for new scan metadata and analyzer-info endpoints.

Verifies:
1. GET /scans/{scan_id}/metadata returns metadata dict
2. GET /scans/{scan_id}/analyzer-info returns analyzer_runs, analyzer_errors, skipped_languages
3. Non-existent scan_id returns 404
4. /scan original fields are still present
"""

import pytest
from fastapi.testclient import TestClient


class TestScanMetadataEndpoints:
    """Tests for /scans/{scan_id}/metadata and /scans/{scan_id}/analyzer-info."""

    @pytest.fixture(autouse=True)
    def _client(self):
        from api.server import app
        return TestClient(app)

    def _create_scan(self, _client, code="def test(): pass", language="python"):
        """Helper: POST /scan and return scan_id."""
        resp = _client.post("/scan", json={
            "input_type": "code",
            "code": code,
            "language": language,
        })
        assert resp.status_code == 200
        return resp.json()["scan_id"]

    # ------------------------------------------------------------------
    # /metadata endpoint
    # ------------------------------------------------------------------
    def test_get_scan_metadata_returns_dict(self, _client):
        """GET /scans/{scan_id}/metadata should return a dict."""
        scan_id = self._create_scan(_client)
        resp = _client.get(f"/scans/{scan_id}/metadata")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, dict)

    def test_get_scan_metadata_contains_analyzer_info(self, _client):
        """GET /scans/{scan_id}/metadata should contain analyzer_info key."""
        scan_id = self._create_scan(_client)
        resp = _client.get(f"/scans/{scan_id}/metadata")
        assert resp.status_code == 200
        data = resp.json()
        assert "analyzer_info" in data

    def test_get_scan_metadata_not_found(self, _client):
        """GET /scans/{scan_id}/metadata with invalid scan_id should return 404."""
        resp = _client.get("/scans/nonexistent123abc/metadata")
        assert resp.status_code == 404

    # ------------------------------------------------------------------
    # /analyzer-info endpoint
    # ------------------------------------------------------------------
    def test_get_scan_analyzer_info_returns_required_fields(self, _client):
        """GET /scans/{scan_id}/analyzer-info should return analyzer_runs, analyzer_errors, skipped_languages."""
        scan_id = self._create_scan(_client)
        resp = _client.get(f"/scans/{scan_id}/analyzer-info")
        assert resp.status_code == 200
        data = resp.json()
        assert "analyzer_runs" in data
        assert "analyzer_errors" in data
        assert "skipped_languages" in data
        assert isinstance(data["analyzer_runs"], list)
        assert isinstance(data["analyzer_errors"], list)
        assert isinstance(data["skipped_languages"], list)

    def test_get_scan_analyzer_info_not_found(self, _client):
        """GET /scans/{scan_id}/analyzer-info with invalid scan_id should return 404."""
        resp = _client.get("/scans/nonexistent123abc/analyzer-info")
        assert resp.status_code == 404

    def test_get_scan_analyzer_info_has_analyzer_runs(self, _client):
        """GET /scans/{scan_id}/analyzer-info should have at least one analyzer run for python code."""
        scan_id = self._create_scan(_client)
        resp = _client.get(f"/scans/{scan_id}/analyzer-info")
        assert resp.status_code == 200
        data = resp.json()
        # Python code should trigger at least one analyzer run
        assert len(data["analyzer_runs"]) >= 1
        run = data["analyzer_runs"][0]
        assert "analyzer_name" in run
        assert "language" in run
        assert "success" in run

    # ------------------------------------------------------------------
    # /scan original fields still present
    # ------------------------------------------------------------------
    def test_scan_original_fields_unchanged(self, _client):
        """POST /scan should still return scan_id, summary, findings, evidence, agent_logs."""
        resp = _client.post("/scan", json={
            "input_type": "code",
            "code": "def test(): pass",
            "language": "python",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert "scan_id" in data
        assert "summary" in data
        assert "findings" in data
        assert "evidence" in data
        assert "agent_logs" in data

    # ------------------------------------------------------------------
    # Multiple scans isolation
    # ------------------------------------------------------------------
    def test_metadata_isolated_between_scans(self, _client):
        """Different scan_ids should return their own metadata."""
        scan_id1 = self._create_scan(_client, code="x = 1")
        scan_id2 = self._create_scan(_client, code="y = 2")

        resp1 = _client.get(f"/scans/{scan_id1}/metadata")
        resp2 = _client.get(f"/scans/{scan_id2}/metadata")
        assert resp1.status_code == 200
        assert resp2.status_code == 200
        # Both should be valid dicts
        assert isinstance(resp1.json(), dict)
        assert isinstance(resp2.json(), dict)
