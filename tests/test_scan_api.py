"""
API integration tests for the new scan pipeline.

Uses FastAPI TestClient to verify:
  - GET  /health
  - POST /scan  (primary entry point)
  - GET  /findings
  - GET  /evidence
  - GET  /agents/logs
  - GET  /report/json
"""

import pytest
from fastapi.testclient import TestClient

from api.server import app

client = TestClient(app)

SQL_INJECTION_CODE = '''
def get_user(user_id):
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
    return cursor.fetchone()
'''

SAFE_CODE = '''
def hello():
    return "Hello, World!"
'''


class TestHealthEndpoint:
    """GET /health"""

    def test_health_returns_ok(self):
        resp = client.get("/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"


class TestScanEndpoint:
    """POST /scan — primary audit entry point"""

    def test_scan_sql_injection(self):
        resp = client.post("/scan", json={
            "input_type": "code",
            "code": SQL_INJECTION_CODE,
            "language": "python",
        })
        assert resp.status_code == 200
        data = resp.json()

        # Must contain all four top-level fields
        assert "summary" in data
        assert "findings" in data
        assert "evidence" in data
        assert "agent_logs" in data

        # Summary fields
        summary = data["summary"]
        assert summary["total_code_units"] == 1
        assert summary["total_findings"] >= 1
        assert isinstance(summary["risk_score"], (int, float))
        assert isinstance(summary["languages"], list)
        assert isinstance(summary["scanned_files"], list)

        # Findings
        assert len(data["findings"]) >= 1
        finding = data["findings"][0]
        assert "type" in finding
        assert "severity" in finding
        assert "file_path" in finding
        assert "start_line" in finding

    def test_scan_safe_code(self):
        resp = client.post("/scan", json={
            "input_type": "code",
            "code": SAFE_CODE,
            "language": "python",
        })
        assert resp.status_code == 200
        data = resp.json()

        assert "summary" in data
        assert "findings" in data
        assert "evidence" in data
        assert "agent_logs" in data
        assert data["summary"]["total_findings"] == 0

    def test_scan_invalid_input_type(self):
        resp = client.post("/scan", json={
            "input_type": "invalid",
            "code": "x",
        })
        # Pydantic validation returns 422 for invalid enum values
        assert resp.status_code == 422

    def test_scan_missing_code(self):
        resp = client.post("/scan", json={
            "input_type": "code",
        })
        assert resp.status_code == 400


class TestSubResourceEndpoints:
    """GET /findings, /evidence, /agents/logs, /report/json"""

    def test_findings_returns_list(self):
        # First run a scan to populate state
        client.post("/scan", json={
            "input_type": "code",
            "code": SQL_INJECTION_CODE,
            "language": "python",
        })
        resp = client.get("/findings")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)
        assert len(data) >= 1

    def test_evidence_returns_list(self):
        client.post("/scan", json={
            "input_type": "code",
            "code": SQL_INJECTION_CODE,
            "language": "python",
        })
        resp = client.get("/evidence")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)

    def test_agents_logs_returns_list(self):
        client.post("/scan", json={
            "input_type": "code",
            "code": SQL_INJECTION_CODE,
            "language": "python",
        })
        resp = client.get("/agents/logs")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)

    def test_report_json_returns_dict(self):
        client.post("/scan", json={
            "input_type": "code",
            "code": SQL_INJECTION_CODE,
            "language": "python",
        })
        resp = client.get("/report/json")
        assert resp.status_code == 200
        data = resp.json()
        assert "summary" in data
        assert "findings" in data
        assert "evidence" in data
        assert "agent_logs" in data

    def test_report_markdown_returns_text(self):
        client.post("/scan", json={
            "input_type": "code",
            "code": SQL_INJECTION_CODE,
            "language": "python",
        })
        resp = client.get("/report/markdown")
        assert resp.status_code == 200
        assert resp.headers["content-type"] == "text/markdown; charset=utf-8"
        content = resp.text
        assert "# Audit Report" in content
        assert "## Summary" in content

    def test_report_html_returns_html(self):
        client.post("/scan", json={
            "input_type": "code",
            "code": SQL_INJECTION_CODE,
            "language": "python",
        })
        resp = client.get("/report/html")
        assert resp.status_code == 200
        assert "text/html" in resp.headers["content-type"]
        content = resp.text
        assert "<!DOCTYPE html>" in content
        assert "<html" in content

    def test_findings_empty_before_scan(self):
        """Before any scan, sub-resources should return empty structures."""
        from api.state import audit_state
        audit_state.clear()

        resp = client.get("/findings")
        assert resp.status_code == 200
        assert resp.json() == []

        resp = client.get("/evidence")
        assert resp.status_code == 200
        assert resp.json() == []

        resp = client.get("/report/json")
        assert resp.status_code == 200
        data = resp.json()
        assert "summary" in data
