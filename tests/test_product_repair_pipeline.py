"""Product-facing scan -> repair acceptance test.

This guards against the title capabilities drifting back into demo-only code.
"""
from pathlib import Path
import sqlite3

from fastapi.testclient import TestClient


def test_product_scan_to_repair_uses_shared_pipeline(tmp_path, monkeypatch):
    db_path = tmp_path / "product-repair.db"
    monkeypatch.setenv("VULNPATCH_DB_PATH", str(db_path))

    from api import database
    from api.state import audit_state

    database.close_connection()
    database._initialized.done = False
    audit_state._latest_scan_id = None

    from api.server import app
    from knowledge.case_store import CaseStore

    java = Path("demo/simple_sql/SimpleSql.java").read_text(encoding="utf-8")
    with TestClient(app) as client:
        scan = client.post("/api/scan", json={
            "input_type": "code",
            "code": java,
            "language": "java",
        })
        assert scan.status_code == 200, scan.text
        scan_data = scan.json()
        finding = next(item for item in scan_data["findings"] if item.get("cwe") == "CWE-89")

        repair = client.post("/api/repair", json={
            "scan_id": scan_data["scan_id"],
            "finding_id": finding["id"],
            "sensitivity": "public",
            "repair_variant": "auto",
        })
        assert repair.status_code == 200, repair.text
        result = repair.json()

    assert result["routing_decision"]["selected_provider"] == "rule_engine"
    assert "prepared" in result["patch"]["strategy"].lower() or "parameter" in result["patch"]["strategy"].lower()
    assert result["verification"]["passed"] is True
    assert result["evolved_case"]["outcome"] == "POSITIVE"
    assert result["evolved_case"]["metadata"]["demo"] is False

    with sqlite3.connect(db_path) as conn:
        persisted = conn.execute(
            "SELECT finding_id FROM routing_decisions WHERE scan_id=?",
            (scan_data["scan_id"],),
        ).fetchall()
    assert persisted and persisted[0][0] == finding["id"]
    cases = CaseStore().list_cases(cwe="CWE-89", limit=50)
    assert any(case.source_scan_id == scan_data["scan_id"] and case.outcome == "POSITIVE" for case in cases)

    database.close_connection()
    database._initialized.done = False
    audit_state._latest_scan_id = None
