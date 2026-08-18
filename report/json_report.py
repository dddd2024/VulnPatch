"""JSON report adapter for the canonical AuditResult model."""
from __future__ import annotations
from typing import Any
from audit_core.models import AuditResult

def build_json_report(result: AuditResult) -> dict[str, Any]:
    """Return a JSON-serialisable representation of an audit result."""
    return result.model_dump(mode="json")
