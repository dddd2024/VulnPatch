"""
Smoke tests for report module.

API / Report / UI member is responsible for:
  - report/
"""

import pytest


class TestReportSmoke:
    """Smoke tests for report module — verify report generation."""

    def test_json_report_generates(self):
        """JSON report should be generable from AuditResult."""
        from audit_core.models import AuditResult, AuditSummary
        from report.json_report import build_json_report

        result = AuditResult(summary=AuditSummary())
        report = build_json_report(result)
        assert isinstance(report, dict)
        assert "summary" in report

    def test_markdown_report_generates(self):
        """Markdown report should be generable from AuditResult."""
        from audit_core.models import AuditResult, AuditSummary
        from report.markdown_report import build_markdown_report

        result = AuditResult(summary=AuditSummary())
        report = build_markdown_report(result)
        assert isinstance(report, str)
        assert len(report) > 0

    def test_html_report_generates(self):
        """HTML report should be generable from AuditResult."""
        from audit_core.models import AuditResult, AuditSummary
        from report.html_report import build_html_report

        result = AuditResult(summary=AuditSummary())
        report = build_html_report(result)
        assert isinstance(report, str)
        assert "<html" in report.lower() or "<!doctype" in report.lower()

    def test_report_with_findings(self):
        """Report should include findings when present."""
        from audit_core.models import (
            AuditResult, AuditSummary, RawFinding,
        )
        from report.json_report import build_json_report

        finding = RawFinding(
            rule_id="TEST-001",
            type="sql_injection",
            severity="ERROR",
            confidence="high",
            file_path="test.py",
            start_line=1,
            message="SQL injection",
            engine="pattern",
        )
        result = AuditResult(
            summary=AuditSummary(total_findings=1),
            findings=[finding],
        )
        report = build_json_report(result)
        assert len(report["findings"]) == 1
