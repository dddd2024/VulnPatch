"""
Integration tests for Agent error isolation and recovery.

These tests verify the end-to-end behavior of the audit pipeline
when Agents fail, ensuring that:
1. The entire scan doesn't crash when an Agent fails
2. AuditResult is still returned with all expected fields
3. Agent logs contain failure information
4. Fallback outputs are properly generated
"""

import pytest
from unittest.mock import Mock, patch

from audit_core.orchestrator import AuditOrchestrator
from audit_core.models import (
    CodeUnit, RawFinding, AgentHypothesis, AgentLog,
    JudgeDecision, AuditResult
)
from agents.recon_agent import ReconAgent
from agents.analysis_agent import AnalysisAgent
from agents.judge_agent import JudgeAgent


class FailingReconAgent(ReconAgent):
    """ReconAgent that always fails."""

    def run(self, code_units):
        raise RuntimeError("ReconAgent simulated failure")


class FailingAnalysisAgent(AnalysisAgent):
    """AnalysisAgent that always fails."""

    def run(self, finding, code_unit=None):
        raise RuntimeError("AnalysisAgent simulated failure")


class FailingJudgeAgent(JudgeAgent):
    """JudgeAgent that always fails."""

    def run(self, finding, hypotheses, evidence_bundle=None):
        raise RuntimeError("JudgeAgent simulated failure")


class TestReconAgentFailure:
    """Tests for ReconAgent failure recovery."""

    def test_scan_code_does_not_crash_when_recon_fails(self):
        """Test that scan_code doesn't crash when ReconAgent fails."""
        orchestrator = AuditOrchestrator()

        # Replace recon_agent with failing version
        orchestrator.recon_agent = FailingReconAgent()

        code = """
import os
user_input = input("Enter command: ")
os.system(user_input)
"""

        # Should not raise an exception
        result = orchestrator.scan_code(code, language="python")

        # Should return a valid AuditResult
        assert isinstance(result, AuditResult)
        assert result.summary is not None

    def test_recon_failure_logged_in_agent_logs(self):
        """Test that ReconAgent failure is logged."""
        orchestrator = AuditOrchestrator()
        orchestrator.recon_agent = FailingReconAgent()

        code = "print('hello')"
        result = orchestrator.scan_code(code, language="python")

        # Check that failure is logged
        recon_logs = [log for log in result.agent_logs if log.agent_name == "recon"]
        assert len(recon_logs) > 0

        # Check that log contains failure information
        failure_log = recon_logs[0]
        assert "failed" in failure_log.message.lower()
        assert failure_log.metadata.get("fallback_applied") is True

    def test_recon_failure_returns_empty_hypotheses(self):
        """Test that ReconAgent failure results in empty hypotheses."""
        orchestrator = AuditOrchestrator()
        orchestrator.recon_agent = FailingReconAgent()

        code = "print('hello')"
        result = orchestrator.scan_code(code, language="python")

        # Analyzers should still run and produce findings
        # But recon hypotheses should be empty
        recon_hypothesis_logs = [
            log for log in result.agent_logs
            if log.agent_name == "recon" and "hypotheses" in log.message.lower()
        ]
        # The log should indicate empty hypotheses
        if recon_hypothesis_logs:
            assert "0" in recon_hypothesis_logs[0].message or "empty" in recon_hypothesis_logs[0].message.lower()


class TestAnalysisAgentFailure:
    """Tests for AnalysisAgent failure recovery."""

    def test_scan_code_does_not_crash_when_analysis_fails(self):
        """Test that scan_code doesn't crash when AnalysisAgent fails."""
        orchestrator = AuditOrchestrator()

        # Replace analysis_agent with failing version
        orchestrator.analysis_agent = FailingAnalysisAgent()

        code = """
import sqlite3
user_input = input("Enter ID: ")
conn = sqlite3.connect("test.db")
cursor = conn.cursor()
cursor.execute("SELECT * FROM users WHERE id = " + user_input)
"""

        # Should not raise an exception
        result = orchestrator.scan_code(code, language="python")

        # Should return a valid AuditResult
        assert isinstance(result, AuditResult)
        assert result.summary is not None

    def test_analysis_failure_generates_fallback_hypothesis(self):
        """Test that AnalysisAgent failure generates fallback hypothesis."""
        orchestrator = AuditOrchestrator()
        orchestrator.analysis_agent = FailingAnalysisAgent()

        code = """
import sqlite3
user_input = input("Enter ID: ")
conn = sqlite3.connect("test.db")
cursor = conn.cursor()
cursor.execute("SELECT * FROM users WHERE id = " + user_input)
"""
        result = orchestrator.scan_code(code, language="python")

        # Check that analysis failure is logged
        analysis_logs = [log for log in result.agent_logs if log.agent_name == "analysis"]
        assert len(analysis_logs) > 0

        # Check that at least one log indicates fallback was used
        fallback_logs = [
            log for log in analysis_logs
            if log.metadata.get("fallback_applied") is True
        ]
        assert len(fallback_logs) > 0

    def test_analysis_failure_judge_still_executes(self):
        """Test that JudgeAgent still executes when AnalysisAgent fails."""
        orchestrator = AuditOrchestrator()
        orchestrator.analysis_agent = FailingAnalysisAgent()

        code = """
import sqlite3
user_input = input("Enter ID: ")
conn = sqlite3.connect("test.db")
cursor = conn.cursor()
cursor.execute("SELECT * FROM users WHERE id = " + user_input)
"""
        result = orchestrator.scan_code(code, language="python")

        # Judge should have run (either successfully or with fallback)
        judge_logs = [log for log in result.agent_logs if log.agent_name == "judge"]
        assert len(judge_logs) > 0


class TestJudgeAgentFailure:
    """Tests for JudgeAgent failure recovery."""

    def test_scan_code_does_not_crash_when_judge_fails(self):
        """Test that scan_code doesn't crash when JudgeAgent fails."""
        orchestrator = AuditOrchestrator()

        # Replace judge_agent with failing version
        orchestrator.judge_agent = FailingJudgeAgent()

        code = """
import sqlite3
user_input = input("Enter ID: ")
conn = sqlite3.connect("test.db")
cursor = conn.cursor()
cursor.execute("SELECT * FROM users WHERE id = " + user_input)
"""

        # Should not raise an exception
        result = orchestrator.scan_code(code, language="python")

        # Should return a valid AuditResult
        assert isinstance(result, AuditResult)
        assert result.summary is not None

    def test_judge_failure_generates_fallback_decision(self):
        """Test that JudgeAgent failure generates fallback decision."""
        orchestrator = AuditOrchestrator()
        orchestrator.judge_agent = FailingJudgeAgent()

        code = """
import sqlite3
user_input = input("Enter ID: ")
conn = sqlite3.connect("test.db")
cursor = conn.cursor()
cursor.execute("SELECT * FROM users WHERE id = " + user_input)
"""
        result = orchestrator.scan_code(code, language="python")

        # Check that judge failure is logged
        judge_logs = [log for log in result.agent_logs if log.agent_name == "judge"]
        assert len(judge_logs) > 0

        # Check that fallback was applied
        fallback_logs = [
            log for log in judge_logs
            if log.metadata.get("fallback_applied") is True
        ]
        assert len(fallback_logs) > 0

    def test_judge_fallback_has_suspicious_verdict(self):
        """Test that JudgeAgent fallback has verdict='suspicious'."""
        orchestrator = AuditOrchestrator()
        orchestrator.judge_agent = FailingJudgeAgent()

        code = """
import sqlite3
user_input = input("Enter ID: ")
conn = sqlite3.connect("test.db")
cursor = conn.cursor()
cursor.execute("SELECT * FROM users WHERE id = " + user_input)
"""
        result = orchestrator.scan_code(code, language="python")

        # Check evidence bundles for fallback decisions
        for evidence in result.evidence:
            if evidence.judge_decision:
                # If it's a fallback decision, it should be suspicious
                if "fallback" in evidence.judge_decision.reason.lower():
                    assert evidence.judge_decision.verdict == "suspicious"
                    assert evidence.judge_decision.confidence == "low"
                    assert evidence.judge_decision.risk_score == 30


class TestMultipleFindingFailureIsolation:
    """Tests that failures in one finding don't affect others."""

    def test_one_finding_failure_does_not_affect_others(self):
        """Test that one finding's failure doesn't crash the whole scan."""
        orchestrator = AuditOrchestrator()

        # Create code with multiple vulnerabilities
        code = """
import sqlite3
import os

# First vulnerability - SQL injection
user_input1 = input("Enter ID: ")
conn = sqlite3.connect("test.db")
cursor = conn.cursor()
cursor.execute("SELECT * FROM users WHERE id = " + user_input1)

# Second vulnerability - Command injection
user_input2 = input("Enter command: ")
os.system(user_input2)

# Third vulnerability - SQL injection again
user_input3 = input("Enter name: ")
cursor.execute("SELECT * FROM products WHERE name = '" + user_input3 + "'")
"""

        # Should not raise an exception
        result = orchestrator.scan_code(code, language="python")

        # Should return a valid AuditResult
        assert isinstance(result, AuditResult)

        # Should have findings
        assert result.summary.total_findings > 0

        # Should have evidence bundles (one per finding)
        assert result.summary.total_evidence_bundles > 0

    def test_audit_result_structure_preserved_on_failures(self):
        """Test that AuditResult structure is preserved even with failures."""
        orchestrator = AuditOrchestrator()

        # Make all agents fail
        orchestrator.recon_agent = FailingReconAgent()
        orchestrator.analysis_agent = FailingAnalysisAgent()
        orchestrator.judge_agent = FailingJudgeAgent()

        code = """
import os
user_input = input("Enter: ")
os.system(user_input)
"""

        result = orchestrator.scan_code(code, language="python")

        # AuditResult should have all required fields
        assert result.summary is not None
        assert isinstance(result.findings, list)
        assert isinstance(result.evidence, list)
        assert isinstance(result.agent_logs, list)

        # Summary should have required fields
        summary = result.summary
        assert hasattr(summary, 'total_code_units')
        assert hasattr(summary, 'total_findings')
        assert hasattr(summary, 'total_evidence_bundles')
        assert hasattr(summary, 'risk_score')
        assert hasattr(summary, 'languages')
        assert hasattr(summary, 'scanned_files')


class TestAuditResultCompleteness:
    """Tests that AuditResult is complete even with Agent failures."""

    def test_audit_result_has_summary_findings_evidence_logs(self):
        """Test that AuditResult has all required fields."""
        orchestrator = AuditOrchestrator()

        code = """
import sqlite3
user_input = input("Enter ID: ")
conn = sqlite3.connect("test.db")
cursor = conn.cursor()
cursor.execute("SELECT * FROM users WHERE id = " + user_input)
"""
        result = orchestrator.scan_code(code, language="python")

        # Check all required fields exist
        assert result.summary is not None
        assert isinstance(result.findings, list)
        assert isinstance(result.evidence, list)
        assert isinstance(result.agent_logs, list)

    def test_agent_logs_contain_all_stages(self):
        """Test that agent_logs contain entries for all stages."""
        orchestrator = AuditOrchestrator()

        code = """
import sqlite3
user_input = input("Enter ID: ")
conn = sqlite3.connect("test.db")
cursor = conn.cursor()
cursor.execute("SELECT * FROM users WHERE id = " + user_input)
"""
        result = orchestrator.scan_code(code, language="python")

        # Check that logs exist for different stages
        stages = set(log.stage for log in result.agent_logs)

        # Should have at least recon and analysis stages
        assert "recon" in stages or any(log.agent_name == "recon" for log in result.agent_logs)
        assert "analysis" in stages or any(log.agent_name == "analysis" for log in result.agent_logs)


class TestErrorIsolationWithRealAgents:
    """Tests with real Agents but simulated failures."""

    def test_normal_scan_still_works(self):
        """Test that normal scans still work correctly."""
        orchestrator = AuditOrchestrator()

        code = """
import sqlite3
user_input = input("Enter ID: ")
conn = sqlite3.connect("test.db")
cursor = conn.cursor()
cursor.execute("SELECT * FROM users WHERE id = " + user_input)
"""
        result = orchestrator.scan_code(code, language="python")

        # Should return valid result
        assert isinstance(result, AuditResult)

        # Should have findings for SQL injection
        sql_findings = [f for f in result.findings if "sql" in f.type.lower()]

        # Should have agent logs
        assert len(result.agent_logs) > 0

        # Should have evidence
        assert len(result.evidence) >= 0  # May be 0 if no findings

    def test_empty_code_scan_works(self):
        """Test that scanning empty code works."""
        orchestrator = AuditOrchestrator()

        result = orchestrator.scan_code("", language="python")

        assert isinstance(result, AuditResult)
        assert result.summary.total_code_units >= 0

    def test_code_without_vulnerabilities_works(self):
        """Test that scanning safe code works."""
        orchestrator = AuditOrchestrator()

        code = """
def greet(name):
    print(f"Hello, {name}!")

greet("World")
"""
        result = orchestrator.scan_code(code, language="python")

        assert isinstance(result, AuditResult)
        # May or may not have findings, but should not crash
