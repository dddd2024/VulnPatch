"""
Tests for AgentRuntime error isolation and fallback handling.

These tests verify that:
1. Agent exceptions don't crash the entire scan
2. Fallback outputs are generated when Agents fail
3. Structured logs are created for both success and failure cases
4. The audit flow continues even when individual Agents fail
"""

import pytest
from unittest.mock import Mock, patch

from audit_core.models import (
    CodeUnit, RawFinding, AgentHypothesis, AgentLog,
    JudgeDecision, EvidenceBundle
)
from audit_core.agent_runtime import AgentRuntime
from audit_core.error_policy import ErrorPolicy, AgentExecutionResult
from agents.recon_agent import ReconAgent
from agents.analysis_agent import AnalysisAgent
from agents.judge_agent import JudgeAgent


class TestAgentRuntimeRecon:
    """Tests for AgentRuntime.run_recon error handling."""

    def test_run_recon_success(self):
        """Test successful ReconAgent execution."""
        runtime = AgentRuntime()
        agent = Mock(spec=ReconAgent)

        # Mock successful execution
        mock_hypothesis = Mock(spec=AgentHypothesis)
        mock_hypothesis.id = "hypo_1"
        mock_log = Mock(spec=AgentLog)
        mock_log.id = "log_1"

        agent.run.return_value = ([mock_hypothesis], [mock_log])

        code_units = [
            CodeUnit(path="test.py", language="python", content="print('hello')")
        ]

        result = runtime.run_recon(agent, code_units)

        assert result.status == "success"
        assert result.output == [mock_hypothesis]
        assert len(result.logs) == 2  # Original log + success log
        assert result.fallback_used is False
        assert result.error is None

    def test_run_recon_failure_returns_empty_hypotheses(self):
        """Test that ReconAgent failure returns empty hypotheses."""
        runtime = AgentRuntime()
        agent = Mock(spec=ReconAgent)

        # Mock failed execution
        agent.run.side_effect = Exception("Recon agent crashed")

        code_units = [
            CodeUnit(path="test.py", language="python", content="print('hello')")
        ]

        result = runtime.run_recon(agent, code_units)

        assert result.status == "failed"
        assert result.output == []  # Empty list
        assert len(result.logs) == 1  # Failure log
        assert result.fallback_used is True
        assert result.error is not None
        assert "Recon agent crashed" in str(result.error)

    def test_run_recon_failure_logs_contain_error_info(self):
        """Test that ReconAgent failure logs contain error information."""
        runtime = AgentRuntime()
        agent = Mock(spec=ReconAgent)

        agent.run.side_effect = ValueError("Invalid code unit")

        code_units = [
            CodeUnit(path="test.py", language="python", content="print('hello')")
        ]

        result = runtime.run_recon(agent, code_units)

        assert len(result.logs) == 1
        log = result.logs[0]
        assert log.agent_name == "recon"
        assert log.stage == "recon"
        assert "failed" in log.message.lower()
        assert log.metadata["error_type"] == "ValueError"
        assert "Invalid code unit" in log.metadata["error_message"]
        assert log.metadata["fallback_applied"] is True


class TestAgentRuntimeAnalysis:
    """Tests for AgentRuntime.run_analysis error handling."""

    def test_run_analysis_success(self):
        """Test successful AnalysisAgent execution."""
        runtime = AgentRuntime()
        agent = Mock(spec=AnalysisAgent)

        mock_hypothesis = Mock(spec=AgentHypothesis)
        mock_hypothesis.id = "hypo_1"
        mock_log = Mock(spec=AgentLog)
        mock_log.id = "log_1"

        agent.run.return_value = (mock_hypothesis, mock_log)

        finding = RawFinding(
            rule_id="TEST-001",
            type="sql_injection",
            severity="ERROR",
            file_path="test.py",
            start_line=10,
            message="Test finding",
            engine="test"
        )
        code_unit = CodeUnit(path="test.py", language="python", content="code")

        result = runtime.run_analysis(agent, finding, code_unit)

        assert result.status == "success"
        assert result.output == mock_hypothesis
        assert len(result.logs) == 1
        assert result.fallback_used is False

    def test_run_analysis_failure_returns_fallback_hypothesis(self):
        """Test that AnalysisAgent failure returns fallback hypothesis."""
        runtime = AgentRuntime()
        agent = Mock(spec=AnalysisAgent)

        agent.run.side_effect = RuntimeError("Analysis failed")

        finding = RawFinding(
            rule_id="TEST-001",
            type="sql_injection",
            severity="ERROR",
            file_path="test.py",
            start_line=10,
            message="Test finding",
            engine="test"
        )

        result = runtime.run_analysis(agent, finding, None)

        assert result.status == "degraded"
        assert result.output is not None
        assert isinstance(result.output, AgentHypothesis)
        assert result.output.confidence == "low"
        assert result.fallback_used is True
        assert "fallback" in result.output.reasoning_summary.lower()

    def test_run_analysis_failure_hypothesis_has_finding_id(self):
        """Test that fallback hypothesis references the finding."""
        runtime = AgentRuntime()
        agent = Mock(spec=AnalysisAgent)

        agent.run.side_effect = Exception("Analysis error")

        finding = RawFinding(
            rule_id="TEST-001",
            type="xss",
            severity="WARN",
            file_path="test.py",
            start_line=5,
            message="XSS vulnerability",
            engine="test"
        )

        result = runtime.run_analysis(agent, finding, None)

        hypothesis = result.output
        assert hypothesis.finding_id == finding.id
        assert hypothesis.agent_name == "analysis"
        assert hypothesis.metadata["fallback_applied"] is True
        assert hypothesis.metadata["original_finding_type"] == "xss"


class TestAgentRuntimeJudge:
    """Tests for AgentRuntime.run_judge error handling."""

    def test_run_judge_success(self):
        """Test successful JudgeAgent execution."""
        runtime = AgentRuntime()
        agent = Mock(spec=JudgeAgent)

        mock_decision = Mock(spec=JudgeDecision)
        mock_decision.id = "decision_1"
        mock_log = Mock(spec=AgentLog)
        mock_log.id = "log_1"

        agent.run.return_value = (mock_decision, mock_log)

        finding = RawFinding(
            rule_id="TEST-001",
            type="sql_injection",
            severity="ERROR",
            file_path="test.py",
            start_line=10,
            message="Test finding",
            engine="test"
        )
        hypotheses = []

        result = runtime.run_judge(agent, finding, hypotheses)

        assert result.status == "success"
        assert result.output == mock_decision
        assert len(result.logs) == 1
        assert result.fallback_used is False

    def test_run_judge_failure_returns_fallback_decision(self):
        """Test that JudgeAgent failure returns fallback decision."""
        runtime = AgentRuntime()
        agent = Mock(spec=JudgeAgent)

        agent.run.side_effect = Exception("Judge crashed")

        finding = RawFinding(
            rule_id="TEST-001",
            type="sql_injection",
            severity="ERROR",
            file_path="test.py",
            start_line=10,
            message="Test finding",
            engine="test"
        )

        result = runtime.run_judge(agent, finding, [])

        assert result.status == "degraded"
        assert result.output is not None
        assert isinstance(result.output, JudgeDecision)
        assert result.fallback_used is True

    def test_run_judge_fallback_has_conservative_values(self):
        """Test that fallback JudgeDecision has conservative values."""
        runtime = AgentRuntime()
        agent = Mock(spec=JudgeAgent)

        agent.run.side_effect = RuntimeError("Judge error")

        finding = RawFinding(
            rule_id="TEST-001",
            type="command_injection",
            severity="ERROR",
            file_path="test.py",
            start_line=10,
            message="Test finding",
            engine="test"
        )

        result = runtime.run_judge(agent, finding, [])
        decision = result.output

        assert decision.verdict == "suspicious"
        assert decision.confidence == "low"
        assert decision.risk_score == 30  # Conservative value
        assert decision.finding_id == finding.id
        assert "JudgeAgent failed" in decision.reason
        assert "fallback" in decision.reason.lower()

    def test_run_judge_fallback_logs_contain_error_info(self):
        """Test that fallback logs contain error information."""
        runtime = AgentRuntime()
        agent = Mock(spec=JudgeAgent)

        agent.run.side_effect = ValueError("Invalid input")

        finding = RawFinding(
            rule_id="TEST-001",
            type="sql_injection",
            severity="ERROR",
            file_path="test.py",
            start_line=10,
            message="Test finding",
            engine="test"
        )

        result = runtime.run_judge(agent, finding, [])

        assert len(result.logs) == 1
        log = result.logs[0]
        assert log.agent_name == "judge"
        assert log.stage == "judge"
        assert log.metadata["error_type"] == "ValueError"
        assert log.metadata["verdict"] == "suspicious"
        assert log.metadata["risk_score"] == 30


class TestAgentRuntimeEvidence:
    """Tests for AgentRuntime.build_evidence error handling."""

    def test_build_evidence_success(self):
        """Test successful evidence building."""
        runtime = AgentRuntime()

        finding = RawFinding(
            rule_id="TEST-001",
            type="sql_injection",
            severity="ERROR",
            file_path="test.py",
            start_line=10,
            message="Test finding",
            engine="test"
        )
        code_unit = CodeUnit(path="test.py", language="python", content="code")
        hypothesis = AgentHypothesis(
            agent_name="analysis",
            hypothesis="SQL injection detected",
            reasoning_summary="Test reasoning",
            confidence="high"
        )
        decision = JudgeDecision(
            finding_id=finding.id,
            verdict="confirmed",
            confidence="high",
            risk_score=80,
            reason="Test reason"
        )

        evidence, logs = runtime.build_evidence(
            finding=finding,
            code_unit=code_unit,
            hypotheses=[hypothesis],
            agent_logs=[],
            judge_decision=decision
        )

        assert evidence is not None
        assert isinstance(evidence, EvidenceBundle)
        assert evidence.finding == finding
        assert len(logs) == 0  # No additional logs on success

    def test_build_evidence_failure_returns_none_and_logs(self):
        """Test that evidence building failure returns None and logs."""
        runtime = AgentRuntime()

        finding = RawFinding(
            rule_id="TEST-001",
            type="sql_injection",
            severity="ERROR",
            file_path="test.py",
            start_line=10,
            message="Test finding",
            engine="test"
        )

        # Patch the build_evidence_bundle function at the module level
        # where AgentRuntime imports it
        with patch('audit_core.agent_runtime.build_evidence_bundle') as mock_build:
            mock_build.side_effect = Exception("Evidence build failed")

            evidence, logs = runtime.build_evidence(
                finding=finding,
                code_unit=None,
                hypotheses=[],
                agent_logs=[],
                judge_decision=None
            )

        assert evidence is None
        assert len(logs) == 1
        log = logs[0]
        assert log.agent_name == "evidence_builder"
        assert log.stage == "evidence"
        assert "failed" in log.message.lower()
        assert log.metadata["finding_preserved"] is True


class TestAgentRuntimeBatchOperations:
    """Tests for batch operations with error isolation."""

    def test_run_analysis_batch_isolates_failures(self):
        """Test that batch analysis isolates failures per finding."""
        runtime = AgentRuntime()
        agent = Mock(spec=AnalysisAgent)

        # First call succeeds, second fails, third succeeds
        def side_effect(finding, code_unit):
            if finding.type == "sql_injection":
                return (
                    AgentHypothesis(
                        agent_name="analysis",
                        hypothesis="SQL injection",
                        reasoning_summary="Test",
                        confidence="high"
                    ),
                    AgentLog(agent_name="analysis", stage="analysis", message="OK")
                )
            elif finding.type == "xss":
                raise Exception("XSS analysis failed")
            else:
                return (
                    AgentHypothesis(
                        agent_name="analysis",
                        hypothesis="Other",
                        reasoning_summary="Test",
                        confidence="medium"
                    ),
                    AgentLog(agent_name="analysis", stage="analysis", message="OK")
                )

        agent.run.side_effect = side_effect

        findings = [
            RawFinding(rule_id="R1", type="sql_injection", severity="ERROR",
                      file_path="a.py", start_line=1, message="SQL", engine="test"),
            RawFinding(rule_id="R2", type="xss", severity="WARN",
                      file_path="b.py", start_line=2, message="XSS", engine="test"),
            RawFinding(rule_id="R3", type="path_traversal", severity="INFO",
                      file_path="c.py", start_line=3, message="Path", engine="test"),
        ]
        code_units = [
            CodeUnit(path="a.py", language="python", content="code"),
            CodeUnit(path="b.py", language="python", content="code"),
            CodeUnit(path="c.py", language="python", content="code"),
        ]

        results = runtime.run_analysis_batch(agent, findings, code_units)

        assert len(results) == 3
        assert results[0].status == "success"
        assert results[1].status == "degraded"  # Failed but recovered
        assert results[2].status == "success"

    def test_extract_outputs_filters_none(self):
        """Test that extract_outputs filters None values."""
        runtime = AgentRuntime()

        mock_hypo = Mock(spec=AgentHypothesis)

        results = [
            AgentExecutionResult(status="success", output=mock_hypo),
            AgentExecutionResult(status="failed", output=None),
            AgentExecutionResult(status="success", output=mock_hypo),
        ]

        outputs = runtime.extract_outputs(results)

        assert len(outputs) == 2
        assert all(o is not None for o in outputs)

    def test_collect_logs_flattens_all_logs(self):
        """Test that collect_logs flattens logs from all results."""
        runtime = AgentRuntime()

        log1 = AgentLog(agent_name="a", stage="s1", message="m1")
        log2 = AgentLog(agent_name="b", stage="s2", message="m2")
        log3 = AgentLog(agent_name="c", stage="s3", message="m3")

        results = [
            AgentExecutionResult(status="success", output=None, logs=[log1, log2]),
            AgentExecutionResult(status="failed", output=None, logs=[log3]),
        ]

        logs = runtime.collect_logs(results)

        assert len(logs) == 3
        assert log1 in logs
        assert log2 in logs
        assert log3 in logs


class TestErrorPolicy:
    """Tests for ErrorPolicy fallback strategies."""

    def test_create_fallback_recon_result(self):
        """Test fallback recon result creation."""
        error = ValueError("Test error")
        result = ErrorPolicy.create_fallback_recon_result(
            code_unit_count=5,
            error=error
        )

        assert result.status == "failed"
        assert result.output == []
        assert result.fallback_used is True
        assert result.error == error
        assert result.agent_name == "recon"
        assert len(result.logs) == 1

    def test_create_fallback_analysis_result(self):
        """Test fallback analysis result creation."""
        error = RuntimeError("Analysis error")
        result = ErrorPolicy.create_fallback_analysis_result(
            finding_id="finding_123",
            finding_type="sql_injection",
            error=error
        )

        assert result.status == "degraded"
        assert isinstance(result.output, AgentHypothesis)
        assert result.output.confidence == "low"
        assert result.fallback_used is True
        assert result.output.finding_id == "finding_123"
        assert "sql_injection" in result.output.vulnerability_type

    def test_create_fallback_judge_result(self):
        """Test fallback judge result creation."""
        error = Exception("Judge error")
        result = ErrorPolicy.create_fallback_judge_result(
            finding_id="finding_456",
            error=error
        )

        assert result.status == "degraded"
        assert isinstance(result.output, JudgeDecision)
        assert result.output.verdict == "suspicious"
        assert result.output.confidence == "low"
        assert result.output.risk_score == 30
        assert result.fallback_used is True
        assert result.output.finding_id == "finding_456"

    def test_create_evidence_failure_log(self):
        """Test evidence failure log creation."""
        error = Exception("Build error")
        log = ErrorPolicy.create_evidence_failure_log(
            finding_id="finding_789",
            error=error
        )

        assert log.agent_name == "evidence_builder"
        assert log.stage == "evidence"
        assert "failed" in log.message.lower()
        assert log.metadata["finding_preserved"] is True
        assert log.metadata["fallback_applied"] is True

    def test_create_success_log(self):
        """Test success log creation."""
        log = ErrorPolicy.create_success_log(
            agent_name="test_agent",
            stage="test_stage",
            message="Test message",
            input_refs=["input1"],
            output_refs=["output1"],
            metadata={"key": "value"}
        )

        assert log.agent_name == "test_agent"
        assert log.stage == "test_stage"
        assert log.message == "Test message"
        assert "input1" in log.input_refs
        assert "output1" in log.output_refs
        assert log.metadata["key"] == "value"


class TestAgentExecutionResult:
    """Tests for AgentExecutionResult dataclass."""

    def test_to_dict(self):
        """Test conversion to dictionary."""
        error = ValueError("Test error")
        result = AgentExecutionResult(
            status="failed",
            output=[1, 2, 3],
            logs=[AgentLog(agent_name="a", stage="s", message="m")],
            error=error,
            fallback_used=True,
            stage="test",
            agent_name="test_agent"
        )

        d = result.to_dict()

        assert d["status"] == "failed"
        assert d["output_type"] == "list"
        assert d["log_count"] == 1
        assert d["error_type"] == "ValueError"
        assert d["error_message"] == "Test error"
        assert d["fallback_used"] is True
        assert d["stage"] == "test"
        assert d["agent_name"] == "test_agent"
