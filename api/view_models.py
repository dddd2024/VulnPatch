"""
View Models for API responses.

View Models provide a UI-friendly representation of internal data models.
They isolate the UI from internal model changes and provide a stable
contract for frontend rendering.

Design Goals:
- UI uses View Models, not RawFinding directly
- View Models can merge data from multiple sources (finding + judge decision)
- View Models have stable, UI-friendly field names
- Internal model changes don't break UI

Team Member Assignment: Member 4 (API, UI & Report)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class FindingView:
    """
    UI-friendly representation of a finding.

    Merges data from RawFinding and JudgeDecision to provide
    a single view for UI rendering.

    Field Mapping:
    - RawFinding.file_path -> FindingView.file
    - RawFinding.start_line -> FindingView.line
    - RawFinding.end_line -> FindingView.end_line
    - JudgeDecision.risk_score -> FindingView.risk_score
    - JudgeDecision.verdict -> FindingView.verdict

    Attributes:
        id: Finding unique identifier
        type: Vulnerability type (e.g., "SQL Injection")
        severity: Severity level ("ERROR", "WARN", "INFO")
        confidence: Confidence level ("high", "medium", "low")
        file: File path (UI-friendly name)
        line: Start line number
        end_line: End line number
        message: Finding message
        rule_id: Rule identifier
        cwe: CWE identifier (optional)
        engine: Detection engine name
        risk_score: Risk score from Judge (0-100)
        verdict: Judge verdict ("confirmed", "suspicious", "rejected")
        snippet: Code snippet (optional)
        call_chain: Call chain (optional)
        metadata: Additional metadata
    """

    id: str
    type: str
    severity: str
    confidence: str
    file: str
    line: int
    end_line: int | None = None
    message: str = ""
    rule_id: str = ""
    cwe: str | None = None
    engine: str = ""
    risk_score: float = 0.0
    verdict: str = "pending"
    snippet: str | None = None
    call_chain: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_raw_finding(
        cls,
        finding: Any,
        decision: Any | None = None,
        evidence: Any | None = None,
    ) -> "FindingView":
        """
        Create FindingView from RawFinding and optional JudgeDecision.

        Args:
            finding: RawFinding instance
            decision: JudgeDecision instance (optional)
            evidence: EvidenceBundle instance (optional)

        Returns:
            FindingView instance
        """
        # Map internal fields to UI-friendly names
        view = cls(
            id=finding.id,
            type=finding.type,
            severity=finding.severity,
            confidence=finding.confidence,
            file=finding.file_path,  # file_path -> file
            line=finding.start_line,  # start_line -> line
            end_line=finding.end_line,
            message=finding.message,
            rule_id=finding.rule_id,
            cwe=finding.cwe,
            engine=finding.engine,
            metadata=finding.metadata or {},
        )

        # Merge JudgeDecision data
        if decision is not None:
            view.risk_score = decision.risk_score or 0.0
            view.verdict = decision.verdict or "pending"

        # Merge EvidenceBundle data
        if evidence is not None:
            # Extract snippet
            if evidence.snippets:
                view.snippet = evidence.snippets[0] if isinstance(evidence.snippets[0], str) else str(evidence.snippets[0])
            # Extract call chain
            if evidence.call_chain:
                view.call_chain = list(evidence.call_chain)

        return view

    def to_dict(self) -> dict[str, Any]:
        """
        Convert to dictionary for JSON serialization.

        Returns:
            Dictionary representation
        """
        return {
            "id": self.id,
            "type": self.type,
            "severity": self.severity,
            "confidence": self.confidence,
            "file": self.file,
            "line": self.line,
            "end_line": self.end_line,
            "message": self.message,
            "rule_id": self.rule_id,
            "cwe": self.cwe,
            "engine": self.engine,
            "risk_score": self.risk_score,
            "verdict": self.verdict,
            "snippet": self.snippet,
            "call_chain": self.call_chain,
            "metadata": self.metadata,
        }


@dataclass
class ScanView:
    """
    UI-friendly representation of a scan result.

    Provides a simplified view of AuditResult for UI rendering.

    Attributes:
        scan_id: Scan unique identifier
        status: Scan status ("completed", "failed", "running")
        total_findings: Total number of findings
        confirmed_count: Number of confirmed findings
        suspicious_count: Number of suspicious findings
        rejected_count: Number of rejected findings
        risk_score: Average risk score
        languages: List of languages scanned
        findings: List of FindingView objects
    """

    scan_id: str
    status: str = "completed"
    total_findings: int = 0
    confirmed_count: int = 0
    suspicious_count: int = 0
    rejected_count: int = 0
    risk_score: float = 0.0
    languages: list[str] = field(default_factory=list)
    findings: list[FindingView] = field(default_factory=list)

    @classmethod
    def from_audit_result(
        cls,
        scan_id: str,
        result: Any,
    ) -> "ScanView":
        """
        Create ScanView from AuditResult.

        Args:
            scan_id: Scan identifier
            result: AuditResult instance

        Returns:
            ScanView instance
        """
        # Build finding views
        finding_views: list[FindingView] = []

        # Build lookup for decisions and evidence
        decision_by_finding_id: dict[str, Any] = {}
        evidence_by_finding_id: dict[str, Any] = {}

        for bundle in result.evidence:
            if bundle.finding:
                finding_id = bundle.finding.id
                evidence_by_finding_id[finding_id] = bundle
                if bundle.judge_decision:
                    decision_by_finding_id[finding_id] = bundle.judge_decision

        for finding in result.findings:
            decision = decision_by_finding_id.get(finding.id)
            evidence = evidence_by_finding_id.get(finding.id)
            view = FindingView.from_raw_finding(finding, decision, evidence)
            finding_views.append(view)

        # Calculate verdict counts
        confirmed = sum(1 for v in finding_views if v.verdict == "confirmed")
        suspicious = sum(1 for v in finding_views if v.verdict == "suspicious")
        rejected = sum(1 for v in finding_views if v.verdict == "rejected")

        # Get summary data
        summary = result.summary
        risk_score = summary.risk_score if summary else 0.0
        languages = summary.languages if summary else []

        return cls(
            scan_id=scan_id,
            status="completed",
            total_findings=len(finding_views),
            confirmed_count=confirmed,
            suspicious_count=suspicious,
            rejected_count=rejected,
            risk_score=risk_score,
            languages=languages,
            findings=finding_views,
        )

    def to_dict(self) -> dict[str, Any]:
        """
        Convert to dictionary for JSON serialization.

        Returns:
            Dictionary representation
        """
        return {
            "scan_id": self.scan_id,
            "status": self.status,
            "total_findings": self.total_findings,
            "confirmed_count": self.confirmed_count,
            "suspicious_count": self.suspicious_count,
            "rejected_count": self.rejected_count,
            "risk_score": self.risk_score,
            "languages": self.languages,
            "findings": [f.to_dict() for f in self.findings],
        }