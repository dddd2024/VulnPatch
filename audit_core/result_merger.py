"""
Result merger for deduplicating findings from multiple analyzers.

When multiple analyzers detect the same vulnerability, this module
merges them into a single finding with combined metadata.
"""

from audit_core.models import RawFinding


def merge_findings(findings: list[RawFinding]) -> list[RawFinding]:
    """
    Merge duplicate findings from multiple analyzers.
    
    Findings are considered duplicates if they have the same:
    - type (vulnerability type)
    - file_path
    - start_line
    - rule_id
    
    When duplicates are found, they are merged into a single finding
    with metadata indicating which engines detected it.
    
    Args:
        findings: List of raw findings from all analyzers
        
    Returns:
        List of deduplicated findings
    """
    # Group findings by their deduplication key
    grouped: dict[tuple, RawFinding] = {}
    
    for finding in findings:
        # Create a key for deduplication
        key = (
            finding.type,
            finding.file_path,
            finding.start_line,
            finding.rule_id
        )
        
        if key not in grouped:
            # First occurrence - store it
            grouped[key] = finding
        else:
            # Duplicate found - merge metadata
            existing = grouped[key]
            
            # Combine engines in metadata
            existing_engines = existing.metadata.get("engines", [existing.engine])
            new_engines = existing_engines + [finding.engine]
            existing.metadata["engines"] = list(set(new_engines))  # Remove duplicates
            
            # Keep the higher severity
            severity_order = {"CRITICAL": 4, "ERROR": 3, "HIGH": 3, "WARN": 2, "MEDIUM": 2, "INFO": 1, "LOW": 1, "UNKNOWN": 0}
            existing_sev = severity_order.get(existing.severity.upper(), 0)
            new_sev = severity_order.get(finding.severity.upper(), 0)
            if new_sev > existing_sev:
                existing.severity = finding.severity
            
            # Keep the higher confidence
            confidence_order = {"high": 2, "medium": 1, "low": 0}
            existing_conf = confidence_order.get(existing.confidence.lower(), 0)
            new_conf = confidence_order.get(finding.confidence.lower(), 0)
            if new_conf > existing_conf:
                existing.confidence = finding.confidence
            
            # Merge evidence
            for k, v in finding.evidence.items():
                if k not in existing.evidence:
                    existing.evidence[k] = v
    
    return list(grouped.values())
