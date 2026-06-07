from typing import Any


def build_prompt(vuln: dict[str, Any], context: str, impact: list[dict[str, Any]]) -> str:
    """构建漏洞分析提示，用于知识图谱证据上下文生成。

    注意：此函数仅用于生成漏洞证据和分析上下文，不生成补丁。
    """
    return f"""You are a vulnerability analysis assistant.

Vulnerability type: {vuln["type"]}
Location: {vuln["file"]}:{vuln["line"]}
Severity: {vuln.get("severity", "UNKNOWN")}
CWE: {vuln.get("cwe", "N/A")}
Risk Score: {vuln.get("risk_score", 0)}
Confidence: {vuln.get("confidence", "low")}
Impact paths: {impact}

Relevant context:
{context}

Provide a concise analysis of:
1. Why this is a vulnerability
2. Potential security impact
3. Recommended mitigation approach (high-level, not code patch)

Return strict JSON:
{{
  "analysis": "...",
  "impact_description": "...",
  "mitigation_recommendation": "..."
}}
"""
