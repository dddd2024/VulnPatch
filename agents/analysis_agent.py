"""
Analysis agent for vulnerability hypothesis generation.

The AnalysisAgent analyzes RawFinding objects and generates hypotheses
about potential vulnerabilities using LLM or fallback logic.
"""

from typing import Any

from audit_core.models import RawFinding, AgentHypothesis, AgentLog, CodeUnit
from agents.interfaces import AnalysisAgentBase
from knowledge.rag_retriever import RagRetriever
from knowledge.cwe_mapper import get_cwe_id


class AnalysisAgent(AnalysisAgentBase):
    name = "analysis"
    SEVERITY_CONFIDENCE = {"ERROR": "high", "WARN": "medium", "INFO": "low"}
    TYPE_VULN_MAP = {
        "sql_injection": "SQL Injection", "command_injection": "Command Injection",
        "xss": "Cross-Site Scripting (XSS)", "path_traversal": "Path Traversal",
        "deserialization": "Insecure Deserialization", "ssrf": "Server-Side Request Forgery (SSRF)",
        "file_upload": "Unrestricted File Upload", "hardcoded_secret": "Hardcoded Secret",
        "weak_crypto": "Weak Cryptography", "insecure_random": "Insecure Randomness",
        "debug_info": "Debug Information Exposure", "info_disclosure": "Information Disclosure",
    }

    def __init__(self, llm_client: Any | None = None, rag_retriever: RagRetriever | None = None) -> None:
        self._llm_client = llm_client
        self._rag_retriever = rag_retriever or RagRetriever()

    def get_llm_client(self) -> Any | None:
        return self._llm_client

    def set_llm_client(self, llm_client: Any | None) -> None:
        self._llm_client = llm_client

    def run(self, finding: RawFinding, code_unit: CodeUnit | None = None) -> tuple[AgentHypothesis, AgentLog]:
        if self._llm_client is not None:
            try:
                return self._analyze_with_llm(finding, code_unit)
            except Exception:
                pass
        return self._analyze_with_fallback(finding, code_unit)

    def _analyze_with_llm(self, finding: RawFinding, code_unit: CodeUnit | None = None) -> tuple[AgentHypothesis, AgentLog]:
        rag_context, rag_context_ids = self._retrieve_rag_context(finding, code_unit)
        prompt = self._build_llm_prompt(finding, code_unit, rag_context=rag_context)
        response = self._llm_client.generate(prompt, system_prompt=self.ANALYSIS_SYSTEM_PROMPT, temperature=0.2, max_tokens=4096)
        if not response.success or not response.content:
            raise Exception("LLM analysis failed")
        confidence = self.SEVERITY_CONFIDENCE.get(finding.severity, "low")
        cwe_id = get_cwe_id(finding.type)
        normalized_type = finding.type.lower().replace(" ", "_")
        vuln_type = self.TYPE_VULN_MAP.get(normalized_type, finding.type)
        metadata = {
            "finding_type": finding.type, "finding_severity": finding.severity,
            "engine": finding.engine, "file_path": finding.file_path,
            "line_number": finding.start_line, "has_code_context": code_unit is not None,
            "analysis_method": "llm", "cwe": finding.cwe, "cwe_id": cwe_id,
            "rag_context_count": len(rag_context), "rag_context_ids": rag_context_ids,
        }
        hypothesis = AgentHypothesis(agent_name=self.name, finding_id=finding.id, hypothesis=f"{vuln_type} vulnerability detected", vulnerability_type=vuln_type, reasoning_summary=response.content, confidence=confidence, supporting_evidence_ids=[finding.id], metadata=metadata)
        llm_provider = getattr(self._llm_client, 'provider_name', None) or getattr(self._llm_client, 'name', 'unknown')
        log = AgentLog(agent_name=self.name, stage="analysis", message=f"Analyzed {finding.type} finding in {finding.file_path}:{finding.start_line}", input_refs=[finding.id], output_refs=[hypothesis.id], metadata={"analysis_method": "llm", "llm_provider": llm_provider, "vulnerability_type": finding.type, "confidence": confidence, "cwe_id": cwe_id, "rag_context_count": len(rag_context)})
        return hypothesis, log

    ANALYSIS_SYSTEM_PROMPT = """You are an expert security auditor performing vulnerability analysis. You must provide a thorough, structured analysis.

For each finding, analyze:
1. **What**: Describe the vulnerability type and its nature
2. **Why**: Explain why this code pattern is dangerous, including attack scenarios
3. **Impact**: Assess the potential damage if exploited (Confidentiality/Integrity/Availability)
4. **Exploitability**: How easy is it to exploit? What conditions are needed?
5. **Evidence**: What specific code constructs support this finding?
6. **Remediation**: Provide specific, actionable fix recommendations with code examples

Be precise and technical. Reference relevant CWE IDs when applicable.
Always consider real-world attack scenarios."""

    def _build_llm_prompt(self, finding: RawFinding, code_unit: CodeUnit | None = None, rag_context: list[dict[str, Any]] | None = None) -> str:
        prompt_parts = [
            "## Security Finding Analysis", "",
            f"**Vulnerability Type**: {finding.type}", f"**Finding Type**: {finding.type}",
            f"**CWE**: {finding.cwe}", f"**Severity**: {finding.severity}",
            f"**Confidence**: {finding.confidence}", f"**Location**: `{finding.file_path}:{finding.start_line}`",
            "", "**Finding Message**:", f"> {finding.message}",
        ]
        if code_unit:
            lines = code_unit.content.split("\n")
            start = max(0, finding.start_line - 5)
            end = min(len(lines), finding.start_line + 10)
            relevant_code = "\n".join(lines[start:end])
            prompt_parts.extend(["", f"**Code Context** ({finding.file_path}, lines {start+1}-{end}):", f"```{code_unit.language or ''}", relevant_code, "```"])
        if rag_context:
            prompt_parts.extend(["", "**Retrieved security knowledge (use as grounded context):**"])
            for item in rag_context[:3]:
                prompt_parts.append(f"- {item.get('cwe_id', '')} {item.get('title', '')}: {item.get('summary', '')} Remediation: {item.get('remediation', '')}")
        prompt_parts.extend(["", "Provide a comprehensive security analysis following the What-Why-How framework.", "Include specific attack scenarios and remediation code."])
        return "\n".join(prompt_parts)

    def _analyze_with_fallback(self, finding: RawFinding, code_unit: CodeUnit | None = None) -> tuple[AgentHypothesis, AgentLog]:
        normalized_type = finding.type.lower().replace(" ", "_")
        vuln_type = self.TYPE_VULN_MAP.get(normalized_type, f"Potential {finding.type.replace('_', ' ').title()}")
        confidence = self.SEVERITY_CONFIDENCE.get(finding.severity, "low")
        cwe_id = get_cwe_id(finding.type)
        rag_context, rag_context_ids = self._retrieve_rag_context(finding, code_unit)
        reasoning = self._generate_reasoning(finding, code_unit, rag_context)
        metadata = {"finding_type": finding.type, "finding_severity": finding.severity, "engine": finding.engine, "file_path": finding.file_path, "line_number": finding.start_line, "has_code_context": code_unit is not None, "analysis_method": "fallback", "rag_context_count": len(rag_context), "rag_context_ids": rag_context_ids, "cwe_id": cwe_id}
        hypothesis = AgentHypothesis(agent_name=self.name, finding_id=finding.id, hypothesis=f"{vuln_type} vulnerability detected", vulnerability_type=vuln_type, reasoning_summary=reasoning, confidence=confidence, supporting_evidence_ids=[finding.id], metadata=metadata)
        log = AgentLog(agent_name=self.name, stage="analysis", message=f"Analyzed {finding.type} finding in {finding.file_path}:{finding.start_line}", input_refs=[finding.id], output_refs=[hypothesis.id], metadata={"analysis_method": "fallback", "vulnerability_type": vuln_type, "confidence": confidence, "cwe_id": cwe_id, "rag_context_count": len(rag_context)})
        return hypothesis, log

    def _retrieve_rag_context(self, finding: RawFinding, code_unit: CodeUnit | None = None) -> tuple[list[dict[str, Any]], list[str]]:
        try:
            query_parts = [finding.type, finding.message]
            if code_unit:
                query_parts.append(code_unit.language)
            rag_results = self._rag_retriever.retrieve(" ".join(query_parts), top_k=3)
            return rag_results, [result["id"] for result in rag_results]
        except Exception:
            return [], []

    def _generate_reasoning(self, finding: RawFinding, code_unit: CodeUnit | None = None, rag_context: list[dict[str, Any]] | None = None) -> str:
        base_reasoning = finding.message
        if finding.type:
            base_reasoning = f"{finding.type}: {base_reasoning}"
        if code_unit:
            base_reasoning += f" Context from {code_unit.path} supports this assessment."
        type_reasoning = {
            "sql_injection": "User input flows directly into SQL query without sanitization.",
            "command_injection": "User input is passed to command execution functions.",
            "xss": "User input is rendered in HTML without proper encoding.",
            "path_traversal": "User input is used to construct file paths without validation.",
            "deserialization": "Untrusted data is deserialized without type checking.",
            "ssrf": "User-controlled URL is used for server-side requests.",
            "file_upload": "File upload lacks validation of file type and content.",
            "hardcoded_secret": "Sensitive credentials are hardcoded in source code.",
            "weak_crypto": "Weak cryptographic algorithms or improper usage detected.",
            "insecure_random": "Predictable random number generation for security purposes.",
        }
        specific = type_reasoning.get(finding.type, "")
        if specific:
            base_reasoning += f" {specific}"
        if rag_context:
            base_reasoning += self._format_rag_context(rag_context)
        return base_reasoning

    def _format_rag_context(self, rag_context: list[dict[str, Any]]) -> str:
        if not rag_context:
            return ""
        parts = ["\n\nRelevant security knowledge:"]
        for i, item in enumerate(rag_context[:3], 1):
            parts.append(f"\n[{i}] {item['title']} ({item['cwe_id']}):")
            parts.append(f"    {item['summary']}")
            if item.get('remediation'):
                parts.append(f"    Remediation: {item['remediation']}")
        return " ".join(parts)
