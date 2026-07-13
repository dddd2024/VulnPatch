"""
Vulnerability graph for knowledge representation.

Builds and manages vulnerability knowledge graphs from EvidenceBundle objects.
Implements a lightweight graph builder without external dependencies.
"""

from typing import Any
from audit_core.models import EvidenceBundle


class VulnerabilityGraph:
    """
    Graph representation of vulnerability relationships.
    
    Builds a lightweight graph structure from EvidenceBundle objects,
    showing relationships between findings, files, CWEs, hypotheses, and decisions.
    
    Features:
    - No external dependencies (no network, no networkx)
    - JSON-serializable output
    - Node and edge deduplication
    - Graceful handling of missing data
    """
    
    def __init__(self) -> None:
        """Initialize the vulnerability graph builder."""
        self._nodes: dict[str, dict[str, Any]] = {}
        self._edges: list[dict[str, Any]] = []
    
    def build(self, evidence_bundles: list[EvidenceBundle]) -> dict[str, Any]:
        """
        Build a vulnerability graph from evidence bundles.
        
        Args:
            evidence_bundles: List of evidence bundles to build graph from
            
        Returns:
            Dictionary with:
            - nodes: List of node objects
            - edges: List of edge objects
            
        Node types:
        - finding: Vulnerability finding
        - file: Source code file
        - cwe: CWE classification
        - agent_hypothesis: Agent-generated hypothesis
        - judge_decision: Judge agent decision
        
        Edge relations:
        - contains: file -> finding
        - classified_as: finding -> cwe
        - supported_by: finding -> agent_hypothesis
        - judged_as: finding -> judge_decision
        """
        # Reset state
        self._nodes = {}
        self._edges = []
        
        # Handle empty input
        if not evidence_bundles:
            return {"nodes": [], "edges": []}
        
        # Process each evidence bundle
        for bundle in evidence_bundles:
            self._process_bundle(bundle)
        
        # Return graph structure
        return {
            "nodes": list(self._nodes.values()),
            "edges": self._edges,
        }
    
    def _process_bundle(self, bundle: EvidenceBundle) -> None:
        """
        Process a single evidence bundle and add nodes/edges to the graph.
        
        Args:
            bundle: EvidenceBundle to process
        """
        # Add finding node
        finding_node_id = self._add_finding_node(bundle.finding)
        
        # Add file node and edge (if code_unit exists)
        if bundle.code_unit:
            file_node_id = self._add_file_node(bundle.code_unit)
            self._add_edge(file_node_id, finding_node_id, "contains", {
                "file_path": bundle.code_unit.path,
                "language": bundle.code_unit.language,
            })
        
        # Add CWE node and edge (if cwe_info exists and has content)
        if bundle.cwe_info and len(bundle.cwe_info) > 0:
            cwe_node_id = self._add_cwe_node(bundle.cwe_info)
            self._add_edge(finding_node_id, cwe_node_id, "classified_as", {
                "cwe_id": bundle.cwe_info.get("id"),
                "cwe_name": bundle.cwe_info.get("name"),
            })
        
        # Add agent hypothesis nodes and edges
        for hypothesis in bundle.agent_hypotheses:
            hypo_node_id = self._add_hypothesis_node(hypothesis)
            self._add_edge(finding_node_id, hypo_node_id, "supported_by", {
                "agent_name": hypothesis.agent_name,
                "confidence": hypothesis.confidence,
            })
        
        # Add judge decision node and edge (if exists)
        if bundle.judge_decision:
            decision_node_id = self._add_decision_node(bundle.judge_decision)
            self._add_edge(finding_node_id, decision_node_id, "judged_as", {
                "verdict": bundle.judge_decision.verdict,
                "risk_score": bundle.judge_decision.risk_score,
            })
    
    def _add_finding_node(self, finding: Any) -> str:
        """
        Add a finding node to the graph.
        
        Args:
            finding: RawFinding object
            
        Returns:
            Node ID
        """
        node_id = f"finding:{finding.id}"
        if node_id not in self._nodes:
            self._nodes[node_id] = {
                "id": node_id,
                "type": "finding",
                "label": f"Finding: {finding.type}",
                "metadata": {
                    "finding_id": finding.id,
                    "rule_id": finding.rule_id,
                    "type": finding.type,
                    "severity": finding.severity,
                    "confidence": finding.confidence,
                    "file_path": finding.file_path,
                    "start_line": finding.start_line,
                    "end_line": finding.end_line,
                    "message": finding.message,
                    "engine": finding.engine,
                }
            }
        return node_id
    
    def _add_file_node(self, code_unit: Any) -> str:
        """
        Add a file node to the graph.
        
        Args:
            code_unit: CodeUnit object
            
        Returns:
            Node ID
        """
        node_id = f"file:{code_unit.id}"
        if node_id not in self._nodes:
            self._nodes[node_id] = {
                "id": node_id,
                "type": "file",
                "label": f"File: {code_unit.path}",
                "metadata": {
                    "code_unit_id": code_unit.id,
                    "path": code_unit.path,
                    "language": code_unit.language,
                    "start_line": code_unit.start_line,
                    "end_line": code_unit.end_line,
                }
            }
        return node_id
    
    def _add_cwe_node(self, cwe_info: dict[str, Any]) -> str:
        """
        Add a CWE node to the graph.
        
        Args:
            cwe_info: CWE information dictionary
            
        Returns:
            Node ID
        """
        cwe_id = cwe_info.get("id", "CWE-UNKNOWN")
        node_id = f"cwe:{cwe_id}"
        if node_id not in self._nodes:
            self._nodes[node_id] = {
                "id": node_id,
                "type": "cwe",
                "label": f"CWE: {cwe_info.get('name', cwe_id)}",
                "metadata": {
                    "cwe_id": cwe_id,
                    "cwe_name": cwe_info.get("name", "Unknown"),
                    "description": cwe_info.get("description", ""),
                }
            }
        return node_id
    
    def _add_hypothesis_node(self, hypothesis: Any) -> str:
        """
        Add an agent hypothesis node to the graph.
        
        Args:
            hypothesis: AgentHypothesis object
            
        Returns:
            Node ID
        """
        node_id = f"hypothesis:{hypothesis.id}"
        if node_id not in self._nodes:
            self._nodes[node_id] = {
                "id": node_id,
                "type": "agent_hypothesis",
                "label": f"Hypothesis: {hypothesis.agent_name}",
                "metadata": {
                    "hypothesis_id": hypothesis.id,
                    "agent_name": hypothesis.agent_name,
                    "finding_id": hypothesis.finding_id,
                    "vulnerability_type": hypothesis.vulnerability_type,
                    "confidence": hypothesis.confidence,
                    "hypothesis_text": hypothesis.hypothesis,
                    "reasoning_summary": hypothesis.reasoning_summary,
                }
            }
        return node_id
    
    def _add_decision_node(self, decision: Any) -> str:
        """
        Add a judge decision node to the graph.
        
        Args:
            decision: JudgeDecision object
            
        Returns:
            Node ID
        """
        node_id = f"decision:{decision.id}"
        if node_id not in self._nodes:
            self._nodes[node_id] = {
                "id": node_id,
                "type": "judge_decision",
                "label": f"Decision: {decision.verdict}",
                "metadata": {
                    "decision_id": decision.id,
                    "finding_id": decision.finding_id,
                    "verdict": decision.verdict,
                    "confidence": decision.confidence,
                    "risk_score": decision.risk_score,
                    "reason": decision.reason,
                }
            }
        return node_id
    
    def _add_edge(
        self, 
        source: str, 
        target: str, 
        relation: str, 
        metadata: dict[str, Any] | None = None
    ) -> None:
        """
        Add an edge to the graph.
        
        Args:
            source: Source node ID
            target: Target node ID
            relation: Relation type
            metadata: Optional edge metadata
        """
        edge = {
            "source": source,
            "target": target,
            "relation": relation,
            "metadata": metadata or {},
        }
        
        # Check for duplicate edges (same source, target, relation)
        edge_key = (source, target, relation)
        existing_edges = [
            (e["source"], e["target"], e["relation"]) 
            for e in self._edges
        ]
        
        if edge_key not in existing_edges:
            self._edges.append(edge)
    
    def reset(self) -> None:
        """Reset the graph builder state."""
        self._nodes = {}
        self._edges = []
    
    def get_node_count(self) -> int:
        """Get the number of nodes in the graph."""
        return len(self._nodes)
    
    def get_edge_count(self) -> int:
        """Get the number of edges in the graph."""
        return len(self._edges)