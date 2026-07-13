# VulnPatch Agents

LLM-powered analysis agents for vulnerability detection and assessment.

## Overview

Agents perform reasoning tasks on structured data (CodeUnit, RawFinding, EvidenceBundle) using LLMs. They do NOT directly read files or scan repositories.

## Agent Architecture

### Base Classes

We provide two levels of base classes:

1. **BaseAgent** (`base_agent.py`) - Generic abstract base with flexible `run(*args, **kwargs)` signature
2. **Strongly-typed Interfaces** (`interfaces.py`) - Specific signatures for each Agent role

### Recommended Usage

For specific Agent roles, inherit from the strongly-typed interfaces in `interfaces.py`:

```python
from agents.interfaces import AnalysisAgentBase
from audit_core.models import RawFinding, AgentHypothesis, AgentLog

class MyAnalysisAgent(AnalysisAgentBase):
    name = "my_analysis"

    def run(
        self,
        finding: RawFinding,
        code_unit: CodeUnit | None = None
    ) -> tuple[AgentHypothesis, AgentLog]:
        # Implementation with type safety
        ...
```

## Agent Types

### 1. ReconAgent (Reconnaissance)

**Purpose**: Initial code inspection to identify attack surfaces

**Input**: `list[CodeUnit]`

**Output**: `tuple[list[AgentHypothesis], list[AgentLog]]`

**Base Class**: `ReconAgentBase`

**Detects**:
- Web routes (HTTP endpoints)
- Request parameters (user input sources)
- File operations (read/write)
- SQL operations (database queries)
- Command execution (system calls)
- Deserialization (object loading)

**Example**:
```python
from agents.recon_agent import ReconAgent
from audit_core.models import CodeUnit

agent = ReconAgent()
code_units = [CodeUnit(...), ...]
hypotheses, logs = agent.run(code_units)
```

### 2. AnalysisAgent

**Purpose**: Analyze findings and generate vulnerability hypotheses

**Input**: 
- `finding: RawFinding` - The finding to analyze
- `code_unit: CodeUnit | None` - Optional context

**Output**: `tuple[AgentHypothesis, AgentLog]`

**Base Class**: `AnalysisAgentBase`

**Features**:
- LLM analysis (placeholder for Stage 2)
- Rule-based fallback when LLM unavailable
- Type-specific reasoning

**Example**:
```python
from agents.analysis_agent import AnalysisAgent
from audit_core.models import RawFinding

agent = AnalysisAgent()
finding = RawFinding(...)
hypothesis, log = agent.run(finding, code_unit=None)
```

### 3. JudgeAgent

**Purpose**: Make final decisions on vulnerability validity

**Input**:
- `finding: RawFinding` - The finding to evaluate
- `hypotheses: list[AgentHypothesis]` - Hypotheses from other agents
- `evidence_bundle: EvidenceBundle | None` - Supporting evidence

**Output**: `tuple[JudgeDecision, AgentLog]`

**Base Class**: `JudgeAgentBase`

**Verdicts**:
- `confirmed` - High confidence vulnerability (risk >= 70)
- `suspicious` - Potential vulnerability requiring review (risk >= 30)
- `rejected` - False positive or low-risk (risk < 30)

**Scoring**:
- Risk score (0-100) based on severity, confidence, and evidence
- Severity weight: 50%
- Confidence weight: 30%
- Evidence weight: 20%

**Example**:
```python
from agents.judge_agent import JudgeAgent
from audit_core.models import RawFinding, AgentHypothesis

agent = JudgeAgent()
finding = RawFinding(...)
hypotheses = [AgentHypothesis(...), ...]
decision, log = agent.run(finding, hypotheses, evidence_bundle=None)

print(decision.verdict)  # "confirmed", "suspicious", or "rejected"
print(decision.risk_score)  # 0-100
```

## Input/Output Contracts

### ReconAgent

```python
def run(self, code_units: list[CodeUnit]) -> tuple[list[AgentHypothesis], list[AgentLog]]:
    """
    Args:
        code_units: List of code units to inspect

    Returns:
        - hypotheses: Attack surface hypotheses for significant findings
        - logs: Execution logs for audit trail
    """
```

### AnalysisAgent

```python
def run(
    self,
    finding: RawFinding,
    code_unit: CodeUnit | None = None,
) -> tuple[AgentHypothesis, AgentLog]:
    """
    Args:
        finding: The RawFinding to analyze
        code_unit: Optional CodeUnit containing the finding

    Returns:
        - hypothesis: Vulnerability hypothesis with reasoning
        - log: Execution log for audit trail
    """
```

### JudgeAgent

```python
def run(
    self,
    finding: RawFinding,
    hypotheses: list[AgentHypothesis],
    evidence_bundle: EvidenceBundle | None = None,
) -> tuple[JudgeDecision, AgentLog]:
    """
    Args:
        finding: The RawFinding to evaluate
        hypotheses: List of AgentHypothesis from other agents
        evidence_bundle: Optional EvidenceBundle with evidence

    Returns:
        - decision: Final verdict with risk score and reasoning
        - log: Execution log for audit trail
    """
```

## Data Models

Agents work with these core models from `audit_core.models`:

- **CodeUnit**: Code file with path, language, content, AST
- **RawFinding**: Analyzer output with type, severity, location
- **AgentHypothesis**: Agent's vulnerability assessment
- **AgentLog**: Execution trace and audit trail
- **JudgeDecision**: Final verdict with risk score
- **EvidenceBundle**: Supporting evidence (snippets, call chains)

## Constraints

### Agents MUST NOT:
- Read files directly (use CodeUnit.content)
- Call analyzers directly
- Modify audit_core/models.py

### Agents MUST:
- Process only structured objects
- Support LLM fallback (AnalysisAgent)
- Return typed results per interface contract
- Log all activity via AgentLog

## Testing

Run Agent tests:
```bash
python -m pytest tests/test_agents.py -v
python -m pytest tests/test_recon_agent.py -v
python -m pytest tests/test_analysis_agent.py -v
python -m pytest tests/test_judge_agent.py -v
```

## Future Work (Stage 2)

- Real LLM integration for AnalysisAgent
- Additional Agent roles (PatchAgent, ExploitAgent)
- Agent-to-Agent communication protocol
- Streaming agent responses
