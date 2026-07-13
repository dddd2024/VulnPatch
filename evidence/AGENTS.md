# Evidence 模块治理规范

## 本模块职责

证据收集和管理，负责构建完整的漏洞证据包。

**核心任务**:
- 代码片段提取
- 调用链构建
- 置信度记录
- 证据包组装

**注意**: Evidence 只处理结构化对象，**不直接读取文件系统**。

---

## 允许输入

### 输入类型
- `CodeUnit` - 代码单元对象
- `RawFinding` - 分析器发现
- `AgentHypothesis` - Agent 假设
- `AgentLog` - Agent 日志
- `JudgeDecision` - 裁决决定

### 输入来源
- 仅通过函数参数接收输入
- 禁止直接读取文件系统

---

## 允许输出

### 输出类型
- `EvidenceBundle` - 证据包
- `dict` - 代码片段信息
- `dict` - 置信度记录

### 输出要求
- `EvidenceBundle` 必须包含：`finding`, `snippets`, `agent_hypotheses`, `judge_decision`

---

## 禁止跨模块行为

### 绝对禁止
1. ❌ **禁止直接读取文件系统**
   ```python
   # 禁止
   with open("some_file.py") as f:
       content = f.read()
   ```

2. ❌ **禁止直接调用 Analyzers**
   ```python
   # 禁止
   from analyzers.pattern_analyzer import PatternAnalyzer
   analyzer = PatternAnalyzer()
   ```

3. ❌ **禁止直接调用 Agents**
   ```python
   # 禁止
   from agents.analysis_agent import AnalysisAgent
   agent = AnalysisAgent()
   ```

4. ❌ **禁止修改 `audit_core/models.py`**

### 允许的内部导入
```python
# 允许
from audit_core.models import CodeUnit, RawFinding, EvidenceBundle
from evidence.snippet_extractor import extract_snippet
from knowledge.cwe_mapper import map_cwe
```

---

## 必须遵守的数据模型

### 输入模型
```python
# CodeUnit
class CodeUnit(BaseModel):
    id: str
    path: str
    language: str
    content: str
    start_line: int
    end_line: Optional[int]

# RawFinding
class RawFinding(BaseModel):
    id: str
    rule_id: str
    type: str
    severity: str
    confidence: str
    file_path: str
    start_line: int
    end_line: Optional[int]
    message: str
```

### 输出模型
```python
# EvidenceBundle
class EvidenceBundle(BaseModel):
    id: str
    finding: RawFinding
    code_unit: Optional[CodeUnit]
    snippets: list[dict[str, Any]]
    call_chain: list[dict[str, Any]]
    agent_hypotheses: list[AgentHypothesis]
    agent_logs: list[AgentLog]
    judge_decision: Optional[JudgeDecision]
    cwe_info: dict[str, Any]
    score_breakdown: dict[str, Any]
    metadata: dict[str, Any]
```

### 代码片段格式
```python
{
    "file_path": str,
    "start_line": int,
    "end_line": int,
    "content": str,
    "vulnerability_start": int,
    "vulnerability_end": int
}
```

---

## 实现规范

### 代码片段提取

```python
from audit_core.models import CodeUnit

def extract_snippet(
    code_unit: CodeUnit,
    start_line: int,
    end_line: Optional[int] = None,
    context_lines: int = 3
) -> dict:
    """
    Extract code snippet with context.
    
    Args:
        code_unit: The code unit containing the snippet
        start_line: Starting line of the vulnerable code
        end_line: Ending line of the vulnerable code
        context_lines: Number of context lines to include
    
    Returns:
        Dictionary with snippet information
    """
    # 从 code_unit.content 提取，不要读取文件
    lines = code_unit.content.split("\n")
    # ... 提取逻辑
```

### 证据包构建

```python
from audit_core.models import RawFinding, EvidenceBundle
from evidence.snippet_extractor import extract_snippet

def build_evidence_bundle(
    finding: RawFinding,
    code_unit: Optional[CodeUnit],
    hypotheses: list[AgentHypothesis],
    agent_logs: list[AgentLog],
    judge_decision: Optional[JudgeDecision]
) -> EvidenceBundle:
    """
    Build complete evidence bundle.
    """
    # 提取代码片段
    snippets = []
    if code_unit:
        snippet = extract_snippet(
            code_unit,
            finding.start_line,
            finding.end_line
        )
        snippets.append(snippet)
    
    # 构建证据包
    return EvidenceBundle(
        finding=finding,
        code_unit=code_unit,
        snippets=snippets,
        agent_hypotheses=hypotheses,
        agent_logs=agent_logs,
        judge_decision=judge_decision
    )
```

---

## 提交前检查清单

- [ ] 我没有直接读取文件系统
- [ ] 我没有直接调用 Analyzers
- [ ] 我没有直接调用 Agents
- [ ] 我的函数只处理结构化对象
- [ ] 我的输出符合 `EvidenceBundle` 模型
- [ ] 我没有修改 `audit_core/models.py`
- [ ] 所有单元测试通过
- [ ] 架构守卫检查通过

---

## 修改记录

| 日期 | 修改人 | 修改内容 |
|------|--------|----------|
| 2026-05-30 | Core Orchestrator | 初始版本 |
