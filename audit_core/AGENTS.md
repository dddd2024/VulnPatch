# Audit Core 模块治理规范

## 本模块职责

核心数据模型和编排逻辑，是整个系统的中央枢纽。

**核心任务**:
- 定义统一数据模型
- 实现 AuditOrchestrator 主入口
- 管理 Analyzer 注册表
- 实现结果合并和评分逻辑

**注意**: Audit Core 是公共契约，**修改需全员讨论**。

---

## 允许输入

### 输入类型
- `CodeUnit` - 代码单元
- `RawFinding` - 原始发现
- `AgentHypothesis` - Agent 假设
- `EvidenceBundle` - 证据包
- 配置文件

### 输入来源
- 各模块通过参数传递
- 配置文件

---

## 允许输出

### 输出类型
- `AuditResult` - 审计结果
- `AuditSummary` - 审计摘要
- `RawFinding` - 原始发现
- `EvidenceBundle` - 证据包

### 输出要求
- `AuditResult` 必须包含：`summary`, `findings`, `evidence`, `agent_logs`
- 所有模型必须可序列化为 JSON

---

## 禁止跨模块行为

### 绝对禁止
1. ❌ **禁止在 Core 中实现具体检测逻辑**
   ```python
   # 禁止
   class AuditOrchestrator:
       def _detect_sql_injection(self, code):
           # 不要在 Core 中实现检测规则
           if "SELECT" in code:
               return True
   ```

2. ❌ **禁止直接调用 LLM**
   ```python
   # 禁止
   import openai
   response = openai.ChatCompletion.create(...)
   ```

3. ❌ **禁止直接读取文件系统（ingest 除外）**

### 允许的内部导入
```python
# 允许
from audit_core.models import CodeUnit, RawFinding, AuditResult
from audit_core.registry import AnalyzerRegistry
from audit_core.orchestrator import AuditOrchestrator
from ingest.repo_loader import RepoLoader
```

---

## 必须遵守的数据模型

### CodeUnit（输入单元）
```python
class CodeUnit(BaseModel):
    id: str = Field(default_factory=generate_id)
    path: str
    language: str
    content: str
    start_line: int = 1
    end_line: Optional[int] = None
    metadata: dict[str, Any] = Field(default_factory=dict)
```

### RawFinding（分析器输出）
```python
class RawFinding(BaseModel):
    id: str = Field(default_factory=generate_id)
    rule_id: str
    type: str
    cwe: Optional[str] = None
    severity: str = "UNKNOWN"
    confidence: str = "low"
    file_path: str
    start_line: int
    end_line: Optional[int] = None
    message: str
    engine: str
    evidence: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)
```

### AuditResult（最终输出）
```python
class AuditResult(BaseModel):
    summary: AuditSummary
    findings: list[RawFinding] = Field(default_factory=list)
    evidence: list[EvidenceBundle] = Field(default_factory=list)
    agent_logs: list[AgentLog] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    
    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")
```

---

## 修改数据模型的规则

### 可以修改（无需讨论）
- 添加新的可选字段
- 修改方法实现
- 添加新的辅助函数

### 必须讨论（全员同意）
- 删除字段
- 修改字段类型
- 修改必填字段
- 修改字段含义

### 修改流程
1. 在群里发起讨论
2. 说明修改原因和影响
3. 所有成员同意后修改
4. 更新相关 Schema 和文档
5. 通知全员同步更新

---

## 实现规范

### Orchestrator 主入口

```python
class AuditOrchestrator:
    """
    Main orchestrator for the audit pipeline.
    This is the primary entry point for new audit workflows.
    """
    
    def __init__(self, registry: AnalyzerRegistry | None = None):
        self.registry = registry or build_default_registry()
        self.repo_loader = RepoLoader()
        # ... 初始化 Agents
    
    def scan(self, *, input_type: str, ...) -> AuditResult:
        """
        Main scan entry point.
        """
        # 1. Load code units
        # 2. Run analyzers
        # 3. Merge findings
        # 4. Run agents
        # 5. Build evidence
        # 6. Return result
```

### 模型定义

```python
from pydantic import BaseModel, Field
from typing import Any, Optional

class MyModel(BaseModel):
    """
    Model description.
    """
    id: str = Field(default_factory=generate_id)
    required_field: str
    optional_field: Optional[str] = None
    list_field: list[str] = Field(default_factory=list)
    dict_field: dict[str, Any] = Field(default_factory=dict)
    
    class Config:
        frozen = False  # 允许修改
```

---

## 提交前检查清单

- [ ] 我没有在 Core 中实现具体检测逻辑
- [ ] 我没有直接调用 LLM
- [ ] 所有模型可序列化为 JSON
- [ ] 如果修改了数据模型，已征得全员同意
- [ ] 已更新相关 Schema
- [ ] 已更新 ARCHITECTURE.md
- [ ] 所有单元测试通过
- [ ] 架构守卫检查通过

---

## 修改记录

| 日期 | 修改人 | 修改内容 |
|------|--------|----------|
| 2026-05-30 | Core Orchestrator | 初始版本 |
