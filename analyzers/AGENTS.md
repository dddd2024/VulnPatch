# Analyzers 模块治理规范

## 本模块职责

静态分析引擎，负责检测源代码中的安全漏洞。

**核心任务**:
- 模式匹配分析（Pattern Analysis）
- 抽象语法树分析（AST Analysis）
- 污点流分析（Taint Analysis）

**注意**: Analyzers 只进行静态分析，**不调用 LLM**，**不直接读取文件系统**。

---

## 允许输入

### 输入类型
- `CodeUnit` - 代码单元对象（来自 `audit_core.models`）
- 配置文件（规则定义文件）

### 输入来源
- 仅通过 `analyze(code_units: list[CodeUnit])` 方法接收输入
- 禁止直接读取文件系统

---

## 允许输出

### 输出类型
- `RawFinding` - 原始发现（来自 `audit_core.models`）

### 输出要求
- 每个发现必须包含：`rule_id`, `type`, `severity`, `confidence`, `file_path`, `start_line`, `message`, `engine`
- 可选字段：`cwe`, `end_line`, `evidence`, `metadata`

---

## 禁止跨模块行为

### 绝对禁止
1. ❌ **禁止导入 `agents` 模块**
   ```python
   # 禁止
   from agents.recon_agent import ReconAgent
   from agents.analysis_agent import AnalysisAgent
   ```

2. ❌ **禁止导入 `llm` 模块**
   ```python
   # 禁止
   from llm import SomeLLMClient
   ```

3. ❌ **禁止直接调用 LLM API**
   ```python
   # 禁止
   response = openai.ChatCompletion.create(...)
   ```

4. ❌ **禁止直接读取文件系统**
   ```python
   # 禁止
   with open("some_file.py") as f:
       content = f.read()
   ```

5. ❌ **禁止修改 `audit_core/models.py`**

6. ❌ **禁止修改 API 路由**

### 允许的内部导入
```python
# 允许
from audit_core.models import CodeUnit, RawFinding
from analyzers.base import BaseAnalyzer
from analyzers.pattern_analyzer import PatternAnalyzer
```

---

## 必须遵守的数据模型

### CodeUnit（输入）
```python
class CodeUnit(BaseModel):
    id: str
    path: str
    language: str
    content: str
    start_line: int
    end_line: Optional[int]
    metadata: dict[str, Any]
```

### RawFinding（输出）
```python
class RawFinding(BaseModel):
    id: str
    rule_id: str
    type: str
    cwe: Optional[str]
    severity: str  # ERROR, WARN, INFO, etc.
    confidence: str  # high, medium, low
    file_path: str
    start_line: int
    end_line: Optional[int]
    message: str
    engine: str
    evidence: dict[str, Any]
    metadata: dict[str, Any]
```

---

## 实现规范

### 创建新分析器

1. 继承 `BaseAnalyzer`
2. 实现 `analyze(self, code_units: list[CodeUnit]) -> list[RawFinding]`
3. 设置 `name` 和 `supported_languages` 类属性
4. 在 `audit_core/registry.py` 中注册

```python
from analyzers.base import BaseAnalyzer
from audit_core.models import CodeUnit, RawFinding

class MyAnalyzer(BaseAnalyzer):
    name = "my_analyzer"
    supported_languages = ["python", "javascript"]
    
    def analyze(self, code_units: list[CodeUnit]) -> list[RawFinding]:
        findings = []
        for unit in code_units:
            # 分析逻辑
            if self._has_vulnerability(unit):
                findings.append(RawFinding(
                    rule_id="MY_RULE_001",
                    type="Vulnerability Type",
                    severity="ERROR",
                    confidence="high",
                    file_path=unit.path,
                    start_line=10,
                    message="Description of the vulnerability",
                    engine=self.name
                ))
        return findings
```

---

## 提交前检查清单

- [ ] 我没有导入 `agents` 或 `llm` 模块
- [ ] 我没有直接调用 LLM API
- [ ] 我没有直接读取文件系统
- [ ] 我的分析器输出符合 `RawFinding` 模型
- [ ] 我的分析器已注册到 `AnalyzerRegistry`
- [ ] 所有单元测试通过
- [ ] 架构守卫检查通过

---

## 修改记录

| 日期 | 修改人 | 修改内容 |
|------|--------|----------|
| 2026-05-30 | Core Orchestrator | 初始版本 |
