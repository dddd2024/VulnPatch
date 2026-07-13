# API 模块治理规范

## 本模块职责

API 路由和请求/响应处理，负责对外暴露 HTTP 接口。

**核心任务**:
- 定义 API 路由
- 请求验证和序列化
- 响应格式化
- 错误处理

**注意**: API 层只负责路由和序列化，**不包含检测规则实现**，**不直接调用分析器**。

---

## 允许输入

### 输入类型
- HTTP 请求（GET/POST/PUT/DELETE）
- JSON 请求体
- URL 参数
- 查询参数

### 输入来源
- 仅通过 FastAPI 路由接收输入
- 禁止在路由处理函数中实现业务逻辑

---

## 允许输出

### 输出类型
- JSON 响应
- HTTP 状态码
- 错误信息

### 输出要求
- `/scan` 必须返回包含 `summary`, `findings`, `evidence`, `agent_logs` 的 JSON
- 所有响应必须符合 `contracts/scan_response.schema.json`

---

## 禁止跨模块行为

### 绝对禁止
1. ❌ **禁止在 API 中实现检测规则**
   ```python
   # 禁止
   @router.post("/scan")
   async def scan(request: ScanRequest):
       # 不要在路由中实现检测逻辑
       if "SELECT" in request.code:
           return {"vulnerability": "SQL Injection"}
   ```

2. ❌ **禁止直接调用 Analyzers**
   ```python
   # 禁止
   from analyzers.pattern_analyzer import PatternAnalyzer
   
   @router.post("/scan")
   async def scan(request: ScanRequest):
       analyzer = PatternAnalyzer()
       findings = analyzer.analyze([request.code])
   ```

3. ❌ **禁止直接调用 Agents**
   ```python
   # 禁止
   from agents.analysis_agent import AnalysisAgent
   
   @router.post("/analyze")
   async def analyze(request: AnalyzeRequest):
       agent = AnalysisAgent()
       result = agent.run(request.finding)
   ```

4. ❌ **禁止修改 `audit_core/models.py`**

5. ❌ **禁止修改 Analyzers 或 Agents**

### 允许的做法
```python
# 允许：使用 Orchestrator 作为唯一入口
from audit_core.orchestrator import AuditOrchestrator

orchestrator = AuditOrchestrator()

@router.post("/scan")
async def scan(request: ScanRequest):
    result = orchestrator.scan(
        input_type=request.input_type,
        code=request.code,
        repo_path=request.repo_path
    )
    return result.to_dict()
```

---

## 必须遵守的数据模型

### /scan 返回结构
```python
class ScanResponse(BaseModel):
    summary: dict  # AuditSummary
    findings: list[dict]  # list[RawFinding]
    evidence: list[dict]  # list[EvidenceBundle]
    agent_logs: list[dict]  # list[AgentLog]
```

### 必需字段
```json
{
  "summary": {
    "total_code_units": 0,
    "total_findings": 0,
    "total_evidence_bundles": 0,
    "risk_score": 0.0,
    "languages": [],
    "scanned_files": []
  },
  "findings": [],
  "evidence": [],
  "agent_logs": []
}
```

---

## 实现规范

### 路由定义

```python
from fastapi import APIRouter
from api.schemas import ScanRequest, ScanResponse
from audit_core.orchestrator import AuditOrchestrator

router = APIRouter()
orchestrator = AuditOrchestrator()

@router.post("/scan", response_model=ScanResponse)
async def scan(request: ScanRequest):
    """
    Scan endpoint - delegates to AuditOrchestrator.
    """
    try:
        result = orchestrator.scan(
            input_type=request.input_type,
            code=request.code,
            repo_path=request.repo_path,
            repo_url=request.repo_url,
            language=request.language
        )
        return ScanResponse(
            summary=result.summary.model_dump(mode="json"),
            findings=[f.model_dump(mode="json") for f in result.findings],
            evidence=[e.model_dump(mode="json") for e in result.evidence],
            agent_logs=[l.model_dump(mode="json") for l in result.agent_logs]
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
```

### 错误处理

```python
from fastapi import HTTPException

@router.post("/scan")
async def scan(request: ScanRequest):
    try:
        result = orchestrator.scan(...)
        return result
    except ValueError as e:
        # 客户端错误
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        # 服务器错误
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")
```

---

## 提交前检查清单

- [ ] 我没有在 API 中实现检测规则
- [ ] 我没有直接调用 Analyzers
- [ ] 我没有直接调用 Agents
- [ ] `/scan` 返回包含所有必需字段
- [ ] 响应格式符合 JSON Schema
- [ ] 我没有修改 `audit_core/models.py`
- [ ] 我没有修改 Analyzers 或 Agents
- [ ] 所有单元测试通过
- [ ] 架构守卫检查通过

---

## 修改记录

| 日期 | 修改人 | 修改内容 |
|------|--------|----------|
| 2026-05-30 | Core Orchestrator | 初始版本 |
