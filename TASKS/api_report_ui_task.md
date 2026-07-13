# API / UI / Report 任务模板

## 负责模块

- `api/` - FastAPI 路由和接口
- `report/` - 报告生成（JSON/Markdown/HTML）
- `ui/` - 用户界面（HTML/JS/CSS）

## 允许修改范围

### 可以修改的文件
- `api/*.py`
- `api/routes/*.py`
- `report/*.py`
- `ui/*.html`
- `ui/*.js`
- `ui/*.css`
- `tests/test_api*.py`
- `tests/test_report*.py`

### 可以添加的内容
- 新的 API 端点
- 新的报告格式
- 新的 UI 组件和交互
- 新的请求/响应 Schema（`api/schemas.py`）

## 禁止修改范围

- ❌ API 不允许写漏洞检测规则（检测逻辑属于 `analyzers/`）
- ❌ API 不允许直接调用 `analyzers/` 或 `agents/` 模块
- ❌ API 不允许绕过 `AuditOrchestrator` 直接调用内部模块
- ❌ report 不允许反向调用分析器或 Agent（只消费 `AuditResult`）
- ❌ ui 不允许实现扫描逻辑（只负责展示）
- ❌ 修改 `audit_core/models.py`
- ❌ 删除 `/scan` 返回的必需字段

## 核心约束

### 1. API 必须通过 AuditOrchestrator 调用主流程
- 所有扫描请求必须委托给 `AuditOrchestrator`
- API 层只负责路由、参数校验和响应序列化
- 不得直接实例化 Analyzer 或 Agent

```python
# ✅ 正确：通过 AuditOrchestrator
from audit_core.orchestrator import AuditOrchestrator
orchestrator = AuditOrchestrator()
result = orchestrator.scan_code(code, language)

# ❌ 错误：直接调用分析器
from analyzers.pattern_analyzer import PatternAnalyzer
analyzer = PatternAnalyzer()
```

### 2. report 只消费 AuditResult，不反向调用分析器
- `report/` 模块的输入是 `AuditResult` 对象
- 不得导入 `analyzers`、`agents`、`evidence`、`knowledge` 模块
- 报告生成是纯展示逻辑，不触发任何分析行为

### 3. ui 只负责展示，不实现扫描逻辑
- `ui/` 通过 API 端点获取数据
- 前端代码不包含任何分析或检测逻辑
- 扫描触发通过 `POST /scan` API 调用

### 4. 必须保持 /scan 返回字段兼容
- `/scan` 返回的 `summary`、`findings`、`evidence`、`agent_logs` 为必需字段
- 不得删除或重命名这些字段
- 可以添加新的可选字段

## 预期输出

### 代码输出
- 符合 FastAPI 规范的路由
- 符合 `api/schemas.py` 的请求/响应模型
- 可序列化为 JSON/Markdown/HTML 的报告
- 无扫描逻辑的前端代码

### 文档输出
- 更新的 `api/AGENTS.md`
- 新 API 端点的使用说明
- 新报告格式的示例

### 测试输出
- 单元测试
- API 集成测试
- 架构守卫检查通过

## 必须运行的测试

```bash
# 1. 模块边界检查
python governance/architecture_guard.py

# 2. 契约测试（所有人必跑）
python -m pytest tests/contracts/ -v

# 3. 单元测试
python -m pytest tests/test_scan_api.py tests/contracts/test_scan_response_contract.py tests/test_api/test_smoke.py tests/test_report/test_smoke.py -v

# 4. 端到端测试
python -c "
from audit_core.orchestrator import AuditOrchestrator
o = AuditOrchestrator()
result = o.scan_code('def test(): pass', 'python')
print(f'Summary: {result.summary}')
print(f'Findings: {len(result.findings)}')
print(f'Evidence: {len(result.evidence)}')
print(f'Agent logs: {len(result.agent_logs)}')
"
```

## 提交检查清单

- [ ] 我的修改仅限于 api/、report/、ui/ 模块
- [ ] 我没有在 API 中实现漏洞检测规则
- [ ] 我没有直接调用 `analyzers/` 或 `agents/` 模块
- [ ] 所有扫描请求通过 `AuditOrchestrator` 调度
- [ ] report 只消费 `AuditResult`，不反向调用分析器
- [ ] ui 只负责展示，不实现扫描逻辑
- [ ] `/scan` 返回的必需字段完整（summary、findings、evidence、agent_logs）
- [ ] 我没有修改 `audit_core/models.py`
- [ ] 所有单元测试通过
- [ ] 架构守卫检查通过

## 给 Codex / Trae 使用的 Prompt 模板

```
请帮我修改 API / UI / Report 模块，实现以下功能：

【功能描述】
...

【约束条件】
- 不要修改 api/、report/、ui/ 以外的文件
- 不要修改 audit_core/models.py
- API 不允许写漏洞检测规则，检测逻辑属于 analyzers/
- API 不允许直接调用 analyzers/ 或 agents/ 模块
- API 必须通过 AuditOrchestrator 调用主流程
- report 只消费 AuditResult，不反向调用分析器或 Agent
- ui 只负责展示，不实现扫描逻辑
- 必须保持 /scan 返回字段兼容（summary、findings、evidence、agent_logs）
- 不要基于 main.py、analysis_engine.py、api/routes/legacy.py 开发

【API 约束】
- 所有扫描请求委托给 AuditOrchestrator
- API 层只负责路由、参数校验和响应序列化

【Report 约束】
- 输入是 AuditResult 对象
- 不得导入 analyzers、agents、evidence、knowledge 模块

【UI 约束】
- 通过 API 端点获取数据
- 前端不包含分析或检测逻辑

【测试要求】
- 运行 python governance/architecture_guard.py
- 运行 python -m pytest tests/contracts/ -v
- 运行 python -m pytest tests/test_scan_api.py tests/contracts/test_scan_response_contract.py tests/test_api/test_smoke.py tests/test_report/test_smoke.py -v
```

## 常见问题

### Q: 需要添加新的 API 端点怎么办？
A: 可以直接添加，但如果是扫描类端点，必须委托给 `AuditOrchestrator`。查询类端点可以直接访问应用状态。

### Q: 需要在报告中展示更多信息怎么办？
A: 报告只消费 `AuditResult`。如需展示新的数据，先向 Core Orchestrator 提出需求，在 `AuditResult` 中添加相应字段。

### Q: 需要在 UI 中添加新的交互功能怎么办？
A: 可以直接修改 `ui/` 文件，但交互逻辑必须通过 API 端点实现，不得在前端实现任何分析逻辑。

### Q: 需要修改 /scan 返回字段怎么办？
A: 必需字段（summary、findings、evidence、agent_logs）不可删除或重命名。添加新可选字段需与 Core Orchestrator 讨论。

### Q: 需要修改公共契约文件怎么办？
A: 在群里发起讨论，所有成员同意后由 Core Orchestrator 负责人统一修改。
