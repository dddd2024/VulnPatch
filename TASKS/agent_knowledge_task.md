# Agent & Knowledge 任务模板

## 负责模块

- `agents/` - LLM 驱动的分析 Agent
- `evidence/` - 证据收集和管理
- `knowledge/` - 知识库和分类

## 允许修改范围

### 可以修改的文件
- `agents/*.py`
- `evidence/*.py`
- `knowledge/*.py`
- `tests/test_agents*.py`
- `tests/test_evidence*.py`
- `tests/test_knowledge*.py`

### 可以添加的内容
- 新的 Agent 子类（继承 `BaseAgent`）
- 新的证据提取策略
- 新的知识检索逻辑
- 新的 CWE 映射规则
- Agent Prompt 模板

## 禁止修改范围

- ❌ 直接读取文件系统（Agent 只能通过结构化对象获取输入）
- ❌ 直接调用 `analyzers/` 模块（分析结果由 AuditOrchestrator 提供）
- ❌ 修改 `audit_core/models.py`
- ❌ 修改 API 路由或 UI 代码
- ❌ 导入 `analyzers` 或 `api` 模块

## 输入对象

Agent & Knowledge 模块接收以下结构化对象作为输入：

| 对象 | 来源模块 | 说明 |
|------|----------|------|
| `CodeUnit` | `audit_core/models` | 代码单元（文件内容、语言、AST） |
| `RawFinding` | `audit_core/models` | 分析器输出的原始发现 |
| `AgentHypothesis` | `audit_core/models` | Agent 生成的漏洞假设 |
| `EvidenceBundle` | `audit_core/models` | 证据包（代码片段、调用链、置信度） |

## 输出对象

Agent & Knowledge 模块产出以下结构化对象：

| 对象 | 消费方 | 说明 |
|------|--------|------|
| `AgentHypothesis` | `evidence/`, `knowledge/` | Agent 对漏洞的推理假设 |
| `AgentLog` | `api/`, `report/` | Agent 执行过程日志 |
| `JudgeDecision` | `report/`, `audit_core/` | Judge Agent 的裁决结果 |
| `EvidenceBundle` | `report/`, `knowledge/` | 组装完成的证据包 |
| CWE 信息 | `report/` | 漏洞分类映射结果 |
| RAG 检索结果 | `agents/` | 知识库相似漏洞检索 |
| 图谱结构 | `report/` | 漏洞知识图谱节点和边 |

## 核心约束

### 1. Agent 不允许直接读取文件系统
- Agent 只能接收 `CodeUnit`、`RawFinding` 等结构化对象
- 不得使用 `open()`、`os.path`、`Path` 等直接访问文件
- 代码内容通过 `CodeUnit.content` 获取

### 2. Agent 不允许直接调用 analyzers
- 分析结果由 `AuditOrchestrator` 统一调度
- Agent 接收的是已合并的 `RawFinding` 列表
- 不得 `from analyzers import ...` 或 `import analyzers`

### 3. Agent 不允许修改 audit_core/models.py
- 数据模型是公共契约，修改需全员讨论
- 如需新字段，向 Core Orchestrator 提出需求

### 4. LLM 调用失败时必须支持 fallback
- LLM 调用应包裹在 try/except 中
- 失败时返回降级结果（如低置信度的 `AgentHypothesis`）
- 不得因 LLM 调用失败而中断整个审计流程
- 记录失败日志到 `AgentLog`

### 5. 必须通过 AuditOrchestrator 接入主流程
- 新增 Agent 必须通过 `AuditOrchestrator` 或 `AgentRuntime` 接入主流程
- 不得绕过 `AuditOrchestrator` 直接被 API 调用
- `OrchestratorAgent` 仅作为未来可选的 LLM 策略协调 Agent，不承担当前工程主流程调度
- 遵循 `ingest -> analyzers -> agents -> evidence -> knowledge -> report` 数据流

## 预期输出

### 代码输出
- 继承 `BaseAgent` 的 Agent 子类
- 符合 Pydantic 模型的输出对象
- 完整的类型注解

### 文档输出
- 更新的 `agents/AGENTS.md`
- 更新的 `evidence/AGENTS.md`
- 新 Agent / 新知识模块的使用说明

### 测试输出
- 单元测试
- 集成测试
- 架构守卫检查通过

## 必须运行的测试

```bash
# 1. 模块边界检查
python governance/architecture_guard.py

# 2. 契约测试（所有人必跑）
python -m pytest tests/contracts/ -v

# 3. 单元测试
python -m pytest tests/test_llm_client_rule_mode.py tests/test_knowledge_graph.py tests/test_recon_agent.py tests/test_analysis_agent_with_mock_llm.py tests/test_evidence_builder.py tests/test_agents/test_smoke.py -v

# 4. 端到端测试
python -c "
from audit_core.orchestrator import AuditOrchestrator
o = AuditOrchestrator()
result = o.scan_code('def test(): pass', 'python')
print(f'Agent logs: {len(result.agent_logs)}')
print(f'Evidence: {len(result.evidence)}')
"
```

## 提交检查清单

- [ ] 我的修改仅限于 agents/、evidence/、knowledge/ 模块
- [ ] 我没有导入 `analyzers` 或 `api` 模块
- [ ] 我没有直接读取文件系统
- [ ] 我没有修改 `audit_core/models.py`
- [ ] LLM 调用包含 try/except 和 fallback 逻辑
- [ ] 新 Agent 已通过 `AuditOrchestrator` 或 `AgentRuntime` 接入主流程
- [ ] 所有输出对象符合 Pydantic 模型定义
- [ ] 所有单元测试通过
- [ ] 架构守卫检查通过

## 给 Codex / Trae 使用的 Prompt 模板

```
请帮我修改 Agent & Knowledge 模块，实现以下功能：

【功能描述】
...

【约束条件】
- 不要修改 agents/、evidence/、knowledge/ 以外的文件
- 不要修改 audit_core/models.py
- 不要导入 analyzers 或 api 模块
- Agent 不允许直接读取文件系统，只能通过 CodeUnit 等结构化对象获取输入
- Agent 不允许直接调用 analyzers，分析结果由 AuditOrchestrator 提供
- LLM 调用必须包含 try/except 和 fallback 逻辑
- 新增 Agent 必须通过 AuditOrchestrator 或后续 AgentRuntime 接入主流程；OrchestratorAgent 仅作为未来可选的 LLM 策略协调 Agent，不承担当前工程主流程调度
- 新功能必须通过 AuditOrchestrator 接入主流程
- 不要基于 main.py、analysis_engine.py、api/routes/legacy.py 开发

【输入对象】
- CodeUnit（代码单元）
- RawFinding（分析器原始发现）
- AgentHypothesis（Agent 假设）
- EvidenceBundle（证据包）

【输出对象】
- AgentHypothesis / AgentLog / JudgeDecision / EvidenceBundle
- CWE 信息 / RAG 检索结果 / 图谱结构

【测试要求】
- 运行 python governance/architecture_guard.py
- 运行 python -m pytest tests/contracts/ -v
- 运行 python -m pytest tests/test_llm_client_rule_mode.py tests/test_knowledge_graph.py tests/test_recon_agent.py tests/test_analysis_agent_with_mock_llm.py tests/test_evidence_builder.py tests/test_agents/test_smoke.py -v
```

## 常见问题

### Q: 需要获取代码内容怎么办？
A: 通过 `CodeUnit.content` 获取，不要直接读取文件系统。

### Q: 需要调用分析器获取更多信息怎么办？
A: 分析器由 `AuditOrchestrator` 统一调度，Agent 只能消费已产出的 `RawFinding`。如需新的分析能力，向 Analyzer 负责人提出需求。

### Q: LLM 调用失败怎么处理？
A: 必须实现 fallback 逻辑，返回低置信度的降级结果，记录失败日志到 `AgentLog`，不得中断审计流程。

### Q: 需要添加新的数据模型字段怎么办？
A: 向 Core Orchestrator 负责人提出需求，由其统一修改 `audit_core/models.py`。

### Q: 需要修改公共契约文件怎么办？
A: 在群里发起讨论，所有成员同意后由 Core Orchestrator 负责人统一修改。
