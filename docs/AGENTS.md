# VulnPatch AI 协作治理规范

## 项目定位

VulnPatch 是一个模块化安全审计平台，结合静态分析与 LLM 推理能力检测源代码漏洞。

**当前阶段**: Stage 2.1（多人协作架构补强完成，Agent Registry + Taint 统一 + UI 契约对齐）

**核心目标**: 建立 AI 协作治理机制，确保四位成员在并行开发时遵守架构边界和契约。

**已完成治理增强**:
- ✅ 四人任务模板补齐（TASKS/*.md）
- ✅ Analyzer Registry 插件化（支持按语言路由）
- ✅ Agent Registry 插件化（`agents/registry.py` + `agents/register_builtin.py`）
- ✅ Agent 强类型接口（BaseAgent + AgentRuntime 错误隔离）
- ✅ /scan session 化（支持多扫描隔离）
- ✅ 模块化测试目录（tests/test_<module>/）
- ✅ Taint 入口统一（顶层 TaintAnalyzer 委托给 python/engines/taint_engine.py）
- ✅ UI 契约对齐（前端使用 /scan，渲染 findings 而非 vulnerabilities）

---

## 核心架构规则

### 1. 分层架构（严格禁止跨层调用）

```
Input → ingest → CodeUnit → analyzers → RawFinding → agents → 
EvidenceBundle → knowledge → report → AuditResult
```

**规则**:
- `analyzers/` 只能输出 `RawFinding`，不能调用 `agents` 或 `llm`
- `agents/` 只能处理结构化对象，不能直接扫描文件系统
- `api/` 只负责路由和序列化，不能包含检测规则实现
- `ingest/` 只负责输入处理，不能包含分析逻辑

### 2. 数据流向（单向）

- 允许: `ingest` → `analyzers` → `agents` → `evidence` → `knowledge` → `report`
- 禁止: 任何反向依赖或跳过中间层的直接调用

### 3. 公共契约（不可擅自修改）

以下文件为公共契约，修改需全员讨论：
- `audit_core/models.py` - 核心数据模型
- `contracts/*.schema.json` - JSON Schema 约束
- `governance/public_contracts.yaml` - 公共契约声明
- `governance/module_boundaries.yaml` - 模块边界定义
- `docs/ARCHITECTURE.md` - 架构文档

---

## 禁止事项

### 绝对禁止
1. **禁止** `analyzers/` 导入 `agents` 或 `llm` 模块
2. **禁止** `analyzers/` 直接调用 LLM API
3. **禁止** `agents/` 直接读取文件系统（只能通过结构化对象）
4. **禁止** `api/` 包含漏洞检测规则实现
5. **禁止** 修改 `audit_core/models.py` 中的字段定义
6. **禁止** 删除或修改 `/scan` 返回的必需字段
7. **禁止** 基于 `main.py`、`analysis_engine.py`、`api/routes/legacy.py` 开发新功能
8. **禁止** 新代码导入 `analysis_engine` 或 `main` 模块
9. **禁止** 导入已删除的 `detector/` 模块

### 必须遵守
1. **必须** 通过 `AuditOrchestrator` 接入主流程
2. **必须** 遵守模块边界（见四人分工）
3. **必须** 运行测试后提交

---

## 提交前测试要求

### 必须运行的测试

```bash
# 1. 契约测试（所有人）
python -m pytest tests/contracts/ -v

# 2. 模块边界检查（所有人）
python governance/architecture_guard.py

# 3. 自己模块的测试（按角色选择具体文件）
python -m pytest tests/test_audit_core.py tests/test_ingest.py tests/test_core/test_pipeline.py -v  # Core
python -m pytest tests/test_python_analyzer.py tests/test_js_analyzer.py tests/test_java_analyzer.py tests/test_c_cpp_analyzer.py tests/test_analyzers/test_smoke.py tests/test_analyzers/test_taint_adapter.py -v  # Analyzer
python -m pytest tests/test_llm_client_rule_mode.py tests/test_knowledge_graph.py tests/test_recon_agent.py tests/test_analysis_agent_with_mock_llm.py tests/test_evidence_builder.py tests/test_agents/test_smoke.py -v  # Agent
python -m pytest tests/test_scan_api.py tests/contracts/test_scan_response_contract.py tests/test_api/test_smoke.py tests/test_report/test_smoke.py -v  # API

# 4. 集成测试（修改 orchestrator 时）
python -m pytest tests/test_integration/ -v
```

---

*最后更新: 2026-06-01*
