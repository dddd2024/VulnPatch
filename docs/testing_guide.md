# VulnPatch 测试指南

## 测试结构

```
tests/
  contracts/           # 契约测试（所有人必须运行）
  test_core/           # Core Orchestrator 模块测试
  test_ingest/         # Ingest 模块测试
  test_analyzers/      # Analyzer & Taint Engine 模块测试
  test_agents/         # Agent & Knowledge 模块测试
  test_evidence/       # Evidence 模块测试
  test_knowledge/      # Knowledge 模块测试
  test_report/         # Report 模块测试
  test_api/            # API 模块测试
  test_integration/    # 端到端集成测试
  fixtures/            # 测试固件（各语言漏洞代码样本）
```

## 四类成员各自运行的测试

### 所有人必须运行（每次提交前）

```bash
# 架构守卫检查
python governance/architecture_guard.py

# 契约测试
python -m pytest tests/contracts/ -v
```

### 成员 1: Core Orchestrator

负责模块：`audit_core/`, `ingest/`, `governance/`, `contracts/`

```bash
python -m pytest tests/test_core/ tests/test_ingest/ -v
python -m pytest tests/test_integration/ -v
```

### 成员 2: Analyzer & Taint Engine

负责模块：`analyzers/`, `analyzers/taint/`

```bash
python -m pytest tests/test_analyzers/ -v
```

### 成员 3: Agent & Knowledge

负责模块：`agents/`, `evidence/`, `knowledge/`

```bash
python -m pytest tests/test_agents/ tests/test_evidence/ tests/test_knowledge/ -v
```

### 成员 4: API / Report / UI

负责模块：`api/`, `report/`, `ui/`

```bash
python -m pytest tests/test_api/ tests/test_report/ -v
```

## 运行全部测试

```bash
python -m pytest tests/ -v
```

## Smoke Tests 说明

每个模块目录下都有 `test_smoke.py`，包含最基本的冒烟测试：

| 模块 | Smoke Test 验证内容 |
|------|---------------------|
| core | AuditOrchestrator 可初始化、数据模型可创建、registry 可用 |
| ingest | 语言检测正确、CodeUnit 可构建 |
| analyzers | 默认 registry 包含所有 analyzer、analyzer 输出 RawFinding |
| agents | 三个 Agent 可实例化、返回类型正确、fallback 可用 |
| evidence | EvidenceBundle 可构建 |
| knowledge | CWE mapper / RAG / 图谱模块可导入 |
| report | JSON/Markdown/HTML 报告可生成 |
| api | /scan 返回 scan_id 和所有必需字段 |
| integration | 完整 scan_code 流程可跑通 |
