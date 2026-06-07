# VulnPatch Architecture

## Overview

VulnPatch is a modular security audit platform that combines static analysis with LLM-powered reasoning to detect and analyze vulnerabilities in source code.

**Project Positioning**: 基于多 Agent 与程序分析的应用安全审计平台

**Core Workflow**:
```
代码输入 → 项目解析 → 攻击面识别 → 静态分析/污点分析 → LLM Agent 漏洞假设 → 证据链 → Judge Agent 裁决 → 审计报告
```

---

## Primary Entry Point (唯一正式入口)

**`POST /scan`** is the **only official entry point** for the audit pipeline.

```
api/routes/scan.py → audit_core/orchestrator.py (AuditOrchestrator) → ingest → analyzers → agents → evidence → knowledge/report → AuditResult
```

## Core Components

| 模块 | 职责 | 关键文件 |
|------|------|---------|
| `audit_core` | 核心数据模型和编排 | `models.py`, `orchestrator.py`, `registry.py` |
| `ingest` | 输入处理和代码加载 | `repo_loader.py`, `language_router.py` |
| `analyzers` | 静态分析引擎 | `pattern_analyzer.py`, `ast_analyzer.py`, `taint/` |
| `agents` | LLM Agent | `recon_agent.py`, `analysis_agent.py`, `judge_agent.py` |
| `evidence` | 证据收集管理 | `evidence_builder.py`, `snippet_extractor.py` |
| `knowledge` | 知识库 | `cwe_mapper.py`, `rag_retriever.py`, `vuln_graph.py` |
| `report` | 报告生成 | `json_report.py`, `markdown_report.py` |
| `api` | FastAPI 路由 | `routes/scan.py`, `schemas.py` |

## API Endpoints

- `POST /scan` - 主扫描端点
- `GET /findings` - 发现列表
- `GET /evidence` - 证据包
- `GET /agents/logs` - Agent 日志
- `GET /report/json` - JSON 报告
- `GET /report/markdown` - Markdown 报告
- `GET /health` - 健康检查

## Error Handling

`AgentRuntime` (`audit_core/agent_runtime.py`) 包装所有 Agent 调用，使用 try/except 防止单个 Agent 失败导致整个扫描崩溃。

- Recon 失败 → 返回空假设列表
- Analysis 失败 → 返回低置信假设
- Judge 失败 → 返回保守裁决
- Evidence 失败 → 保留发现，日志记录

## Key Design Principles

1. **单一入口**: 所有功能通过 `/scan` + `AuditOrchestrator`
2. **关注点分离**: Analyzer 做静态分析，Agent 做 LLM 推理
3. **统一数据模型**: 所有组件使用标准化 Pydantic 模型
4. **可扩展性**: 新增 Analyzer/Agent 通过 Registry 接入
5. **多语言支持**: 独立 Analyzer 支持 Python/JS/Java/C++

---

*最后更新: 2026-06-01*
