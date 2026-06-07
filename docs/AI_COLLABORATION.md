# VulnPatch AI 协作指南

## 概述

本文档说明四位成员如何使用 Codex / Trae 进行并行开发协作。

## 协作原则

1. **模块边界清晰** - 每个成员只修改自己的模块
2. **公共契约稳定** - 修改公共契约需全员讨论
3. **测试驱动** - 提交前必须运行测试
4. **文档同步** - 修改行为需同步更新文档

---

## Agent Registry 机制

### 概述

`AgentRegistry` 是 Agent 模块的注册中心。所有 Agent 通过 `agents/register_builtin.py` 注册，`AuditOrchestrator` 从 registry 获取 Agent 实例。

### 关键文件

```
agents/registry.py            # AgentRegistry 类定义
agents/register_builtin.py    # 内置 Agent 注册入口
```

### 注册新 Agent 的步骤

1. 在 `agents/` 下创建新 Agent 类（继承 `BaseAgent` 或强类型接口）
2. 在 `agents/register_builtin.py` 的 `register_builtin_agents()` 中添加注册调用
3. 运行测试确认注册成功

---

## 开始任务前如何限定 Scope

### 1. 查看当前任务

```bash
# 查看任务模板（根据你的角色选择对应的模板）
cat TASKS/core_orchestrator_task.md       # 成员 1: Core Orchestrator
cat TASKS/analyzer_taint_task.md           # 成员 2: Analyzer & Taint Engine
cat TASKS/agent_knowledge_task.md          # 成员 3: Agent & Knowledge
cat TASKS/api_report_ui_task.md            # 成员 4: API / UI / Report
```

### 2. 确认修改范围

- 我的模块是哪些文件？
- 我可以修改什么？
- 我绝对不能修改什么？

### 3. 使用 Codex / Trae 时的 Prompt 模板

```
请帮我修改 <模块名> 模块，实现以下功能：

【功能描述】
...

【约束条件】
- 不要修改其他模块的文件
- 不要修改 audit_core/models.py
- 输出必须符合 RawFinding 模型
- 不要基于 main.py、analysis_engine.py 开发
- 新功能必须通过 AuditOrchestrator 接入 /scan 入口

【测试要求】
- 运行 python governance/architecture_guard.py
- 运行 python -m pytest tests/test_<module>.py -v
```

---

## 如何提交 PR

### PR 流程

1. **创建分支**: `git checkout -b feature/<module>-<description>`
2. **开发功能**: 按照任务模板开发，遵守模块边界
3. **运行测试**: 架构守卫 + 契约测试 + 模块测试
4. **填写 PR 描述**: 说明变更摘要、范围、测试情况
5. **请求审查**: @Core Orchestrator 负责人

### 必须运行的测试（所有人，每次提交前）

```bash
# 架构守卫检查
python governance/architecture_guard.py

# 契约测试
python -m pytest tests/contracts/ -v
```

---

## 关键文件位置

```
docs/AGENTS.md               # 协作治理规范
docs/ARCHITECTURE.md         # 架构文档
docs/AI_COLLABORATION.md     # 协作指南
TASKS/                       # 任务模板
governance/                  # 架构治理
contracts/                   # JSON Schema
tests/                       # 测试目录
tests/test_cve_candidate.py  # CVE 候选评估测试
```

---

*最后更新: 2026-06-01*
