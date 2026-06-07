# VulnPatch

基于多 Agent 与程序分析的应用安全审计平台

## 项目定位

VulnPatch 是一个模块化安全审计平台，结合静态分析与 LLM 推理能力检测源代码漏洞。

**核心流程**：
```
代码输入 → 项目解析 → 攻击面识别 → 静态分析/污点分析 → LLM Agent 漏洞假设 → 证据链 → Judge Agent 裁决 → 审计报告
```

## 架构概览

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              VulnPatch Platform                              │
├─────────────────────────────────────────────────────────────────────────────┤
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                         API Layer                                    │   │
│  │  ┌──────────┐  ┌──────────┐  ┌───────────┐  ┌───────────┐          │   │
│  │  │ POST     │  │ GET      │  │ GET       │  │ GET       │          │   │
│  │  │ /scan    │  │ /health  │  │ /findings │  │ /report   │          │   │
│  │  │ (primary)│  │          │  │ /evidence │  │ /agents   │          │   │
│  │  └──────────┘  └──────────┘  │ /logs     │  │ /json     │          │   │
│  │                              └───────────┘  └───────────┘            │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                    │                                         │
│                                    ▼                                         │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                    AuditOrchestrator                                 │   │
│  │              (Main entry point for audit workflow)                   │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                    │                                         │
│          ┌─────────────────────────┼─────────────────────────┐              │
│          │                         │                         │              │
│          ▼                         ▼                         ▼              │
│  ┌──────────────┐        ┌──────────────┐        ┌──────────────┐         │
│  │    ingest    │        │   analyzers  │        │    agents    │         │
│  │              │        │              │        │              │         │
│  │ Code loading │        │ Pattern      │        │ ReconAgent   │         │
│  │ Language     │        │ AST          │        │ AnalysisAgent│         │
│  │ detection    │        │ Taint        │        │ JudgeAgent   │         │
│  └──────────────┘        └──────────────┘        └──────────────┘         │
│          │                         │                         │              │
│          └─────────────────────────┼─────────────────────────┘              │
│                                    │                                         │
│                                    ▼                                         │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                         evidence                                     │   │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────────┐ │   │
│  │  │ Snippets    │  │ Call Chains │  │ Confidence Ledger           │ │   │
│  │  └─────────────┘  └─────────────┘  └─────────────────────────────┘ │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                    │                                         │
│                                    ▼                                         │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                       knowledge                                      │   │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────────┐ │   │
│  │  │ CWE Mapper  │  │ RAG         │  │ Vuln Graph                  │ │   │
│  │  └─────────────┘  └─────────────┘  └─────────────────────────────┘ │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                    │                                         │
│                                    ▼                                         │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                        report                                        │   │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────────┐ │   │
│  │  │ JSON        │  │ Markdown    │  │ HTML                        │ │   │
│  │  └─────────────┘  └─────────────┘  └─────────────────────────────┘ │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
```

## 数据流

```
Input → ingest → CodeUnit → analyzers → RawFinding → merge → agents →
EvidenceBundle → knowledge → report → AuditResult
```

## 核心模块

- **audit_core**: 核心数据模型和编排逻辑
- **ingest**: 输入处理和代码加载
- **analyzers**: 静态分析引擎（Pattern、AST、Taint）
- **agents**: LLM 驱动的分析 Agent（Recon、Analysis、Judge）
- **evidence**: 证据收集和管理
- **knowledge**: 知识库和分类（CWE、RAG、Vuln Graph）
- **report**: 报告生成（JSON/Markdown/HTML）
- **api**: FastAPI 路由和接口

## 快速开始

### 安装依赖

```bash
pip install -r requirements.txt
```

### 运行架构守卫检查

```bash
python governance/architecture_guard.py
```

### 运行契约测试

```bash
python -m pytest tests/contracts/ -v
```

### 运行完整审计流程

```python
from audit_core.orchestrator import AuditOrchestrator

orchestrator = AuditOrchestrator()

# 扫描代码片段
result = orchestrator.scan_code("def hello(): pass", language="python")

# 扫描本地仓库
result = orchestrator.scan_path("/path/to/repo")
```

### 启动 API 服务

```bash
python api/server.py
```

## API 端点

**主入口**：
- `POST /scan` - 主扫描端点（委托给 AuditOrchestrator）
- `GET /findings` - 最近扫描的发现
- `GET /evidence` - 最近扫描的证据包
- `GET /agents/logs` - 最近扫描的 Agent 日志
- `GET /report/json` - JSON 格式的完整审计结果
- `GET /report/markdown` - Markdown 格式的审计报告
- `GET /report/html` - HTML 格式的审计报告
- `GET /health` - 健康检查

## 文档

所有项目文档集中管理在 `docs/` 目录下：

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) - 架构文档
- [docs/AGENTS.md](docs/AGENTS.md) - AI 协作治理规范
- [docs/AI_COLLABORATION.md](docs/AI_COLLABORATION.md) - AI 协作指南
- [docs/testing_guide.md](docs/testing_guide.md) - 测试指南
- [docs/DETECTOR_MIGRATION.md](docs/DETECTOR_MIGRATION.md) - 检测器迁移记录
- [docs/VULNPATCH_IMPROVEMENTS.md](docs/VULNPATCH_IMPROVEMENTS.md) - 改进清单

任务模板：

- [TASKS/core_orchestrator_task.md](TASKS/core_orchestrator_task.md) - Core Orchestrator 任务模板
- [TASKS/analyzer_taint_task.md](TASKS/analyzer_taint_task.md) - Analyzer & Taint Engine 任务模板
- [TASKS/agent_knowledge_task.md](TASKS/agent_knowledge_task.md) - Agent & Knowledge 任务模板
- [TASKS/api_report_ui_task.md](TASKS/api_report_ui_task.md) - API / UI / Report 任务模板

## CVE Candidate Review

VulnPatch 支持对扫描结果进行 CVE 候选评估，自动判断漏洞是否具备 CVE 申请价值。

### 功能说明

- **CVE 潜力评分**: 对每个漏洞进行 10 项检查（发布版本、入口点、安全敏感流程等）
- **证据链分析**: 自动列出已确认证据和缺失证据
- **去重检查**: 生成搜索关键词，对比已知 CVE/GHSA 数据库
- **置信度评估**: high/medium/low 三级置信度
- **下一步建议**: 根据评估结果生成具体行动建议

### 运行 CVE 候选分析

```bash
# 通过 API 扫描（自动包含 CVE 候选评估）
python api/server.py
# POST /scan 会自动返回 cve_candidates 字段
```

```python
# 通过代码调用
from audit_core.orchestrator import AuditOrchestrator
from cve_candidate.evaluator import CveCandidateEvaluator

orchestrator = AuditOrchestrator()
result = orchestrator.scan_code("code here", language="java")

# CVE 候选评估
evaluator = CveCandidateEvaluator()
cve_results = evaluator.evaluate_batch(result.findings)
for r in cve_results:
    if r.cve_candidate:
        print(f"CVE candidate: {r.title} (confidence={r.confidence})")
        print(f"  Missing evidence: {r.missing_evidence}")
```

### 输出 JSON 示例

扫描结果中的 `cve_candidates` 字段示例：

```json
{
  "cve_candidates": [
    {
      "cve_candidate": true,
      "confidence": "medium",
      "reason": "Meets 7/10 CVE criteria with medium confidence.",
      "affected_file": "UmsMemberServiceImpl.java",
      "cwe": "CWE-338",
      "cvss_score": 5.3,
      "evidence": ["Security-relevant CWE: CWE-338"],
      "missing_evidence": [
        "No version/release/tag information available.",
        "No reachable entry point identified."
      ],
      "recommended_next_steps": [
        "Confirm the vulnerability exists in a released version.",
        "Identify a reachable entry point."
      ]
    }
  ]
}
```

### 查看 missing_evidence

所有缺失证据都会在 `missing_evidence` 字段中列出。如果该列表为空且 `confidence` 为 `high`，说明证据充分，可以考虑申请 CVE。

### 判断是否适合申请 CVE

| 条件 | 说明 |
|------|------|
| `cve_candidate: true` + `confidence: high` | 证据充分，建议申请 |
| `cve_candidate: true` + `confidence: medium` | 需要更多证据 |
| `cve_candidate: false` | 不建议申请 CVE |
| `missing_evidence` 为空 | 所有检查项通过 |
| `duplicate_check.duplicate_risk: high` | 可能存在重复 CVE |

### 避免误报和夸大

- 所有结论基于 evidence 和 missing_evidence，不使用推测
- 未获得 CVE 编号前，只能写 CVE-PENDING
- 无法证明的内容必须标为 missing_evidence
- 置信度不会因为缺少证据而设为 high

## 开发规范

1. **模块边界清晰** - 每个模块只负责特定功能
2. **公共契约稳定** - 修改公共契约需全员讨论
3. **测试驱动** - 提交前必须运行测试
4. **文档同步** - 修改行为需同步更新文档
5. **CVE 材料分离** - CVE 相关材料放在 `cve_mall_tiny/` 目录，不污染根目录

## 项目目录结构

```
VulnPatch/
├── docs/                       # 项目文档（集中管理）
├── cve_mall_tiny/              # CVE 候选材料（mall-tiny CWE-338）
│   ├── CVE_SUBMISSION.md       # CVE 提交材料
│   ├── CVE_FIX.patch           # 修复补丁
│   ├── poc/                    # PoC 文件
│   └── README.md               # 快速参考
├── cve_candidate/               # CVE 候选评估模块
├── duplicate_check/              # 去重检查模块
├── samples/                     # 测试样例
│   └── mall-tiny/              # mall-tiny 漏洞样例
├── agents/                      # Agent 模块
├── analyzers/                   # 分析器模块
├── audit_core/                  # 核心编排模块
├── api/                         # API 模块
├── llm/                         # LLM 客户端
├── report/                      # 报告生成
└── tests/                       # 测试
```

## 许可证

MIT
