# VulnPatch

自主多模型调度与案例库自进化的漏洞修复辅助系统

## 项目定位

VulnPatch 是一个模块化安全审计平台，结合静态分析与 LLM 推理能力检测源代码漏洞。
前端基于 Vue 3 + Element Plus + ECharts 构建，后端基于 FastAPI 提供 REST API。

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
│  │                    API Server (FastAPI)                              │   │
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
- **api**: FastAPI 服务器和 REST API 接口
- **frontend**: Vue 3 前端 Web 界面（Element Plus + ECharts）

## 快速开始

### 1. 安装后端依赖

```bash
pip install -r requirements.txt
```

### 2. 启动后端 API 服务

```bash
python api/server.py
```

后端服务默认运行在 `http://localhost:8000`，提供所有 REST API 接口。

### 3. 启动前端

```bash
cd frontend
npm install
npm run dev
```

前端默认运行在 `http://localhost:5173`，自动代理 `/api` 请求到后端 `localhost:8000`。

### 4. 使用 Web 界面

1. 浏览器打开 `http://localhost:5173`
2. 进入「安全扫描」页面，选择输入方式：
   - **代码片段**: 直接粘贴代码
   - **本地路径**: 输入本地仓库路径
   - **GitHub 仓库**: 输入 GitHub URL
3. 点击「开始扫描」，等待结果返回
4. 在「仪表盘」查看漏洞统计和图表
5. 在「漏洞发现」查看详情和代码片段
6. 在「证据链」查看调用链和 Judge 裁决
7. 在「审计报告」生成 JSON/Markdown/HTML 报告

### 运行架构守卫检查

```bash
python governance/architecture_guard.py
```

### 运行契约测试

```bash
python -m pytest tests/contracts/ -v
```

## API 端点

所有 API 端点前缀为 `/api`：

- `POST /api/scan` - 主扫描端点（支持 code/path/github 三种输入）
- `GET  /api/health` - 健康检查
- `GET  /api/findings` - 最近扫描的发现列表
- `GET  /api/evidence` - 最近扫描的证据包
- `GET  /api/agents/logs` - 最近扫描的 Agent 日志
- `GET  /api/report/json` - JSON 格式的完整审计结果
- `GET  /api/report/markdown` - Markdown 格式的审计报告
- `GET  /api/report/html` - HTML 格式的审计报告
- `GET  /api/scans` - 扫描历史列表
- `POST /api/auth/login` - 用户登录
- `POST /api/auth/register` - 用户注册

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
# 通过 API 调用扫描
import httpx

response = httpx.post('http://localhost:8000/api/scan', json={
    'input_type': 'code',
    'code': 'your code here',
    'language': 'python'
})
result = response.json()
print(result['scan_id'])
print(result['summary'])
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
├── api/                         # FastAPI 服务器和 REST API
├── frontend/                    # Vue 3 前端 Web 界面
│   ├── src/
│   │   ├── api/                # API 封装和类型定义
│   │   ├── stores/             # Pinia 状态管理
│   │   ├── router/             # Vue Router 路由配置
│   │   ├── layouts/            # 布局组件
│   │   ├── views/              # 页面组件（仪表盘、扫描、报告等）
│   │   └── styles/             # 全局样式
│   ├── package.json
│   └── vite.config.ts
├── llm/                         # LLM 客户端
├── report/                      # 报告生成
└── tests/                       # 测试
```

## 许可证

MIT
