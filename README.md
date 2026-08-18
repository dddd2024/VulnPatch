# VulnPatch

**自主多模型调度与案例库自进化的漏洞修复辅助系统**

## 项目定位

VulnPatch 是一个面向源代码漏洞检测、修复与验证的安全工程平台。静态分析、污点分析与 Agent 审计负责发现漏洞；发现进入修复阶段后，系统会依据任务复杂度、代码敏感度、模型健康状态、成本/时延和能力要求自主选择执行模型，并检索历史正/负修复案例辅助生成补丁。只有经过确定性验证的结果才会写回案例库，成为后续相似漏洞修复的可复用经验。

前端基于 Vue 3 + Element Plus + ECharts，后端基于 FastAPI。比赛能力不是独立的“比赛页面”：普通扫描与普通漏洞详情使用正式产品 API 和同一套 RepairPipeline，`/api/demo/*` 仅保留为可复现实验 fixture。

## 核心闭环

```text
代码输入
  ↓
RepoLoader / LanguageRouter
  ↓
Pattern / AST / Taint Analyzers
  ↓
ReconAgent → AnalysisAgent → JudgeAgent
  ↓
RawFinding + EvidenceBundle
  ↓
ModelRouter
  ├─ complexity / confidence
  ├─ privacy policy
  ├─ provider health / availability
  ├─ cost / latency
  └─ required capabilities
  ↓
CaseRetriever（历史 POSITIVE / NEGATIVE RepairCase）
  ↓
RepairAgent
  ↓
PatchCandidate
  ↓
VerificationAgent
  ├─ syntax / compile
  ├─ static rescan
  ├─ PoC
  ├─ regression
  └─ anti-bypass
  ↓
VerificationResult
  ↓
CaseEvolver
  ├─ PASS → POSITIVE case
  └─ FAIL → NEGATIVE case
  ↓
下一次相似任务检索并实际影响修复决策
```

核心设计原则是：**模型选择有证据、案例复用有归因、修复结果必须经过验证、失败经验同样进入知识闭环。**

## 架构概览

```text
┌──────────────────────────────────────────────────────────────────────┐
│                              VulnPatch                                │
├──────────────────────────────────────────────────────────────────────┤
│ Product API                                                          │
│  POST /api/scan          POST /api/repair                            │
│  GET  /api/findings      GET  /api/routing/decisions                │
│  GET  /api/evidence      GET  /api/cases /api/cases/events          │
├──────────────────────────────────────────────────────────────────────┤
│ AuditOrchestrator                                                    │
│  RepoLoader → AnalyzerRegistry → AgentRuntime → Evidence / Report    │
├──────────────────────────────────────────────────────────────────────┤
│ RepairPipeline                                                       │
│  ModelRouter → CaseRetriever → RepairAgent → VerificationAgent      │
│       ↑                                            ↓                 │
│       └──────────── CaseStore ← CaseEvolver ───────┘                 │
├──────────────────────────────────────────────────────────────────────┤
│ Persistence                                                          │
│  AuditState / RepairCase+CaseEvent / RoutingDecisionStore (SQLite)   │
├──────────────────────────────────────────────────────────────────────┤
│ Generic Frontend                                                     │
│  Scan / Findings+Repair / Agents / Knowledge / Evidence / Report     │
└──────────────────────────────────────────────────────────────────────┘
```

## 两项标题能力

### 1. 自主多模型调度

`ModelRouter` 不按固定优先级盲目调用模型，而是记录完整 `RoutingDecision`：

- 简单、高置信度任务可直接使用确定性 `rule_engine`，避免不必要的模型成本；
- 复杂公开任务可选择具备所需能力的语义模型；
- 机密源码对云模型执行隐私策略阻断，优先本地 provider；
- provider 不可用或健康异常时按 fallback chain 降级；
- `required_capabilities` 是真实 eligibility gate，无法满足时会明确留下 unmet-capability 证据；
- 路由决策写入 SQLite，可在通用 Agents 页面/API 中审计。

### 2. 案例库自进化

`RepairCase` 不只是静态知识条目。每次修复都会经过 `VerificationAgent`，再由 `CaseEvolver` 写入：

- `POSITIVE`：验证通过的成功策略；
- `NEGATIVE`：验证失败、被绕过或产生回归的失败策略；
- 后续任务通过 `CaseRetriever` 检索相似案例；
- `RepairAgent` 只允许高可信正案例选择预注册安全 adapter，负案例用于阻断已知失败策略；
- reuse 指标只归因给实际 `used/avoided` 的案例，而不是所有被检索到的案例。

这使“案例被检索”与“案例实际改变 repair decision”可以被分别验证。

## 核心模块

- **audit_core/orchestrator.py**：正式扫描业务边界，负责输入、分析器、Agent、证据与结果汇总。
- **audit_core/agent_runtime.py**：Agent 执行隔离、fallback 与日志收集。
- **audit_core/repair_pipeline.py**：通用修复闭环；正式产品 API 与可复现实验 fixture 共用。
- **ingest/**：本地目录、GitHub/GitLab/Gitea、ZIP 和代码片段加载。
- **analyzers/**：Pattern、AST、Python/JavaScript 和 Taint 分析能力。
- **llm/model_router.py**：多模型策略路由与 fallback。
- **llm/routing_store.py**：RoutingDecision 持久化。
- **agents/repair_agent.py**：结构化补丁生成与案例感知策略选择。
- **agents/verification_agent.py**：compile/rescan/PoC/regression/anti-bypass 验证。
- **knowledge/**：RepairCase、CaseStore、CaseRetriever、CaseEvolver、CWE/RAG。
- **report/**：JSON / Markdown / HTML / PDF 报告。
- **frontend/**：通用扫描、漏洞修复、路由证据、案例库、证据链与报告界面。

## 快速开始

### 1. 安装后端依赖

```bash
pip install -r requirements.txt
```

### 2. 启动后端

```bash
python api/server.py
```

默认地址：`http://localhost:8000`。

### 3. 启动前端

```bash
cd frontend
npm ci
npm run dev
```

默认地址：`http://localhost:5173`，Vite 将 `/api` 代理到 `localhost:8000`。

### 4. 正常产品使用流程

1. 在「安全扫描」提交代码、本地路径或 GitHub 仓库；
2. 在「漏洞发现」查看 finding，点击「生成修复」；
3. 修复抽屉展示模型选择理由、历史案例 used/avoided、patch diff 和 Verification checks；
4. 在「Agents」查看持久化 RoutingDecision；
5. 在「Knowledge」查看新生成的正/负 RepairCase 和演化事件；
6. 在「证据链」与「审计报告」查看检测证据和最终报告。

## 主要 API

- `POST /api/scan`：正式扫描入口（code/path/github）
- `POST /api/repair`：对已扫描 finding 执行通用修复闭环
- `GET  /api/findings`：最近扫描 findings
- `GET  /api/evidence`：最近扫描 EvidenceBundle
- `GET  /api/agents/logs`：Agent 执行日志
- `GET  /api/routing/decisions`：持久化多模型路由决策
- `GET  /api/cases`：修复案例库
- `GET  /api/cases/events`：案例演化/复用事件
- `GET  /api/report/json|markdown|html`：审计报告
- `GET  /api/scans`：扫描历史

为了兼容历史调用，服务仍保留 `/scan`、`/health` 等根路径 alias；新客户端统一使用 `/api/*`。

## 展示与验证

核心能力可通过普通产品路径直接演示；`/api/demo/*` 只用于确定性 fixture、故障注入和重复实验，不包含比赛专用前端。

```bash
# 核心调度 + 案例进化回归
python -m pytest tests/test_competition_capabilities.py tests/test_closeout_review_fixes.py -q

# 架构守卫
python governance/architecture_guard.py

# 全仓 Python 编译完整性
python -m compileall -q .
```

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
