# VulnPatch 五轮改进完整清单

## 第一轮改进 - 核心架构

### 新增文件
1. agents/verification_agent.py - 验证智能体
2. agents/analysis/analysis_agent.py - 分析智能体
3. agents/judge/judge_agent.py - 评判智能体
4. agents/recon/recon_agent.py - 侦察智能体
5. api/server.py - REST API服务器
6. api/routes/scan.py - 扫描路由

## 第二轮改进 - 分析器扩展

### 新增文件
12. analyzers/go/go_pattern_analyzer.py - Go分析器
13. analyzers/php/php_pattern_analyzer.py - PHP分析器
14. analyzers/taint/taint_engine.py - 污点分析引擎
15. analyzers/taint/sources.py - 污点源
16. analyzers/taint/sinks.py - 污点汇
17. graph/vuln_knowledge_graph.py - 漏洞知识图谱

## 第三轮改进 - 语言支持增强

### 新增文件
20. analyzers/rust/rust_pattern_analyzer.py - Rust分析器
21. analyzers/javascript/js_pattern_analyzer.py - JavaScript分析器增强
22. analyzers/c_cpp/c_pattern_analyzer.py - C/C++分析器
23. ingest/zip_loader.py - ZIP上传扫描
24. report/markdown_report.py - Markdown报告生成

## 第四轮改进 - 实时功能与API增强

### 新增文件
27. api/routes/scan_stream.py - WebSocket实时日志
28. api/routes/websocket.py - WebSocket路由
29. knowledge/cve_patterns.py - CVE模式库 (55个模式)

## 第五轮改进 - CVE候选评估模块 (2026-06-02)

### 新增文件
- `cve_candidate/` - CVE候选评估模块
  - `__init__.py` - 模块入口
  - `models.py` - 数据模型 (CveCandidateResult, CveCheckResult)
  - `scoring.py` - 评分引擎 (10项检查)
  - `evaluator.py` - 评估器主入口
- `duplicate_check/` - 去重检查模块
  - `__init__.py` - 模块入口
  - `models.py` - 数据模型
  - `checker.py` - 半自动去重检查器
- `cve_mall_tiny/` - mall-tiny CWE-338 漏洞完整材料
- `docs/` - 项目文档集中管理

### 关键改进
- 自动判断漏洞是否具备 CVE 申请价值
- 诚实评估置信度，不夸大结论
- 证据链分析和缺失证据标记
- 去重检查，避免提交重复 CVE

## 关键改进统计

| 类别 | 数量 |
|------|------|
| 智能体 | 4个 |
| 分析器 | 8个语言 |
| API路由 | 8个 |
| CVE 候选评估 | 完整模块 |
| 测试文件 | 30+ |
| **总计** | **60+个文件** |

---

生成日期: 2026-06-02
