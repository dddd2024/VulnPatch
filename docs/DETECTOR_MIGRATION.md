# Detector 模块迁移完成

## 状态

**✅ 迁移已完成**

| 日期 | 事件 |
|------|------|
| 2026-05-31 | 迁移 detector 引擎到 analyzers/python/ |
| 2026-05-31 | 添加 `enable_legacy` 参数，默认禁用 LegacyAnalyzerAdapter |
| 2026-05-31 | 更新 architecture_guard，仅允许 analyzers/legacy_adapter.py 导入 detector |
| 2026-05-31 | **删除 detector/ 目录** |
| 2026-05-31 | **删除 LegacyAnalyzerAdapter** |
| 2026-05-31 | **删除 enable_legacy 参数** |

---

## 新的 Python 分析架构

```
analyzers/python/
├── core/
│   ├── models.py              # Rule, Finding 数据模型
│   ├── ast_utils.py           # AST 工具函数
│   ├── rule_loader.py         # YAML 规则加载器
│   └── taint_models.py        # 污点分析数据模型
├── engines/
│   ├── ast_rule_engine.py     # AST 规则引擎
│   ├── regex_rule_engine.py   # 正则规则引擎
│   └── taint_engine.py        # 污点分析引擎
├── rules/
│   ├── ast/                   # AST 规则
│   ├── regex/                 # 正则规则
│   └── taint/                 # 污点规则
└── python_analyzer.py         # 主分析器
```

---

## 导入路径

| 旧路径（已删除） | 新路径 |
|-----------------|--------|
| `detector.core.*` | `analyzers.python.core.*` |
| `detector.engines.*` | `analyzers.python.engines.*` |
| `detector.rules.*` | `analyzers.python.rules.*` |

---

## 注意事项

- ❌ 禁止 `import detector` 或 `from detector import ...`
- ❌ `detector/` 目录已完全删除
- ✅ 使用 `analyzers.python.*` 替代

---

**文档状态**: 归档（迁移已完成）
**最后更新**: 2026-05-31
