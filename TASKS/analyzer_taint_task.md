# Analyzer & Taint Engine 任务模板

## 负责模块

- `analyzers/` - 静态分析器
- `analyzers/taint/` - 污点分析引擎
- `analyzers/python/` - Python 分析器
- `analyzers/javascript/` - JavaScript/TypeScript 分析器
- `analyzers/java/` - Java 分析器
- `analyzers/c_cpp/` - C/C++ 分析器

## 允许修改范围

### 可以修改的文件
- `analyzers/*.py`
- `analyzers/python/*.py`
- `analyzers/javascript/*.py`
- `analyzers/java/*.py`
- `analyzers/c_cpp/*.py`
- `analyzers/taint/*.py`
- `analyzers/*/register.py`
- `tests/test_analyzers*.py`
- `tests/test_python_analyzer.py`
- `tests/test_js_analyzer.py`
- `tests/test_java_analyzer.py`
- `tests/test_c_cpp_analyzer.py`

### 可以添加的内容
- 新的检测规则
- 新的分析器类
- 污点源/汇聚点/净化器定义

## 禁止修改范围

- ❌ 导入 `agents` 或 `llm` 模块
- ❌ 直接调用 LLM API
- ❌ 直接读取文件系统
- ❌ 修改 `audit_core/models.py`
- ❌ 修改 API 路由

## 预期输出

### 代码输出
- 继承 `BaseAnalyzer` 的分析器类
- 输出 `RawFinding` 对象的 `analyze()` 方法
- 已注册到 `AnalyzerRegistry`

### 文档输出
- 更新的 `analyzers/AGENTS.md`
- 新分析器的使用说明

### 测试输出
- 单元测试
- 集成测试

## 必须运行的测试

```bash
# 1. 模块边界检查
python governance/architecture_guard.py

# 2. 契约测试（所有人必跑）
python -m pytest tests/contracts/ -v

# 3. 单元测试
python -m pytest tests/test_python_analyzer.py tests/test_js_analyzer.py tests/test_java_analyzer.py tests/test_c_cpp_analyzer.py tests/test_analyzers/test_smoke.py tests/test_analyzers/test_taint_adapter.py -v

# 4. 端到端测试
python -c "
from audit_core.orchestrator import AuditOrchestrator
o = AuditOrchestrator()
result = o.scan_code('def test(): pass', 'python')
print(f'Findings: {result.summary.total_findings}')
"
```

## 提交检查清单

- [ ] 我没有导入 `agents` 或 `llm` 模块
- [ ] 我没有直接调用 LLM API
- [ ] 我没有直接读取文件系统
- [ ] 我的分析器输出符合 `RawFinding` 模型
- [ ] 我的分析器已注册到 `AnalyzerRegistry`
- [ ] 所有单元测试通过
- [ ] 架构守卫检查通过
