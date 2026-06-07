# Core Orchestrator 任务模板

## 负责模块

- `audit_core/` - 核心数据模型和编排器
- `ingest/` - 输入处理
- `governance/` - 架构治理
- `contracts/` - 契约定义

## 允许修改范围

### 可以修改的文件
- `audit_core/models.py`（需全员讨论）
- `audit_core/orchestrator.py`
- `audit_core/registry.py`
- `audit_core/result_merger.py`
- `audit_core/scoring.py`
- `ingest/*.py`
- `governance/*.yaml`
- `governance/*.py`
- `contracts/*.json`

### 可以添加的内容
- 新的数据模型字段（可选）
- 新的编排器方法
- 新的治理规则
- 新的契约定义

## 禁止修改范围

- ❌ 其他模块的文件（analyzers/, agents/, api/, report/）
- ❌ 删除公共契约文件
- ❌ 修改数据模型的必填字段（需全员讨论）

## 预期输出

### 代码输出
- 符合 Pydantic 模型的数据类
- 可序列化为 JSON 的对象
- 完整的类型注解

### 文档输出
- 更新的 ARCHITECTURE.md
- 更新的 AGENTS.md
- 更新的 JSON Schema

### 测试输出
- 单元测试
- 契约测试
- 架构守卫检查通过

## 必须运行的测试

```bash
# 1. 契约测试
python -m pytest tests/contracts/test_models_contract.py -v

# 2. 架构守卫检查
python governance/architecture_guard.py

# 3. 单元测试
python -m pytest tests/test_audit_core.py tests/test_ingest.py tests/test_core/test_pipeline.py -v

# 4. 集成测试
python -c "from audit_core.orchestrator import AuditOrchestrator; o = AuditOrchestrator(); print(o.scan_code('def test(): pass', 'python'))"
```

## 提交检查清单

- [ ] 我的修改仅限于 Core Orchestrator 模块
- [ ] 如果修改了 models.py，已征得全员同意
- [ ] 已更新相关 JSON Schema
- [ ] 已更新 ARCHITECTURE.md
- [ ] 所有数据模型可序列化
- [ ] 所有契约测试通过
- [ ] 架构守卫检查通过
- [ ] 所有单元测试通过

## 常见问题

### Q: 需要添加新的数据模型字段怎么办？
A: 如果是可选字段，可以直接添加；如果是必填字段，需要全员讨论。

### Q: 发现其他模块需要新的接口怎么办？
A: 定义接口规范，通知相关成员实现。

### Q: 需要修改公共契约文件怎么办？
A: 在群里发起讨论，所有成员同意后修改。
