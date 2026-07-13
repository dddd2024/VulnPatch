# 动态测试状态报告

> **报告日期**: 2026-06-02
> **最后更新**: 2026-06-02 (v1.1)
> **测试环境**: 未配置（缺少 MySQL、Redis、完整 mall-tiny 源码）
> **状态**: 待完成

---

## CVE_FIX.patch 编译验证

### RedisService 方法检查

**状态**: 无法直接验证（mall-tiny 完整源码不在本地）

需要确认 RedisService 接口是否包含以下方法：

| 方法 | 用途 | 状态 |
|------|------|------|
| `String get(String key)` | 读取验证码、尝试次数、限流时间 | 待确认 |
| `void set(String key, String value)` | 存储验证码、计数器 | 待确认 |
| `boolean expire(String key, long time)` | 设置过期时间 | 待确认 |
| `void del(String key)` | 删除验证码、计数器 | 待确认 |

**说明**: mall-tiny 项目通常使用 Spring Data Redis 或自定义 RedisService 封装。
根据 mall-tiny 的常见实现，`RedisService` 接口通常包含 `get`、`set`、`set(key,value,time)`、`expire`、`del` 方法。
但**未在本地源码中确认**，需要在实际 mall-tiny 项目中验证。

### UmsMemberService 接口检查

**状态**: 无法直接验证

需要确认 `UmsMemberService` 接口是否声明了 `verifyAuthCode` 方法。

**说明**: patch 中假设 `verifyAuthCode` 是 `UmsMemberService` 接口的方法。
如果原接口没有此方法，需要在接口中添加声明。

### Patch 代码审查结果

| 检查项 | 状态 | 说明 |
|--------|------|------|
| Long.parseLong 异常处理 | ✅ 已修复 | rateLimit 部分已添加 try-catch |
| Integer.parseInt 异常处理 | ✅ 已有 | attempts 解析已有 try-catch |
| authCode 空值检查 | ✅ 已有 | 使用 StringUtils.hasText() |
| redisAuthCode 空值检查 | ✅ 已有 | 使用 StringUtils.hasText() |
| 验证成功后删除验证码 | ✅ 已有 | redisService.del() |
| TTL 维护 | ✅ 已有 | 每次 set 后调用 expire |
| 频率限制实现 | ✅ 已有 | Redis 计数 + TTL |
| 开发模式配置 | ✅ 已有 | @Value 配置项 |

### mvn clean compile

**状态**: 未执行

**原因**: mall-tiny 完整源码不在本地（f:\test 中仅有分析框架和代码片段）。
需要克隆 macrozheng/mall-learning 仓库后才能编译。

```bash
# 需要先获取源码
git clone https://github.com/macrozheng/mall-learning.git
cd mall-learning/mall-tiny
git apply <path_to_CVE_FIX.patch>
mvn clean compile
```

**预期结果**: 如果 RedisService 包含所需方法，编译应成功。
如果 RedisService 缺少 `expire` 或 `del` 方法，需要先补充接口和实现。

---

## 测试环境限制说明

由于当前环境限制，以下测试**尚未完成**：

1. **缺少 mall-tiny 完整源码**
   - 当前仅基于代码片段分析
   - 需要完整项目结构才能编译运行

2. **缺少数据库环境**
   - MySQL 未安装/配置
   - 无法初始化 mall_tiny 数据库

3. **缺少缓存环境**
   - Redis 未安装/运行
   - 无法测试验证码存储和 TTL

4. **缺少编译环境**
   - Maven 依赖未下载
   - 无法验证 patch 编译

---

## 待完成的测试清单

### 1. 编译测试

```bash
# 在 mall-tiny 目录执行
mvn clean compile
```

**预期结果**: 编译成功，无错误

**实际状态**: 未执行

---

### 2. 启动服务测试

```bash
mvn spring-boot:run
```

**预期结果**: 应用启动在 http://localhost:8080

**实际状态**: 未执行

---

### 3. getAuthCode 接口测试

```bash
curl -i -X POST "http://localhost:8080/sso/getAuthCode?telephone=13800138000"
```

**需要记录**:
- HTTP 状态码
- 响应体
- 是否返回验证码
- 是否需要认证

**实际状态**: 未执行

---

### 4. Redis TTL 测试

```bash
redis-cli GET authCode:13800138000
redis-cli TTL authCode:13800138000
```

**需要确认**:
- 验证码是否正确保存
- TTL 是否为 -1（无过期）或正数

**实际状态**: 未执行

---

### 5. verifyAuthCode 测试

```bash
curl -i -X POST "http://localhost:8080/sso/verifyAuthCode?telephone=13800138000&authCode=<code>"
```

**需要确认**:
- 正确验证码是否通过
- 错误验证码是否可无限尝试
- 验证成功后验证码是否仍存在

**实际状态**: 未执行

---

### 6. 错误次数限制测试

连续提交错误验证码 5 次：

```bash
for i in {1..6}; do
  curl -i -X POST "http://localhost:8080/sso/verifyAuthCode?telephone=13800138000&authCode=00000$i"
done
```

**需要确认**: 是否有锁定或限制

**实际状态**: 未执行

---

### 7. 修复后回归测试

应用 CVE_FIX.patch 后重新运行：

- [ ] getAuthCode 正常工作
- [ ] Redis TTL 正确设置（5分钟）
- [ ] verifyAuthCode 正常工作
- [ ] 错误次数限制生效（最多5次）
- [ ] 默认不返回验证码（生产模式）
- [ ] 开发模式可配置返回验证码

**实际状态**: 未执行

---

## 证据链影响

由于动态测试未完成，以下证据链节点状态为**待确认**：

| 节点 | 状态 | 影响 |
|------|------|------|
| 未认证访问 | 待动态验证 | CVSS PR 字段无法确定 |
| API 响应格式 | 待动态验证 | 无法确认验证码是否实际返回 |
| Redis TTL | 待动态验证 | 无法确认是否永久存储 |
| verifyAuthCode 行为 | 待动态验证 | 无法确认验证逻辑 |
| 业务影响 | 待动态验证 | 无法确认登录/注册/密码重置是否受影响 |

---

## 建议

1. **短期**: 在具备完整环境后优先完成动态测试
2. **中期**: 根据动态测试结果更新证据链和 CVSS 评分
3. **长期**: 完成所有测试后再决定是否申请 CVE

---

> **结论**: 当前动态测试因环境限制未完成，所有测试状态标记为 "Test pending"。
> 在 CVE_READINESS_REVIEW.md 和 CVE_POC.md 中已如实记录此状态。
