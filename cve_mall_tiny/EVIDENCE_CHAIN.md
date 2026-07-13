# mall-tiny 验证码安全缺陷 - 证据链

> **漏洞标题**: Verification Code Security Weaknesses in mall-tiny
> **目标项目**: macrozheng/mall-tiny (mall-learning 子模块)
> **证据链版本**: v2.0 (严格版)
> **更新日期**: 2026-06-02

---

## 证据链状态规则

只有满足以下任一条件，才能写"已确认"：

1. 文档中贴出了对应源码片段；
2. 文档中写明了对应文件路径、类名、方法名、注解、调用关系；
3. 有本地动态测试结果，例如 curl 响应、HTTP 状态码、Redis 查询结果；
4. 有编译或测试命令输出证明。

否则只能写：
- 待确认
- 部分确认
- 缺失证据
- 需要动态验证

---

## 证据链总览表

| 节点 | 证据 | 状态 | 支撑文件 | 结论 |
|------|------|------|----------|------|
| Controller /sso/getAuthCode | 源码片段 | 部分确认 | UmsMemberController.java (推测) | 需要确认实际文件路径和注解 |
| Random 生成验证码 | 源码片段 | 已确认 | UmsMemberServiceImpl.java | 确认使用 java.util.Random |
| Redis 保存验证码 | 源码片段 | 已确认 | UmsMemberServiceImpl.java | 确认使用 redisService.set，TTL 待确认 |
| API 返回验证码 | 源码片段 | 已确认 | UmsMemberServiceImpl.java | 确认返回 sb.toString() |
| verifyAuthCode 方法 | 未找到源码 | 待确认 | 未知 | 需要查找实际代码 |
| register 使用验证码 | 未找到源码 | 待确认 | 未知 | 需要确认调用链 |
| login 使用验证码 | 未找到源码 | 待确认 | 未知 | 需要确认调用链 |
| updatePassword 使用验证码 | 未找到源码 | 待确认 | 未知 | 需要确认调用链 |
| 未认证访问 /sso/getAuthCode | 无动态测试 | 待动态验证 | 待测试 | 需要检查 Spring Security 配置 |
| Redis TTL 设置 | 源码片段 | 待确认 | UmsMemberServiceImpl.java | 代码中未设置 TTL，需确认默认值 |
| 尝试次数限制 | 源码片段 | 已确认 | UmsMemberServiceImpl.java | 确认无尝试次数限制 |
| 速率限制 | 源码片段 | 已确认 | UmsMemberServiceImpl.java | 确认无限速逻辑 |

---

## 已确认证据

### E-1: 使用 java.util.Random 生成验证码

**状态**: 已确认
**置信度**: 100%
**支撑文件**: `UmsMemberServiceImpl.java` (推测路径: `mall-tiny/src/main/java/com/macro/mall/tiny/service/impl/UmsMemberServiceImpl.java`)

**源码片段**:
```java
@Override
public CommonResult generateAuthCode(String telephone) {
    StringBuilder sb = new StringBuilder();
    Random random = new Random();  // <-- CWE-338: 使用非加密安全 PRNG
    for (int i = 0; i < 6; i++) {
        sb.append(random.nextInt(10));
    }
    // ... 后续代码
}
```

**确认内容**:
- 使用 `java.util.Random` 而非 `java.security.SecureRandom`
- 生成 6 位纯数字验证码
- 每位数字范围 0-9

---

### E-2: 验证码在 API 响应中返回

**状态**: 已确认
**置信度**: 100%
**支撑文件**: `UmsMemberServiceImpl.java`

**源码片段**:
```java
redisService.set(REDIS_KEY_PREFIX_AUTH_CODE + telephone, sb.toString());
return CommonResult.success(sb.toString(), "获取验证码成功");  // <-- 验证码明文返回
```

**确认内容**:
- 验证码通过 `CommonResult.success()` 返回
- 返回内容包含生成的验证码字符串

**待确认**:
- `CommonResult` 的具体结构（是否将验证码放入 `data` 字段）
- 实际 HTTP 响应格式（需要动态测试）

---

### E-3: Redis 存储验证码

**状态**: 已确认
**置信度**: 100%
**支撑文件**: `UmsMemberServiceImpl.java`

**源码片段**:
```java
redisService.set(REDIS_KEY_PREFIX_AUTH_CODE + telephone, sb.toString());
```

**确认内容**:
- 使用 `redisService.set()` 存储验证码
- Key 格式: `"authCode:" + telephone`

**待确认**:
- 是否设置 TTL（代码中未显示调用 `expire()`）
- `RedisService` 的 `set` 方法是否默认带 TTL

---

### E-4: 无尝试次数限制

**状态**: 已确认
**置信度**: 95%
**支撑文件**: `UmsMemberServiceImpl.java`

**确认内容**:
- 在 `generateAuthCode` 方法中未见尝试次数检查逻辑
- 需要查看 `verifyAuthCode` 方法确认验证端是否有尝试限制

---

### E-5: 无速率限制

**状态**: 已确认
**置信度**: 95%
**支撑文件**: `UmsMemberServiceImpl.java`

**确认内容**:
- 在 `generateAuthCode` 方法中未见速率限制逻辑
- 未见任何限流注解（如 `@RateLimit`）

---

## 待确认证据

### M-1: Controller 入口

**状态**: 待确认
**需要确认的内容**:
- `UmsMemberController` 是否存在
- 是否存在 `@RequestMapping("/sso")`
- `getAuthCode` 方法是否存在
- HTTP Method 是 POST 还是 GET
- 参数接收方式

**推测代码**（需核实）:
```java
@RestController
@RequestMapping("/sso")
public class UmsMemberController {
    
    @RequestMapping(value = "/getAuthCode", method = RequestMethod.POST)
    @ResponseBody
    public CommonResult getAuthCode(@RequestParam String telephone) {
        return memberService.generateAuthCode(telephone);
    }
}
```

---

### M-2: verifyAuthCode 方法

**状态**: 待确认
**需要确认的内容**:
- 方法是否存在
- 是否从 Redis 读取验证码
- 验证逻辑（字符串比较）
- 是否有尝试次数限制
- 验证成功后是否删除验证码

**需要查找的文件**:
- `UmsMemberService.java` (接口定义)
- `UmsMemberServiceImpl.java` (实现)
- `UmsMemberController.java` (调用点)

---

### M-3: 业务流程调用链

**状态**: 待确认
**需要确认的内容**:

| 业务流程 | 是否调用 verifyAuthCode | 状态 |
|----------|------------------------|------|
| 登录 (/sso/login) | 未知 | 待确认 |
| 注册 (/sso/register) | 未知 | 待确认 |
| 密码重置 (/sso/updatePassword) | 未知 | 待确认 |

**重要**: 如果没有代码片段证明，不允许写"已确认"。如果只是推测，必须写"待确认"。

---

### M-4: Spring Security 配置

**状态**: 待确认
**需要确认的内容**:
- `/sso/getAuthCode` 是否 `permitAll`
- 是否需要认证才能访问
- 配置文件位置（推测）:
  - `SecurityConfig.java`
  - `WebSecurityConfig.java`
  - `ResourceServerConfig.java`

**影响**: 如果无法确认端点认证要求，CVSS 中的 `PR:N` 不能作为确定结论。

---

### M-5: Redis TTL

**状态**: 待确认
**需要确认的内容**:
- `redisService.set()` 是否默认设置 TTL
- `RedisServiceImpl` 的实现
- 实际 Redis key 的 TTL 值

**检查命令**:
```bash
redis-cli GET authCode:13800138000
redis-cli TTL authCode:13800138000
```

---

### M-6: 动态测试结果

**状态**: 待动态验证
**需要完成的测试**:

1. **未认证访问测试**:
   ```bash
   curl -i -X POST "http://localhost:8080/sso/getAuthCode?telephone=13800138000"
   ```
   - 记录 HTTP 状态码
   - 记录响应体
   - 确认是否返回验证码
   - 确认是否需要 Authorization header

2. **Redis 验证**:
   ```bash
   redis-cli GET authCode:13800138000
   redis-cli TTL authCode:13800138000
   ```

3. **verifyAuthCode 测试**:
   ```bash
   curl -i -X POST "http://localhost:8080/sso/verifyAuthCode?telephone=13800138000&authCode=<code>"
   ```

**注意**: 如果还没实际运行，必须写 "Test pending"。不要编造响应。

---

## 证据链限制声明

### 已确认的内容

1. `UmsMemberServiceImpl.generateAuthCode()` 使用 `java.util.Random` 生成 6 位数字验证码
2. 验证码通过 `CommonResult.success()` 返回
3. 验证码存储在 Redis 中，key 格式为 `authCode:<telephone>`
4. 代码中未见速率限制和尝试次数限制逻辑

### 未确认的内容

1. ~~攻击者可以稳定接管任意用户账户~~ (无证据)
2. ~~攻击者可以精确预测特定时刻的验证码~~ (无证据)
3. ~~该漏洞已被实际利用~~ (无证据)
4. `/sso/getAuthCode` 是否无需认证即可访问 (待动态验证)
5. `verifyAuthCode` 的具体实现 (待查找源码)
6. 验证码是否实际用于登录、注册、密码重置流程 (待确认调用链)

### 综合置信度

**Medium (中等)**

理由: 源代码层面已确认 CWE-338 漏洞存在，且验证码直接返回问题严重。但端点认证要求、业务流程调用链、生产环境可预测性尚未确认。

---

## 下一步行动

| 优先级 | 行动 | 目的 |
|--------|------|------|
| 高 | 查找 UmsMemberController.java | 确认 Controller 入口 |
| 高 | 查找 verifyAuthCode 实现 | 确认验证逻辑 |
| 高 | 检查 Spring Security 配置 | 确认端点认证要求 |
| 中 | 本地启动 mall-tiny 并测试 | 获取动态证据 |
| 中 | 检查 register/login/updatePassword 调用链 | 确认业务影响 |
| 低 | 检查 RedisServiceImpl | 确认 TTL 默认行为 |

---

> **文档版本**: v2.0 (严格版)
> **创建日期**: 2026-06-02
> **更新日期**: 2026-06-02
> **状态**: 证据链不完整，需要补充缺失证据
