# mall-tiny 验证码安全缺陷复现指南

> **漏洞类型**: Verification Code Security Weaknesses (CWE-338, CWE-200, CWE-307, CWE-770, CWE-775)
> **目标项目**: macrozheng/mall-tiny (mall-learning 子模块)
> **文档用途**: 本地安全研究验证，仅供授权测试环境使用
> **状态**: CVE Candidate / Need more evidence

---

## 1. 漏洞概述

mall-tiny 是一个基于 Spring Boot 的轻量级电商后端项目，由 macrozheng 开源维护。该项目使用了验证码机制。然而，验证码的生成使用了 `java.util.Random` 而非 `java.security.SecureRandom`，存在以下安全问题：

- **弱随机数生成**: `java.util.Random` 是线性同余生成器，不具备密码学安全性
- **验证码直接返回**: API 响应体中直接包含生成的验证码，存在设计缺陷
- **无速率限制**: 验证码获取接口无请求频率限制
- **无尝试次数限制**: 验证码校验接口无错误次数限制
- **无过期时间**: Redis 中存储的验证码未设置过期时间
- **无手机号格式校验**: 未对手机号格式进行合法性验证

> **重要声明**: 当前只证明验证码机制设计缺陷。验证码是否实际用于登录、注册、密码重置等业务流程，**尚未通过源码调用链和动态测试确认**。不要声称登录、注册、密码重置已受影响。

---

## 2. 受影响版本

### 获取受影响代码

```bash
git clone https://github.com/macrozheng/mall-learning.git
cd mall-learning/mall-tiny
git branch -a
git log --oneline -10
```

mall-tiny 作为 mall-learning 仓库的子模块存在，主要代码位于 `mall-tiny` 目录下。

---

## 3. 环境准备

| 组件 | 版本要求 | 说明 |
|------|---------|------|
| JDK | 1.8+ | 推荐 OpenJDK 11 或 Oracle JDK 8 |
| Maven | 3.6+ | 项目构建工具 |
| MySQL | 5.7+ / 8.0 | 数据库 |
| Redis | 5.0+ | 缓存服务，用于存储验证码 |
| Git | 最新版 | 获取源代码 |

### 数据库初始化

```bash
mysql -u root -p -e "CREATE DATABASE mall_tiny DEFAULT CHARACTER SET utf8mb4;"
mysql -u root -p mall_tiny < doc/sql/mall_tiny.sql
```

### Redis 配置

```bash
redis-cli ping  # 应返回 PONG
```

### 修改配置文件

编辑 `mall-tiny/src/main/resources/application.yml`，配置数据库和 Redis 连接信息。

---

## 4. 启动步骤

```bash
cd mall-learning/mall-tiny
mvn clean install -DskipTests
mvn spring-boot:run
```

应用默认启动在 `http://localhost:8080`。

---

## 5. 证据链分析

### Controller API 入口

**文件**: `com.macro.mall.tiny.controller.UmsMemberController`

```java
@ApiOperation("获取验证码")
@RequestMapping(value = "/getAuthCode", method = RequestMethod.POST)
@ResponseBody
public CommonResult getAuthCode(@RequestParam String telephone) {
    return memberService.generateAuthCode(telephone);
}
```

### Service 层实现

**文件**: `com.macro.mall.tiny.service.impl.UmsMemberServiceImpl`

```java
@Override
public CommonResult generateAuthCode(String telephone) {
    StringBuilder sb = new StringBuilder();
    Random random = new Random();  // CWE-338: 不安全
    for (int i = 0; i < 6; i++) {
        sb.append(random.nextInt(10));
    }
    redisTemplate.opsForValue().set("authCode:" + telephone, sb.toString());
    return CommonResult.success(sb.toString());  // 验证码明文返回
}
```

### 完整链路图

```
[1] POST /sso/getAuthCode?telephone=xxx
[2] UmsMemberServiceImpl.generateAuthCode()
[3] java.util.Random.nextInt(10) x 6
[4] Redis 存储 (无过期时间)
[5] API 响应直接返回验证码  ← 设计缺陷
[6] verifyAuthCode() (无尝试次数限制) ← 待确认实际实现
[7] 登录 / 注册 / 密码重置流程 ← 待确认：是否调用 verifyAuthCode 尚未验证
```

> **注意**: 节点 [6] 和 [7] 的调用链尚未通过源码确认。不要声称登录、注册、密码重置已受影响。

### 缺陷汇总

| 缺陷 | 描述 | CWE |
|------|------|-----|
| D-1 | 使用 `java.util.Random` 而非 `SecureRandom` | CWE-338 |
| D-2 | 验证码在 API 响应中直接返回 | CWE-200 |
| D-3 | `/sso/getAuthCode` 无速率限制 | CWE-770 |
| D-4 | `verifyAuthCode` 无尝试次数限制 | CWE-307 |
| D-5 | Redis 验证码无过期时间 | CWE-775 |
| D-6 | 无手机号格式校验 | CWE-20 |

---

## 6. 验证码生成逻辑分析

### java.util.Random 的安全性问题

`java.util.Random` 使用线性同余生成器（LCG），核心算法：

```
next(seed) = (seed * 0x5DEECE66DL + 0xBL) & ((1L << 48) - 1)
```

**关键弱点**:
1. **种子空间有限**: 默认种子基于 `System.nanoTime()`，种子空间为 48 位
2. **输出可预测（理论）**: 如果攻击者能推断种子值，则可预测后续随机数输出。但在实际生产环境中，种子推断的可行性尚未得到验证。
3. **不适用于安全场景**: java.util.Random 的设计目标不包含密码学安全性，不应被用于验证码等安全敏感值

> **重要**: 本报告**不声称**可以在生产环境中稳定预测 mall-tiny 验证码。上述分析仅为原理说明。

### 与 SecureRandom 的对比

| 特性 | java.util.Random | java.security.SecureRandom |
|------|-----------------|---------------------------|
| 算法 | LCG (线性同余) | 操作系统提供的高熵源 |
| 种子 | 48位，基于时间 | 160+位，基于系统熵 |
| 可预测性 | 可预测 | 不可预测 |
| 适用场景 | 非安全用途 | 密码学安全用途 |

---

## 7. 诚实评估

### 已确认的安全风险

- mall-tiny 在安全敏感的验证码生成中使用了密码学不安全的 `java.util.Random`
- 验证码在 API 响应中直接返回，验证码机制的安全价值完全丧失
- 验证码获取接口无速率限制，存在被滥用的风险
- 验证码校验无尝试次数限制，存在暴力破解的理论可能

### 无法确认的风险

- 在生产环境中稳定预测特定验证码的可行性（需要更多分析）
- 该端点是否实际无需认证即可访问（需检查 Spring Security 配置）
- 是否存在其他层面的安全防护（如 WAF、反向代理限制）
- 验证码是否实际用于登录、注册、密码重置流程（需确认调用链）

### 当前结论

**当前只证明验证码机制设计缺陷，业务影响待确认。**

### 置信度评估

| 评估维度 | 置信度 | 说明 |
|---------|-------|------|
| 源代码确认 | **高** | 已直接确认 `java.util.Random` 的使用 |
| 验证码返回问题 | **高** | API 响应中确实包含验证码 |
| 无速率限制 | **高** | 代码中未见速率限制逻辑 |
| 暴力破解可行性 | **中** | 需确认端点是否需要认证 |
| 随机数预测可行性 | **中低** | 理论上可行但需要更多信息 |
| 实际账户接管 | **低** | 缺乏端到端的利用链证据 |

---

## 8. 限制声明

- 本文档仅用于**本地授权环境**下的安全研究验证
- **不包含**任何针对第三方系统的攻击脚本
- **不包含**任何暴力破解、批量攻击或短信轰炸代码
- **不鼓励**任何未经授权的安全测试行为

如确认漏洞真实存在且具有安全影响，应遵循负责任的披露流程。

---

> **文档版本**: v1.1 (修正版)
> **创建日期**: 2026-06-02
> **修正日期**: 2026-06-02
> **用途**: VulnPatch 项目本地安全研究
