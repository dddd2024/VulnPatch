# CVE PoC: mall-tiny 验证码安全缺陷

> **漏洞类型**: Verification Code Security Weaknesses (CWE-338, CWE-200, CWE-307, CWE-770)
> **目标项目**: macrozheng/mall-tiny (mall-learning 子模块)
> **文档用途**: 本地安全研究验证，仅供授权测试环境使用
> **状态**: 待完成动态测试

---

## 1. 测试目标

| 项目 | 内容 |
|------|------|
| **目标项目** | macrozheng/mall-learning 或 macrozheng/mall-tiny |
| **目标模块** | mall-tiny |
| **目标接口** | `/sso/getAuthCode` |
| **目标方法** | `UmsMemberServiceImpl.generateAuthCode` |
| **目标验证方法** | `verifyAuthCode` (待确认) |

**注意**: Affected version is not fully confirmed. The test should be run against the commit or tag that contains the vulnerable `generateAuthCode` implementation.

---

## 2. 环境准备

### 2.1 获取代码

```bash
# 克隆仓库
git clone https://github.com/macrozheng/mall-learning.git
cd mall-learning/mall-tiny

# 查看可用分支和标签
git branch -a
git tag -l
git log --oneline -10

# 注意：需要确认哪个 tag/commit 包含 vulnerable generateAuthCode 实现
```

### 2.2 依赖检查

| 组件 | 版本要求 | 检查命令 |
|------|---------|---------|
| JDK | 1.8+ | `java -version` |
| Maven | 3.6+ | `mvn -version` |
| MySQL | 5.7+ / 8.0 | `mysql --version` |
| Redis | 5.0+ | `redis-cli ping` |

### 2.3 数据库初始化

```bash
# 创建数据库
mysql -u root -p -e "CREATE DATABASE IF NOT EXISTS mall_tiny DEFAULT CHARACTER SET utf8mb4;"

# 导入初始化 SQL（如果存在）
# mysql -u root -p mall_tiny < doc/sql/mall_tiny.sql
```

### 2.4 配置文件修改

编辑 `src/main/resources/application.yml` 或 `application-dev.yml`：

```yaml
spring:
  datasource:
    url: jdbc:mysql://localhost:3306/mall_tiny?useUnicode=true&characterEncoding=utf-8
    username: root
    password: your_password
  redis:
    host: localhost
    port: 6379
```

### 2.5 编译和启动

```bash
# 编译
mvn clean package -DskipTests

# 启动
mvn spring-boot:run

# 或运行 jar
java -jar target/mall-tiny-*.jar
```

**预期**: 应用启动在 `http://localhost:8080`

---

## 3. 未认证访问测试

### 3.1 测试命令

```bash
curl -i -X POST "http://localhost:8080/sso/getAuthCode?telephone=13800138000"
```

### 3.2 需要记录的信息

| 检查项 | 预期/实际 | 备注 |
|--------|----------|------|
| HTTP 状态码 | 200 / 401 / 403 | 200 表示可能无需认证 |
| 响应体 | JSON / 空 | 是否包含验证码 |
| 是否需要 Authorization header | 是 / 否 | 检查是否被 Spring Security 拦截 |
| 是否被重定向到登录页 | 是 / 否 | 检查登录要求 |

### 3.3 测试状态

**状态**: Test pending

> 注意：在完成实际测试前，不要声称未认证访问可行。

---

## 4. 验证码返回测试

### 4.1 测试命令

```bash
curl -i -X POST "http://localhost:8080/sso/getAuthCode?telephone=13800138001"
```

### 4.2 预期响应示例（如果测试确认）

```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "code": 200,
  "message": "操作成功",
  "data": "123456"
}
```

### 4.3 需要记录的信息

| 检查项 | 实际值 | 备注 |
|--------|--------|------|
| 响应中是否包含验证码 | 是 / 否 | 检查 `data` 字段 |
| 验证码格式 | 6位数字 / 其他 | 确认生成逻辑 |
| 响应消息 | - | 检查 `message` 字段 |

### 4.4 测试状态

**状态**: Test pending

> 注意：不要编造响应。如果实际测试未返回验证码，需记录实际行为。

---

## 5. Redis 验证

### 5.1 检查命令

```bash
# 检查验证码是否保存
redis-cli GET authCode:13800138000

# 检查 TTL（过期时间）
redis-cli TTL authCode:13800138000
```

### 5.2 TTL 结果说明

| TTL 值 | 含义 |
|--------|------|
| -1 | 未设置过期时间（永久存储）|
| -2 | Key 不存在 |
| > 0 | 剩余秒数 |

### 5.3 需要记录的信息

| 检查项 | 实际值 | 备注 |
|--------|--------|------|
| 验证码值 | - | 与 API 返回对比 |
| TTL | -1 / 正数 | 确认是否有过期时间 |

### 5.4 测试状态

**状态**: Test pending

---

## 6. verifyAuthCode 测试

### 6.1 确认接口路径

首先确认 `verifyAuthCode` 接口的实际路径：

```bash
# 尝试常见路径
curl -i -X POST "http://localhost:8080/sso/verifyAuthCode?telephone=13800138000&authCode=123456"

# 或其他可能路径
curl -i -X POST "http://localhost:8080/sso/verifyAuthCode" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "telephone=13800138000&authCode=123456"
```

### 6.2 测试用例

#### 测试 6.2.1: 正确验证码

```bash
curl -i -X POST "http://localhost:8080/sso/verifyAuthCode?telephone=13800138000&authCode=<正确的验证码>"
```

**预期**: 验证成功

#### 测试 6.2.2: 错误验证码

```bash
curl -i -X POST "http://localhost:8080/sso/verifyAuthCode?telephone=13800138000&authCode=000000"
```

**预期**: 验证失败

#### 测试 6.2.3: 多次错误尝试

连续提交错误验证码 5 次以上：

```bash
for i in {1..6}; do
  curl -i -X POST "http://localhost:8080/sso/verifyAuthCode?telephone=13800138000&authCode=00000$i"
done
```

**需要确认**: 
- 是否有锁定机制
- 错误次数是否被记录
- 超过次数后是否拒绝验证

#### 测试 6.2.4: 验证后验证码状态

```bash
# 1. 获取新验证码
curl -X POST "http://localhost:8080/sso/getAuthCode?telephone=13800138002"

# 2. 使用正确验证码验证
curl -X POST "http://localhost:8080/sso/verifyAuthCode?telephone=13800138002&authCode=<code>"

# 3. 检查 Redis 中验证码是否被删除
redis-cli GET authCode:13800138002

# 4. 尝试再次使用同一验证码
curl -X POST "http://localhost:8080/sso/verifyAuthCode?telephone=13800138002&authCode=<code>"
```

**需要确认**: 验证成功后验证码是否被删除（防止重放）

### 6.3 测试状态

**状态**: Test pending

---

## 7. 业务影响测试

### 7.1 检查注册流程

查找 `UmsMemberController` 或类似类中的 `register` 方法：

```bash
# 在源码中搜索
grep -r "verifyAuthCode" --include="*.java" .
grep -r "register" --include="*.java" . | grep -i "controller"
```

**需要确认**: `register` 方法是否调用 `verifyAuthCode`

### 7.2 检查登录流程

```bash
grep -r "login" --include="*.java" . | grep -i "controller"
```

**需要确认**: `login` 方法是否调用 `verifyAuthCode`

### 7.3 检查密码重置流程

```bash
grep -r "updatePassword" --include="*.java" . | grep -i "controller"
```

**需要确认**: `updatePassword` 方法是否调用 `verifyAuthCode`

### 7.4 测试状态

**状态**: Test pending

**重要**: 如果没有代码片段证明，不要写登录、注册、密码重置都受影响。

---

## 8. Random 原理演示

### 8.1 说明

以下代码演示为什么 `java.util.Random` 不适合生成验证码。这**不**构成对 mall-tiny 的稳定利用证明。

### 8.2 演示代码

```java
import java.util.Random;
import java.security.SecureRandom;

public class RandomDemonstration {
    
    public static void main(String[] args) {
        System.out.println("=== java.util.Random 安全性演示 ===\n");
        
        // 演示 1: 相同种子产生相同序列
        demonstrateSameSeed();
        
        // 演示 2: Random vs SecureRandom
        demonstrateComparison();
    }
    
    static void demonstrateSameSeed() {
        System.out.println("【演示】相同种子产生相同序列");
        System.out.println("-".repeat(50));
        
        long seed = System.currentTimeMillis();
        Random random1 = new Random(seed);
        Random random2 = new Random(seed);
        
        System.out.println("种子: " + seed);
        System.out.println("Random1 生成的6位验证码: " + generateCode(random1));
        System.out.println("Random2 生成的6位验证码: " + generateCode(random2));
        
        System.out.println("\n结论: 如果攻击者能推断种子，验证码可被预测。");
        System.out.println("但这不意味着 mall-tiny 生产环境可被稳定攻击。\n");
    }
    
    static void demonstrateComparison() {
        System.out.println("【对比】Random vs SecureRandom");
        System.out.println("-".repeat(50));
        
        Random random = new Random();
        SecureRandom secureRandom = new SecureRandom();
        
        System.out.println("Random 生成的验证码:        " + generateCode(random));
        System.out.println("SecureRandom 生成的验证码:  " + generateCode(secureRandom));
        
        System.out.println("\n特性对比:");
        System.out.println("  java.util.Random:");
        System.out.println("    - 使用线性同余生成器 (LCG)");
        System.out.println("    - 48位种子，可被逆向");
        System.out.println("    - 不适合安全敏感用途");
        System.out.println("  java.security.SecureRandom:");
        System.out.println("    - 使用系统强熵源");
        System.out.println("    - 不可预测");
        System.out.println("    - 适合验证码、密钥生成");
    }
    
    static String generateCode(Random random) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 6; i++) {
            sb.append(random.nextInt(10));
        }
        return sb.toString();
    }
}
```

### 8.3 重要声明

> This demonstrates why `java.util.Random` is unsuitable for verification codes. 
> It does not by itself prove a stable end-to-end exploit against a deployed mall-tiny instance.

---

## 9. 修复后回归测试

应用 `CVE_FIX.patch` 后，重新运行以下测试：

### 9.1 编译测试

```bash
mvn clean compile
```

**预期**: 编译成功，无错误

### 9.2 功能测试

| 测试项 | 预期结果 |
|--------|---------|
| getAuthCode | 正常生成验证码 |
| Redis TTL | 验证码有过期时间（如 5 分钟）|
| verifyAuthCode 正确码 | 验证成功，验证码被删除 |
| verifyAuthCode 错误码 | 验证失败，记录错误次数 |
| 错误次数超限 | 锁定并要求重新获取验证码 |
| 开发模式 | 配置 `mall.auth-code.return-in-response=true` 时返回验证码 |
| 生产模式 | 配置 `mall.auth-code.return-in-response=false` 时不返回验证码 |

### 9.3 测试状态

**状态**: Test pending (patch 待验证编译)

---

## 10. 测试结果汇总

### 10.1 测试完成状态

| 测试项 | 状态 | 备注 |
|--------|------|------|
| 环境准备 | 待完成 | - |
| 未认证访问测试 | 待完成 | - |
| 验证码返回测试 | 待完成 | - |
| Redis TTL 测试 | 待完成 | - |
| verifyAuthCode 测试 | 待完成 | - |
| 错误次数限制测试 | 待完成 | - |
| 业务影响测试 | 待完成 | - |
| 修复后回归测试 | 待完成 | Patch 待验证 |

### 10.2 当前结论

**Business impact is not fully confirmed.** 

The verified issue is a weakness in the verification-code generation and validation mechanism:
- Use of `java.util.Random` (CWE-338)
- Verification code disclosure in API responses (CWE-200)
- Missing expiration (CWE-775)
- Missing attempt limits (CWE-307)
- Missing rate limiting (CWE-770)

**Missing evidence for CVE application:**
- Whether `/sso/getAuthCode` is accessible without authentication
- Whether `verifyAuthCode` is actually used in login/register/password reset flows
- Whether the affected code is present in a formal release tag
- Dynamic PoC confirming end-to-end impact

---

## 11. 限制声明

1. 本文档仅用于**本地授权环境**下的安全研究验证
2. **不包含**任何针对第三方系统的攻击脚本
3. **不包含**任何暴力破解、批量攻击或短信轰炸代码
4. **不鼓励**任何未经授权的安全测试行为
5. 所有"Test pending"的测试必须在完成实际测试后才能更新结论

---

> **文档版本**: v1.0
> **创建日期**: 2026-06-02
> **状态**: 待完成动态测试
