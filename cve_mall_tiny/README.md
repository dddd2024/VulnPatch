# mall-tiny 验证码安全缺陷 - CVE Candidate

> **状态**: CVE Candidate / Need more evidence  
> **置信度**: Medium  
> **最后更新**: 2026-06-02

---

## 快速参考

### 漏洞标题

**Verification Code Security Weaknesses in mall-tiny**

副标题：The issue includes use of java.util.Random for verification-code generation, verification code disclosure in API responses, missing expiration, missing attempt limits, and missing rate limiting.

### CWE 列表

- CWE-338: Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)
- CWE-330: Use of Insufficiently Random Values
- CWE-200: Information Exposure
- CWE-307: Improper Restriction of Excessive Authentication Attempts
- CWE-770: Allocation of Resources Without Limits or Throttling
- CWE-775: Missing Release of Resource after Effective Lifetime

### 当前结论

| 判断项 | 结论 |
|--------|------|
| 是否建议申请 CVE | **Need more evidence** |
| 当前置信度 | **Medium (中等)** |
| 重复风险 | **Low (低)** |
| 下一步 | 先补充动态验证，再联系维护者 |

---

## CVE Candidate Review

### 如何运行 CVE 候选分析

VulnPatch 扫描结果会自动包含 `cve_candidates` 字段：

```python
from audit_core.orchestrator import AuditOrchestrator
from cve_candidate.evaluator import CveCandidateEvaluator

orchestrator = AuditOrchestrator()
result = orchestrator.scan_code(java_code, language="java")

# CVE 候选评估
evaluator = CveCandidateEvaluator()
cve_results = evaluator.evaluate_batch(result.findings)
for r in cve_results:
    if r.cve_candidate:
        print(f"CVE candidate: {r.title} (confidence={r.confidence})")
        print(f"  Missing evidence: {r.missing_evidence}")
```

### 如何查看 cve_candidates 输出

扫描结果中的 `cve_candidates` 字段示例：

```json
{
  "cve_candidates": [
    {
      "title": "Verification Code Security Weaknesses in mall-tiny",
      "cve_candidate": true,
      "readiness": "Need more evidence",
      "confidence": "medium",
      "reason": "Source code confirms weak verification-code generation and disclosure, but endpoint authentication requirements and business impact need dynamic verification.",
      "evidence": [
        "java.util.Random is used to generate 6-digit verification codes.",
        "The generated verification code appears to be returned in the API response.",
        "The verification code is stored in Redis."
      ],
      "missing_evidence": [
        "Whether /sso/getAuthCode is accessible without authentication.",
        "Whether register, login, or password reset flows actually rely on verifyAuthCode.",
        "Whether the affected code is present in a formal release tag.",
        "Whether a dynamic PoC confirms the end-to-end impact."
      ],
      "duplicate_check": {
        "duplicate_risk": "low",
        "possible_duplicates": [],
        "notes": "Known mall-tiny CVEs appear to cover different vulnerability classes."
      },
      "recommended_next_steps": [
        "Run local dynamic tests.",
        "Confirm Spring Security configuration.",
        "Confirm affected version range.",
        "Privately report to the maintainer via GitHub Security Advisory."
      ]
    }
  ]
}
```

### 如何查看 missing_evidence

所有缺失证据都会在 `missing_evidence` 字段中列出。如果该列表为空且 `confidence` 为 `high`，说明证据充分，可以考虑申请 CVE。

### 为什么 Need more evidence 不等于 No

"Need more evidence" 表示：
- 已确认存在安全问题（源代码层面）
- 但证据不足以支持 CVE 申请
- 需要补充动态测试、版本确认、业务影响验证

这不是"没有漏洞"，而是"证据不足"。

### 为什么不能把 CVE-PENDING 写成已分配 CVE

- **CVE-PENDING**: 表示正在准备 CVE 申请材料，尚未获得 CVE 编号
- **CVE-202X-XXXXX**: 表示 MITRE 已分配的正式 CVE 编号
- 在获得正式 CVE 编号前，只能使用 CVE-PENDING

---

## 如何运行本地复现测试

### 环境准备

```bash
# 1. 克隆仓库
git clone https://github.com/macrozheng/mall-learning.git
cd mall-learning/mall-tiny

# 2. 确认受影响版本
# 注意：需要确认哪个 tag/commit 包含 vulnerable generateAuthCode 实现

# 3. 配置 MySQL 和 Redis
# 编辑 src/main/resources/application.yml

# 4. 编译和启动
mvn clean package -DskipTests
mvn spring-boot:run
```

### 测试命令

```bash
# 未认证访问测试
curl -i -X POST "http://localhost:8080/sso/getAuthCode?telephone=13800138000"

# Redis 检查
redis-cli GET authCode:13800138000
redis-cli TTL authCode:13800138000

# verifyAuthCode 测试
curl -i -X POST "http://localhost:8080/sso/verifyAuthCode?telephone=13800138000&authCode=<code>"
```

详细步骤参见: [CVE_POC.md](CVE_POC.md)

---

## 如何应用 CVE_FIX.patch

### 应用补丁

```bash
cd mall-learning/mall-tiny

# 检查补丁内容
cat CVE_FIX.patch

# 应用补丁
git apply CVE_FIX.patch

# 或者使用 patch 命令
patch -p2 < CVE_FIX.patch
```

### 验证编译

```bash
mvn clean compile
```

**注意**: Patch 中使用了 `redisService.expire()` 和 `redisService.del()`，需要确认 RedisService 接口是否有这些方法。如果缺少，需要补充接口和实现。

---

## 开发环境如何打开验证码返回

在 `application-dev.yml` 中添加配置：

```yaml
mall:
  auth-code:
    return-in-response: true
    rate-limit-seconds: 10  # 开发环境可以更短
```

**警告**: 仅开发环境允许返回验证码，生产环境必须设置为 `false`。

---

## 生产环境为什么禁止验证码明文返回

1. **安全风险**: 验证码在 API 响应中返回，任何能调用该 API 的主体都能获取验证码
2. **设计缺陷**: 验证码的安全价值在于"只有手机号持有者才能收到"，直接返回破坏了这一假设
3. **正确做法**: 验证码应通过短信网关发送到用户手机，API 只返回"验证码已发送"

---

## 文件说明

| 文件 | 说明 |
|------|------|
| `CVE_SUBMISSION.md` | CVE 候选提交材料（修正版） |
| `CVE_READINESS_REVIEW.md` | CVE 申请就绪性评审 |
| `EVIDENCE_CHAIN.md` | 严格证据链（禁止过度确认） |
| `DUPLICATE_CHECK.md` | 去重检查报告（修正 CVE 描述） |
| `CVE_FIX.patch` | 修复补丁（待验证编译） |
| `CVE_POC.md` | 概念验证指南（含动态测试步骤） |
| `CVE_POC.java` | Random 原理演示（附录） |
| `DYNAMIC_TEST_STATUS.md` | 动态测试状态报告 |
| `poc/` | PoC 代码目录 |

---

## 禁止事项

1. 不要编造 CVE 编号
2. 不要把 CVE-PENDING 写成已经分配的 CVE
3. 不要公开发 GitHub Issue
4. 不要写批量攻击、短信轰炸、撞库、爆破工具
5. 不要声称已经实现账户接管（除非有完整动态证据）
6. 不要声称稳定预测生产验证码（除非有可重复实验数据）
7. 不要在端点认证未确认时写 PR:N 为最终结论
8. 不要在业务调用链未确认时写登录、注册、密码重置都受影响
9. 不要只靠 java.util.Random 就判定 High
10. 不要继续扩写没有证据的风险描述

---

## 最终结论

当前 mall-tiny 验证码问题的 CVE 申请就绪性：**Need more evidence**

当前置信度：**Medium**

当前不建议直接申请 MITRE CVE

当前不建议公开 issue

**建议先补充动态验证，并通过 GitHub Security Advisory 私密联系维护者**

---

> **版本**: v2.0 (修正版)
> **更新日期**: 2026-06-02
