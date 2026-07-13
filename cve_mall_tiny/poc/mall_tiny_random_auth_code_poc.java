/**
 * ============================================================================
 *  mall-tiny 验证码安全缺陷 - 概念验证 (PoC)
 * ============================================================================
 *
 *  漏洞类型: Verification Code Security Weaknesses
 *            (CWE-338, CWE-200, CWE-307, CWE-770, CWE-775)
 *  目标项目: macrozheng/mall-tiny (mall-learning 子模块)
 *  用途: 本地安全研究验证 ONLY
 *  状态: CVE Candidate / Need more evidence
 *
 * ============================================================================
 *  免责声明 (DISCLAIMER):
 *  本 PoC 仅用于授权安全研究和教育目的。严禁用于任何未经授权的
 *  安全测试或攻击行为。使用者需自行承担所有法律责任。
 *
 *  重要: 本 PoC 只证明验证码机制设计缺陷，不声称生产环境稳定预测，
 *  不声称账户接管，不声称登录/注册/密码重置已受影响。
 * ============================================================================
 */

import java.util.Random;
import java.security.SecureRandom;

/**
 * mall_tiny_random_auth_code_poc
 *
 * 本 PoC 演示了 mall-tiny 项目中验证码生成逻辑的安全缺陷。
 * 具体展示了:
 * 1. mall-tiny 中 UmsMemberServiceImpl.generateAuthCode 的实际代码逻辑
 * 2. java.util.Random 在种子已知时可被预测
 * 3. 验证码在 API 响应中直接返回的设计缺陷
 * 4. 无速率限制的安全风险
 *
 * 本文件不包含任何暴力破解、批量攻击或短信轰炸代码。
 */
public class MallTinyRandomAuthCodePoc {

    // =========================================================================
    // 第一部分: 还原 mall-tiny 中的验证码生成逻辑
    // =========================================================================

    /**
     * 还原 UmsMemberServiceImpl.generateAuthCode(String telephone) 中的
     * 验证码生成逻辑。
     *
     * 源文件: com.macro.mall.tiny.service.impl.UmsMemberServiceImpl
     *
     * 原始代码:
     *   @Override
     *   public CommonResult generateAuthCode(String telephone) {
     *       StringBuilder sb = new StringBuilder();
     *       Random random = new Random();
     *       for (int i = 0; i < 6; i++) {
     *           sb.append(random.nextInt(10));
     *       }
     *       redisTemplate.opsForValue().set("authCode:" + telephone, sb.toString());
     *       return CommonResult.success(sb.toString());
     *   }
     *
     * 问题:
     *   - 使用 java.util.Random 而非 java.security.SecureRandom
     *   - Random 使用线性同余生成器 (LCG)，不具备密码学安全性
     *   - 默认种子基于 System.nanoTime()，种子空间仅 48 位
     */
    public static String generateAuthCodeVulnerable() {
        StringBuilder sb = new StringBuilder();
        Random random = new Random(); // CWE-338: 不安全的随机数生成器
        for (int i = 0; i < 6; i++) {
            sb.append(random.nextInt(10));
        }
        return sb.toString();
    }

    // =========================================================================
    // 第二部分: 演示 java.util.Random 的可预测性
    // =========================================================================

    /**
     * 演示: 当 java.util.Random 的种子已知时，其输出是可预测的。
     *
     * java.util.Random 使用线性同余生成器 (LCG):
     *   next_seed = (seed * 0x5DEECE66DL + 0xBL) & ((1L << 48) - 1)
     *
     * 注意: 这仅演示原理。在实际生产环境中推断种子值的可行性
     * 尚未得到验证。本报告不声称可以稳定预测 mall-tiny 验证码。
     */
    public static void demonstratePredictability() {
        System.out.println("=== java.util.Random 可预测性演示 ===\n");

        long guessedSeed = System.currentTimeMillis();
        Random randomWithGuessedSeed = new Random(guessedSeed);

        StringBuilder predictedCode = new StringBuilder();
        for (int i = 0; i < 6; i++) {
            predictedCode.append(randomWithGuessedSeed.nextInt(10));
        }

        System.out.println("攻击者猜测的种子: " + guessedSeed);
        System.out.println("使用该种子预测的验证码: " + predictedCode.toString());
        System.out.println("\n结论: 如果攻击者能准确推断种子值，");
        System.out.println("则可以预测生成的验证码（仅原理演示）。");
        System.out.println("java.util.Random 的默认种子基于 System.nanoTime()。");
        System.out.println("\n【重要声明】这不证明 mall-tiny 生产环境可被稳定攻击。");
        System.out.println("实际利用需要满足多个前提条件，当前尚未验证。");
    }

    // =========================================================================
    // 第三部分: 演示验证码直接返回的设计缺陷
    // =========================================================================

    /**
     * 演示: mall-tiny 的 API 响应中直接包含验证码。
     *
     * 响应示例:
     *   {
     *     "code": 200,
     *     "message": "操作成功",
     *     "data": "583921"    <-- 验证码直接在响应体中返回
     *   }
     *
     * 这意味着任何能调用 POST /sso/getAuthCode 的主体都能直接获取验证码。
     */
    public static void demonstrateApiResponseFlaw() {
        System.out.println("\n=== 验证码直接返回设计缺陷演示 ===\n");

        String telephone = "13800138000";
        String authCode = generateAuthCodeVulnerable();

        System.out.println("请求: POST /sso/getAuthCode");
        System.out.println("参数: telephone=" + telephone);
        System.out.println();
        System.out.println("响应:");
        System.out.println("{");
        System.out.println("  \"code\": 200,");
        System.out.println("  \"message\": \"操作成功\",");
        System.out.println("  \"data\": \"" + authCode + "\"    <-- 验证码明文返回!");
        System.out.println("}");
        System.out.println();
        System.out.println("问题: 验证码在 API 响应体中直接返回，");
        System.out.println("验证码的安全验证价值完全丧失。");
        System.out.println("注意: 这可能是学习项目的简化设计，");
        System.out.println("生产环境应通过短信网关发送验证码。");
    }

    // =========================================================================
    // 第四部分: 演示无速率限制的风险
    // =========================================================================

    /**
     * 演示: /sso/getAuthCode 端点无速率限制。
     *
     * 在 mall-tiny 的源代码中:
     * - Controller 层未使用任何限流注解或拦截器
     * - Service 层未检查请求频率
     * - 未集成任何限流组件
     */
    public static void demonstrateNoRateLimiting() {
        System.out.println("\n=== 无速率限制风险演示 ===\n");

        System.out.println("模拟快速连续调用 5 次验证码生成 (无任何限制):");
        System.out.println();

        for (int i = 1; i <= 5; i++) {
            String code = generateAuthCodeVulnerable();
            System.out.println("  第 " + i + " 次调用 -> 验证码: " + code);
        }

        System.out.println();
        System.out.println("观察: 每次调用都能成功生成验证码，无任何频率限制。");
        System.out.println("风险: 攻击者可利用此特性分析 Random 的输出模式。");
    }

    // =========================================================================
    // 第五部分: 安全修复方案演示
    // =========================================================================

    /**
     * 演示安全的验证码生成方式。
     *
     * 修复要点:
     * 1. 使用 java.security.SecureRandom 替代 java.util.Random
     * 2. 设置 Redis 过期时间
     * 3. 添加速率限制
     * 4. 添加手机号格式校验
     * 5. 不在 API 响应中返回验证码
     */
    public static String generateAuthCodeSecure() {
        SecureRandom secureRandom = new SecureRandom();
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 6; i++) {
            sb.append(secureRandom.nextInt(10));
        }
        return sb.toString();
    }

    public static void demonstrateSecureFix() {
        System.out.println("\n=== 安全修复方案演示 ===\n");

        System.out.println("修复前 (mall-tiny 当前代码):");
        System.out.println("  Random random = new Random();  // CWE-338");
        System.out.println("  redisTemplate.opsForValue().set(key, code);  // 无过期时间");
        System.out.println("  return CommonResult.success(code);  // 验证码直接返回");
        System.out.println();
        System.out.println("修复后 (推荐方案):");
        System.out.println("  SecureRandom secureRandom = new SecureRandom();  // 密码学安全");
        System.out.println("  redisTemplate.opsForValue().set(key, code, 5, TimeUnit.MINUTES);  // 5分钟过期");
        System.out.println("  return CommonResult.success(\"验证码已发送\");  // 不返回验证码");
        System.out.println();

        String secureCode = generateAuthCodeSecure();
        System.out.println("安全验证码示例: " + secureCode);
        System.out.println("(SecureRandom 生成的验证码不可预测)");
    }

    // =========================================================================
    // 主方法: 运行所有演示
    // =========================================================================

    public static void main(String[] args) {
        System.out.println("==========================================================");
        System.out.println("  mall-tiny CWE-338 不安全随机数验证码 - 概念验证 (PoC)");
        System.out.println("  用途: 本地安全研究验证 ONLY");
        System.out.println("==========================================================");
        System.out.println();

        demonstratePredictability();
        demonstrateApiResponseFlaw();
        demonstrateNoRateLimiting();
        demonstrateSecureFix();

        System.out.println("\n==========================================================");
        System.out.println("  PoC 演示完成");
        System.out.println("  本 PoC 不包含任何攻击性代码。");
        System.out.println("  当前只证明验证码机制设计缺陷，业务影响待确认。");
        System.out.println("  请遵循负责任的披露流程报告漏洞。");
        System.out.println("==========================================================");
    }
}
