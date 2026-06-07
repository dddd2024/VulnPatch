"""
PoC 代码模板库

为不同漏洞类型提供多语言 PoC 代码模板，支持 Python 和 JavaScript 两种语言。
"""

from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from enum import Enum
import logging

logger = logging.getLogger(__name__)


class VulnType(Enum):
    """支持的漏洞类型"""
    SQL_INJECTION = "sql_injection"
    COMMAND_INJECTION = "command_injection"
    XSS = "xss"
    PATH_TRAVERSAL = "path_traversal"
    SSRF = "ssrf"
    HARDCODED_CREDENTIALS = "hardcoded_credentials"


class Language(Enum):
    """支持的编程语言"""
    PYTHON = "python"
    JAVASCRIPT = "javascript"
    JAVA = "java"
    GO = "go"
    PHP = "php"
    RUST = "rust"
    C = "c"
    CPP = "cpp"
    TYPESCRIPT = "typescript"


@dataclass
class PoCTemplate:
    """PoC 模板定义"""
    vuln_type: VulnType
    language: Language
    name: str
    description: str
    template: str
    expected_indicators: List[str]
    severity: str
    cwe: str


class PoCTemplateLibrary:
    """
    PoC 代码模板库

    为不同漏洞类型和语言提供可复用的 PoC 模板。
    模板使用占位符机制，允许运行时注入目标代码和参数。
    """

    # SQL 注入 PoC 模板
    SQLI_PYTHON = '''
"""
SQL Injection PoC - Python
Target: {{target_file}}
"""
import sys
import json
import re
import sqlite3
from io import StringIO

# 读取目标代码
with open(r"{{target_file}}", "r", encoding="utf-8") as f:
    target_code = f.read()

# 检测 SQL 注入特征
indicators = []

# 1. 检查字符串拼接/格式化构建 SQL
sql_patterns = [
    r'["\']\\s*SELECT\\s+.*\\s+FROM\\s+.*["\']\\s*\\+',
    r'["\']\\s*INSERT\\s+INTO\\s+.*["\']\\s*\\+',
    r'["\']\\s*UPDATE\\s+.*\\s+SET\\s+.*["\']\\s*\\+',
    r'["\']\\s*DELETE\\s+FROM\\s+.*["\']\\s*\\+',
    r'f["\'].*SELECT\\s+.*\\{.*\\}.*["\']',
    r'\.format\\s*\\(.*SELECT',
    r'%\\s*\\(.*\\)\\s*.*SELECT',
]

for pattern in sql_patterns:
    if re.search(pattern, target_code, re.IGNORECASE):
        indicators.append(f"SQL拼接模式匹配: {pattern}")

# 2. 检查 execute() 直接执行用户输入
dangerous_patterns = [
    r'cursor\.execute\\s*\\(\\s*[^,)]*\\+',
    r'cursor\.execute\\s*\\(\\s*f["\']',
    r'\.execute\\s*\\(\\s*.*%\\s*',
    r'\.executemany\\s*\\(\\s*.*\\+',
]

for pattern in dangerous_patterns:
    if re.search(pattern, target_code, re.IGNORECASE):
        indicators.append(f"危险execute模式: {pattern}")

# 3. 模拟注入测试
test_payloads = [
    "' OR '1'='1",
    "'; DROP TABLE users; --",
    "' UNION SELECT * FROM sqlite_master --",
    "1 OR 1=1",
]

injection_simulated = False
for payload in test_payloads:
    # 检查代码中是否有将用户输入直接传入 SQL 的位置
    if re.search(r'(request\\.args|request\\.form|input\\s*\\(|sys\\.argv|params\\[)', target_code):
        injection_simulated = True
        indicators.append(f"发现用户输入流向 SQL 执行点，payload '{payload}' 可能生效")
        break

# 4. 检查是否使用参数化查询（安全措施）
parametrized = re.search(r'execute\\s*\\(\\s*["\'].*["\']\\s*,\\s*\\(', target_code)
if not parametrized:
    indicators.append("未检测到参数化查询的使用")

result = {
    "vuln_type": "sql_injection",
    "indicators": indicators,
    "injection_simulated": injection_simulated,
    "severity": "high" if len(indicators) >= 3 else "medium",
    "confidence": min(0.95, 0.5 + len(indicators) * 0.1),
    "cwe": "CWE-89"
}

print(json.dumps(result, indent=2, ensure_ascii=False))
'''

    SQLI_JAVASCRIPT = '''
/**
 * SQL Injection PoC - JavaScript
 * Target: {{target_file}}
 */
const fs = require('fs');

// 读取目标代码
const targetCode = fs.readFileSync("{{target_file}}", "utf-8");

// 检测 SQL 注入特征
const indicators = [];

// 1. 检查字符串拼接构建 SQL
const sqlPatterns = [
    /["']\\s*SELECT\\s+.*\\s+FROM\\s+.*["']\\s*\\+/i,
    /["']\\s*INSERT\\s+INTO\\s+.*["']\\s*\\+/i,
    /["']\\s*UPDATE\\s+.*\\s+SET\\s+.*["']\\s*\\+/i,
    /["']\\s*DELETE\\s+FROM\\s+.*["']\\s*\\+/i,
    /`.*SELECT\\s+.*\\$\\{.*\\}.*`/i,
    /query\\s*\\+\\s*/i,
    /\\+\\s*["'].*SELECT/i,
];

sqlPatterns.forEach(pattern => {
    if (pattern.test(targetCode)) {
        indicators.push(`SQL拼接模式匹配: ${pattern.source}`);
    }
});

// 2. 检查 query()/execute() 直接执行拼接 SQL
const dangerousPatterns = [
    /\\.query\\s*\\(\\s*[^,)]*\\+/i,
    /\\.query\\s*\\(\\s*`/i,
    /\\.execute\\s*\\(\\s*.*\\$\\{/i,
    /sequelize\\.query\\s*\\(\\s*.*\\+/i,
];

dangerousPatterns.forEach(pattern => {
    if (pattern.test(targetCode)) {
        indicators.push(`危险查询模式: ${pattern.source}`);
    }
});

// 3. 检查用户输入来源
const userInputPatterns = [
    /req\\.body/i,
    /req\\.query/i,
    /req\\.params/i,
    /process\\.argv/i,
    /prompt\\s*\\(/i,
];

let userInputFound = false;
userInputPatterns.forEach(pattern => {
    if (pattern.test(targetCode)) {
        userInputFound = true;
        indicators.push(`发现用户输入来源: ${pattern.source}`);
    }
});

// 4. 检查参数化查询
const parametrized = /query\\s*\\(\\s*["'].*["']\\s*,\\s*\\[/.test(targetCode);
if (!parametrized) {
    indicators.push("未检测到参数化查询的使用");
}

const result = {
    vuln_type: "sql_injection",
    indicators: indicators,
    injection_simulated: userInputFound && indicators.length >= 2,
    severity: indicators.length >= 3 ? "high" : "medium",
    confidence: Math.min(0.95, 0.5 + indicators.length * 0.1),
    cwe: "CWE-89"
};

console.log(JSON.stringify(result, null, 2));
'''

    # 命令注入 PoC 模板
    CMDI_PYTHON = '''
"""
Command Injection PoC - Python
Target: {{target_file}}
"""
import sys
import json
import re

# 读取目标代码
with open(r"{{target_file}}", "r", encoding="utf-8") as f:
    target_code = f.read()

indicators = []

# 1. 检查危险函数调用
dangerous_functions = [
    (r'os\\.system\\s*\\(', "os.system() 调用"),
    (r'os\\.popen\\s*\\(', "os.popen() 调用"),
    (r'subprocess\\.call\\s*\\([^)]*shell\\s*=\\s*True', "subprocess.call(shell=True)"),
    (r'subprocess\\.run\\s*\\([^)]*shell\\s*=\\s*True', "subprocess.run(shell=True)"),
    (r'subprocess\\.Popen\\s*\\([^)]*shell\\s*=\\s*True', "subprocess.Popen(shell=True)"),
    (r'eval\\s*\\(', "eval() 调用"),
    (r'exec\\s*\\(', "exec() 调用"),
]

for pattern, desc in dangerous_functions:
    if re.search(pattern, target_code):
        indicators.append(f"危险函数: {desc}")

# 2. 检查用户输入与危险函数的组合
user_input_flow = False
input_patterns = [
    r'(request\\.args|request\\.form|input\\s*\\(|sys\\.argv)',
    r'os\\.system\\s*\\(.*(?:request|input|argv|params)',
    r'subprocess\\..*\\(.*(?:request|input|argv|params)',
]

for pattern in input_patterns:
    if re.search(pattern, target_code, re.IGNORECASE):
        user_input_flow = True
        indicators.append("用户输入可能流向危险函数")
        break

# 3. 检查命令拼接
command_concat = [
    r'["\'].*(?:ls|cat|ping|curl|wget|rm|chmod).*["\']\\s*\\+',
    r'f["\'].*(?:ls|cat|ping|curl|wget|rm|chmod).*\\{.*\\}',
    r'\\.format\\s*\\(.*(?:ls|cat|ping|curl|wget)',
]

for pattern in command_concat:
    if re.search(pattern, target_code, re.IGNORECASE):
        indicators.append("命令字符串拼接 detected")
        break

result = {
    "vuln_type": "command_injection",
    "indicators": indicators,
    "command_injection_risk": user_input_flow and len(indicators) >= 2,
    "severity": "critical" if user_input_flow else "high",
    "confidence": min(0.95, 0.5 + len(indicators) * 0.12),
    "cwe": "CWE-78"
}

print(json.dumps(result, indent=2, ensure_ascii=False))
'''

    CMDI_JAVASCRIPT = '''
/**
 * Command Injection PoC - JavaScript
 * Target: {{target_file}}
 */
const fs = require('fs');

const targetCode = fs.readFileSync("{{target_file}}", "utf-8");
const indicators = [];

// 1. 检查危险函数调用
const dangerousPatterns = [
    /child_process\.exec\s*\(/i,
    /child_process\.execSync\s*\(/i,
    /child_process\.spawn\s*\([^)]*shell\s*:\s*true/i,
    /eval\s*\(/i,
    /new\s+Function\s*\(/i,
    /setTimeout\s*\(\s*["'][^"']+["']/i,
    /setInterval\s*\(\s*["'][^"']+["']/i,
];

dangerousPatterns.forEach(pattern => {
    if (pattern.test(targetCode)) {
        indicators.push(`危险函数调用: ${pattern.source}`);
    }
});

// 2. 检查用户输入流向
const userInputPatterns = [
    /req\.body/i,
    /req\.query/i,
    /req\.params/i,
    /process\.argv/i,
];

let userInputFound = false;
userInputPatterns.forEach(pattern => {
    if (pattern.test(targetCode)) {
        userInputFound = true;
    }
});

// 3. 检查命令拼接
const concatPatterns = [
    /["'].*(?:ls|cat|ping|curl|wget|rm|chmod).*["']\s*\+/i,
    /`.*(?:ls|cat|ping|curl|wget|rm|chmod).*\$\{/i,
];

concatPatterns.forEach(pattern => {
    if (pattern.test(targetCode)) {
        indicators.push("命令字符串拼接 detected");
    }
});

const result = {
    vuln_type: "command_injection",
    indicators: indicators,
    command_injection_risk: userInputFound && indicators.length >= 2,
    severity: userInputFound ? "critical" : "high",
    confidence: Math.min(0.95, 0.5 + indicators.length * 0.12),
    cwe: "CWE-78"
};

console.log(JSON.stringify(result, null, 2));
'''

    # XSS PoC 模板
    XSS_PYTHON = '''
"""
XSS PoC - Python
Target: {{target_file}}
"""
import json
import re

with open(r"{{target_file}}", "r", encoding="utf-8") as f:
    target_code = f.read()

indicators = []

# 1. 检查直接输出用户输入到响应
xss_patterns = [
    (r'return\\s+.*(?:request|input|params|form)', "直接返回用户输入"),
    (r'render_template_string\\s*\\(', "render_template_string 使用"),
    (r'Markup\\s*\\(', "Markup() 包装未过滤输入"),
    (r'response\\.write\\s*\\(.*(?:request|input)', "response.write 用户输入"),
    (r'HttpResponse\\s*\\(.*(?:request|input|params)', "HttpResponse 包含用户输入"),
]

for pattern, desc in xss_patterns:
    if re.search(pattern, target_code, re.IGNORECASE):
        indicators.append(desc)

# 2. 检查 HTML 上下文输出
html_context = [
    r'<.*>.*(?:request|input|params|form).*</.*>',
    r'["\']<script>.*["\']\\s*\\+',
    r'innerHTML\\s*=',
    r'document\\.write\\s*\\(',
]

for pattern in html_context:
    if re.search(pattern, target_code, re.IGNORECASE):
        indicators.append("HTML 上下文输出 detected")
        break

# 3. 检查缺少转义
if not re.search(r'escape|bleach|sanitize|htmlspecialchars|mark_safe', target_code, re.IGNORECASE):
    indicators.append("未检测到输出转义/消毒措施")

# 4. 常见 XSS payload 测试
xss_payloads = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "javascript:alert(1)",
    "<svg onload=alert(1)>",
]

result = {
    "vuln_type": "xss",
    "indicators": indicators,
    "xss_vectors": xss_payloads,
    "severity": "high" if len(indicators) >= 3 else "medium",
    "confidence": min(0.9, 0.5 + len(indicators) * 0.1),
    "cwe": "CWE-79"
}

print(json.dumps(result, indent=2, ensure_ascii=False))
'''

    XSS_JAVASCRIPT = '''
/**
 * XSS PoC - JavaScript
 * Target: {{target_file}}
 */
const fs = require('fs');

const targetCode = fs.readFileSync("{{target_file}}", "utf-8");
const indicators = [];

// 1. 检查直接输出用户输入
const xssPatterns = [
    /res\.send\s*\(\s*.*(?:req\.body|req\.query|req\.params)/i,
    /res\.render\s*\([^,)]*,\s*\{[^}]*(?:req|input)/i,
    /innerHTML\s*=/i,
    /document\.write\s*\(/i,
    /eval\s*\(\s*.*(?:req|input|params)/i,
];

xssPatterns.forEach(pattern => {
    if (pattern.test(targetCode)) {
        indicators.push(`XSS 输出模式: ${pattern.source}`);
    }
});

// 2. 检查模板引擎未转义
const templatePatterns = [
    /\{\{\{.*\}\}\}/,
    /<%.*-.*%>/,
    /!=\s*.*(?:req|input)/,
];

templatePatterns.forEach(pattern => {
    if (pattern.test(targetCode)) {
        indicators.push("模板引擎未转义输出 detected");
    }
});

// 3. 检查缺少转义
const hasSanitization = /escape|sanitize|DOMPurify|he\.encode|htmlspecialchars/.test(targetCode);
if (!hasSanitization) {
    indicators.push("未检测到输出转义/消毒措施");
}

const xssPayloads = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "javascript:alert(1)",
    "<svg onload=alert(1)>",
];

const result = {
    vuln_type: "xss",
    indicators: indicators,
    xss_vectors: xssPayloads,
    severity: indicators.length >= 3 ? "high" : "medium",
    confidence: Math.min(0.9, 0.5 + indicators.length * 0.1),
    cwe: "CWE-79"
};

console.log(JSON.stringify(result, null, 2));
'''

    # 路径遍历 PoC 模板
    PATH_TRAVERSAL_PYTHON = '''
"""
Path Traversal PoC - Python
Target: {{target_file}}
"""
import json
import re

with open(r"{{target_file}}", "r", encoding="utf-8") as f:
    target_code = f.read()

indicators = []

# 1. 检查文件操作函数
file_ops = [
    (r'open\\s*\\(.*(?:request|input|params|argv)', "open() 使用用户输入"),
    (r'os\\.path\\.join\\s*\\(.*(?:request|input)', "os.path.join 使用用户输入"),
    (r'send_from_directory\\s*\\(.*(?:request|input)', "send_from_directory 使用用户输入"),
    (r'FileResponse\\s*\\(.*(?:request|input)', "FileResponse 使用用户输入"),
]

for pattern, desc in file_ops:
    if re.search(pattern, target_code, re.IGNORECASE):
        indicators.append(desc)

# 2. 检查路径拼接
path_concat = [
    r'["\'].*(?:/|\\\\).*["\']\\s*\\+.*(?:request|input)',
    r'(?:request|input).*\\+\\s*["\'].*(?:/|\\\\)',
]

for pattern in path_concat:
    if re.search(pattern, target_code, re.IGNORECASE):
        indicators.append("路径拼接 detected")
        break

# 3. 检查路径验证缺失
if not re.search(r'realpath|abspath|normpath|resolve|is_safe_path', target_code, re.IGNORECASE):
    indicators.append("未检测到路径验证/规范化")

# 4. 测试 payload
traversal_payloads = [
    "../../../etc/passwd",
    "..\\\\..\\\\..\\\\windows\\\\system32\\\\drivers\\\\etc\\\\hosts",
    "....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
]

result = {
    "vuln_type": "path_traversal",
    "indicators": indicators,
    "traversal_payloads": traversal_payloads,
    "severity": "high" if len(indicators) >= 2 else "medium",
    "confidence": min(0.9, 0.5 + len(indicators) * 0.15),
    "cwe": "CWE-22"
}

print(json.dumps(result, indent=2, ensure_ascii=False))
'''

    PATH_TRAVERSAL_JAVASCRIPT = '''
/**
 * Path Traversal PoC - JavaScript
 * Target: {{target_file}}
 */
const fs = require('fs');

const targetCode = fs.readFileSync("{{target_file}}", "utf-8");
const indicators = [];

// 1. 检查文件操作函数
const fileOps = [
    /fs\.readFile\s*\(\s*.*(?:req\.body|req\.query|req\.params)/i,
    /fs\.readFileSync\s*\(\s*.*(?:req|input|params)/i,
    /res\.sendFile\s*\(\s*.*(?:req|input|params)/i,
    /path\.join\s*\(\s*.*(?:req|input|params)/i,
];

fileOps.forEach(pattern => {
    if (pattern.test(targetCode)) {
        indicators.push(`文件操作使用用户输入: ${pattern.source}`);
    }
});

// 2. 检查路径拼接
const concatPatterns = [
    /["'].*(?:\/|\\)["']\s*\+.*(?:req|input)/i,
    /`.*\$\{.*(?:req|input).*\}.*`/i,
];

concatPatterns.forEach(pattern => {
    if (pattern.test(targetCode)) {
        indicators.push("路径拼接 detected");
    }
});

// 3. 检查路径验证
const hasValidation = /resolve|normalize|path\.resolve|isPathInside|path-is-inside/.test(targetCode);
if (!hasValidation) {
    indicators.push("未检测到路径验证/规范化");
}

const traversalPayloads = [
    "../../../etc/passwd",
    "..\\\\..\\\\..\\\\windows\\\\system32\\\\drivers\\\\etc\\\\hosts",
    "....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
];

const result = {
    vuln_type: "path_traversal",
    indicators: indicators,
    traversal_payloads: traversalPayloads,
    severity: indicators.length >= 2 ? "high" : "medium",
    confidence: Math.min(0.9, 0.5 + indicators.length * 0.15),
    cwe: "CWE-22"
};

console.log(JSON.stringify(result, null, 2));
'''

    # SSRF PoC 模板
    SSRF_PYTHON = '''
"""
SSRF PoC - Python
Target: {{target_file}}
"""
import json
import re

with open(r"{{target_file}}", "r", encoding="utf-8") as f:
    target_code = f.read()

indicators = []

# 1. 检查网络请求函数
network_ops = [
    (r'requests\\.(get|post|put|delete|head|patch)\\s*\\(.*(?:request|input|params)', "requests 使用用户输入 URL"),
    (r'urllib\\.request\\.urlopen\\s*\\(.*(?:request|input)', "urllib 使用用户输入"),
    (r'http\\.client\\..*\\s*\\(.*(?:request|input)', "http.client 使用用户输入"),
    (r'urlopen\\s*\\(.*(?:request|input)', "urlopen 使用用户输入"),
]

for pattern, desc in network_ops:
    if re.search(pattern, target_code, re.IGNORECASE):
        indicators.append(desc)

# 2. 检查 URL 拼接
url_concat = [
    r'["\']https?://["\']\\s*\\+.*(?:request|input)',
    r'f["\']https?://.*\\{.*(?:request|input).*\\}',
    r'["\']https?://.*(?:request|input|params|argv)',
]

for pattern in url_concat:
    if re.search(pattern, target_code, re.IGNORECASE):
        indicators.append("URL 拼接使用用户输入")
        break

# 3. 检查 URL 验证缺失
if not re.search(r'urlparse|urlsplit|validators|allowlist|whitelist', target_code, re.IGNORECASE):
    indicators.append("未检测到 URL 验证/白名单")

# 4. SSRF 测试 payload
ssrf_payloads = [
    "http://169.254.169.254/latest/meta-data/",
    "http://localhost:22/",
    "http://127.0.0.1:8080/",
    "file:///etc/passwd",
    "dict://localhost:11211/",
    "gopher://localhost:9000/",
]

result = {
    "vuln_type": "ssrf",
    "indicators": indicators,
    "ssrf_payloads": ssrf_payloads,
    "severity": "high" if len(indicators) >= 2 else "medium",
    "confidence": min(0.9, 0.5 + len(indicators) * 0.15),
    "cwe": "CWE-918"
}

print(json.dumps(result, indent=2, ensure_ascii=False))
'''

    SSRF_JAVASCRIPT = '''
/**
 * SSRF PoC - JavaScript
 * Target: {{target_file}}
 */
const fs = require('fs');

const targetCode = fs.readFileSync("{{target_file}}", "utf-8");
const indicators = [];

// 1. 检查网络请求函数
const networkOps = [
    /fetch\s*\(\s*.*(?:req\.body|req\.query|req\.params)/i,
    /axios\.(get|post|put|delete)\s*\(\s*.*(?:req|input|params)/i,
    /request\s*\(\s*.*(?:req|input|params)/i,
    /http\.get\s*\(\s*.*(?:req|input|params)/i,
    /https\.get\s*\(\s*.*(?:req|input|params)/i,
];

networkOps.forEach(pattern => {
    if (pattern.test(targetCode)) {
        indicators.push(`网络请求使用用户输入: ${pattern.source}`);
    }
});

// 2. 检查 URL 拼接
const urlPatterns = [
    /["']https?:\/\/["']\s*\+.*(?:req|input)/i,
    /`https?:\/\/.*\$\{.*(?:req|input).*\}`/i,
];

urlPatterns.forEach(pattern => {
    if (pattern.test(targetCode)) {
        indicators.push("URL 拼接使用用户输入");
    }
});

// 3. 检查 URL 验证
const hasValidation = /URL|url|parse|validate|allowlist|whitelist/.test(targetCode);
if (!hasValidation) {
    indicators.push("未检测到 URL 验证/白名单");
}

const ssrfPayloads = [
    "http://169.254.169.254/latest/meta-data/",
    "http://localhost:22/",
    "http://127.0.0.1:8080/",
    "file:///etc/passwd",
    "dict://localhost:11211/",
    "gopher://localhost:9000/",
];

const result = {
    vuln_type: "ssrf",
    indicators: indicators,
    ssrf_payloads: ssrfPayloads,
    severity: indicators.length >= 2 ? "high" : "medium",
    confidence: Math.min(0.9, 0.5 + indicators.length * 0.15),
    cwe: "CWE-918"
};

console.log(JSON.stringify(result, null, 2));
'''

    # 硬编码凭证 PoC 模板
    HARDCODED_PYTHON = '''
"""
Hardcoded Credentials PoC - Python
Target: {{target_file}}
"""
import json
import re
import math
from collections import Counter

with open(r"{{target_file}}", "r", encoding="utf-8") as f:
    target_code = f.read()

indicators = []
credentials_found = []

# 1. 检查密码/密钥/令牌模式
secret_patterns = [
    (r'password\\s*=\\s*["\'][^"\']{4,}["\']', "password 赋值"),
    (r'secret\\s*=\\s*["\'][^"\']{4,}["\']', "secret 赋值"),
    (r'api_key\\s*=\\s*["\'][^"\']{8,}["\']', "api_key 赋值"),
    (r'token\\s*=\\s*["\'][^"\']{8,}["\']', "token 赋值"),
    (r'aws_access_key_id\\s*=\\s*["\'][^"\']{10,}["\']', "AWS Access Key"),
    (r'aws_secret_access_key\\s*=\\s*["\'][^"\']{10,}["\']', "AWS Secret Key"),
    (r'private_key\\s*=\\s*["\'][^"\']{20,}["\']', "Private Key"),
    (r'BEGIN\\s+(RSA|DSA|EC|OPENSSH)\\s+PRIVATE\\s+KEY', "PEM Private Key"),
    (r'Bearer\\s+[a-zA-Z0-9_\\-\\.]{20,}', "Bearer Token"),
    (r'AKIA[0-9A-Z]{16}', "AWS Access Key ID 格式"),
]

for pattern, desc in secret_patterns:
    matches = re.findall(pattern, target_code, re.IGNORECASE)
    for match in matches:
        credentials_found.append({
            "type": desc,
            "match": match if isinstance(match, str) else match[0],
            "context": target_code[max(0, target_code.find(match if isinstance(match, str) else match[0]) - 50):
                                  min(len(target_code), target_code.find(match if isinstance(match, str) else match[0]) + len(match if isinstance(match, str) else match[0]) + 50)]
        })
        indicators.append(desc)

# 2. 计算熵值检测高熵字符串
def shannon_entropy(data):
    if not data:
        return 0
    entropy = 0
    for x in Counter(data).values():
        p_x = x / len(data)
        entropy -= p_x * math.log2(p_x)
    return entropy

# 查找高熵字符串（可能是密钥）
high_entropy_strings = []
for match in re.finditer(r'["\']([a-zA-Z0-9+/=]{20,})["\']', target_code):
    s = match.group(1)
    entropy = shannon_entropy(s)
    if entropy > 4.5:
        high_entropy_strings.append({
            "string": s[:20] + "...",
            "entropy": round(entropy, 2)
        })

if high_entropy_strings:
    indicators.append(f"发现 {len(high_entropy_strings)} 个高熵字符串（可能是密钥）")

# 3. 检查是否在配置文件/常量中
if re.search(r'config|settings|constants|env|\.cfg|\.ini', target_code, re.IGNORECASE):
    indicators.append("代码位于配置/常量区域")

result = {
    "vuln_type": "hardcoded_credentials",
    "indicators": list(set(indicators)),
    "credentials_found": credentials_found[:10],  # 限制数量
    "high_entropy_strings": high_entropy_strings[:5],
    "severity": "critical" if len(credentials_found) >= 2 else "high",
    "confidence": min(0.95, 0.6 + len(credentials_found) * 0.1 + len(high_entropy_strings) * 0.05),
    "cwe": "CWE-798"
}

print(json.dumps(result, indent=2, ensure_ascii=False))
'''

    HARDCODED_JAVASCRIPT = '''
/**
 * Hardcoded Credentials PoC - JavaScript
 * Target: {{target_file}}
 */
const fs = require('fs');

const targetCode = fs.readFileSync("{{target_file}}", "utf-8");
const indicators = [];
const credentialsFound = [];

// 1. 检查密码/密钥/令牌模式
const secretPatterns = [
    { pattern: /password\s*=\s*["'][^"']{4,}["']/gi, desc: "password 赋值" },
    { pattern: /secret\s*=\s*["'][^"']{4,}["']/gi, desc: "secret 赋值" },
    { pattern: /api_key\s*=\s*["'][^"']{8,}["']/gi, desc: "api_key 赋值" },
    { pattern: /token\s*=\s*["'][^"']{8,}["']/gi, desc: "token 赋值" },
    { pattern: /aws_access_key_id\s*=\s*["'][^"']{10,}["']/gi, desc: "AWS Access Key" },
    { pattern: /aws_secret_access_key\s*=\s*["'][^"']{10,}["']/gi, desc: "AWS Secret Key" },
    { pattern: /private_key\s*=\s*["'][^"']{20,}["']/gi, desc: "Private Key" },
    { pattern: /BEGIN\s+(RSA|DSA|EC|OPENSSH)\s+PRIVATE\s+KEY/gi, desc: "PEM Private Key" },
    { pattern: /Bearer\s+[a-zA-Z0-9_\-\.]{20,}/gi, desc: "Bearer Token" },
    { pattern: /AKIA[0-9A-Z]{16}/g, desc: "AWS Access Key ID 格式" },
];

secretPatterns.forEach(({ pattern, desc }) => {
    const matches = targetCode.match(pattern);
    if (matches) {
        matches.forEach(match => {
            const idx = targetCode.indexOf(match);
            credentialsFound.push({
                type: desc,
                match: match.substring(0, 50),
                context: targetCode.substring(Math.max(0, idx - 50), Math.min(targetCode.length, idx + match.length + 50))
            });
        });
        indicators.push(desc);
    }
});

// 2. 计算熵值
function shannonEntropy(data) {
    const len = data.length;
    const counts = {};
    for (const char of data) {
        counts[char] = (counts[char] || 0) + 1;
    }
    let entropy = 0;
    for (const count of Object.values(counts)) {
        const p = count / len;
        entropy -= p * Math.log2(p);
    }
    return entropy;
}

const highEntropyStrings = [];
const entropyRegex = /["']([a-zA-Z0-9+/=]{20,})["']/g;
let m;
while ((m = entropyRegex.exec(targetCode)) !== null) {
    const s = m[1];
    const entropy = shannonEntropy(s);
    if (entropy > 4.5) {
        highEntropyStrings.push({
            string: s.substring(0, 20) + "...",
            entropy: parseFloat(entropy.toFixed(2))
        });
    }
}

if (highEntropyStrings.length > 0) {
    indicators.push(`发现 ${highEntropyStrings.length} 个高熵字符串（可能是密钥）`);
}

// 3. 检查配置区域
if (/config|settings|constants|env|\.cfg|\.ini/i.test(targetCode)) {
    indicators.push("代码位于配置/常量区域");
}

const result = {
    vuln_type: "hardcoded_credentials",
    indicators: [...new Set(indicators)],
    credentials_found: credentialsFound.slice(0, 10),
    high_entropy_strings: highEntropyStrings.slice(0, 5),
    severity: credentialsFound.length >= 2 ? "critical" : "high",
    confidence: Math.min(0.95, 0.6 + credentialsFound.length * 0.1 + highEntropyStrings.length * 0.05),
    cwe: "CWE-798"
};

console.log(JSON.stringify(result, null, 2));
'''

    def __init__(self):
        """初始化模板库"""
        self._templates: Dict[str, PoCTemplate] = {}
        self._register_templates()

    def _register_templates(self):
        """注册所有内置模板"""
        templates_data = [
            (VulnType.SQL_INJECTION, Language.PYTHON, "SQL Injection (Python)",
             "检测 Python 代码中的 SQL 注入漏洞", self.SQLI_PYTHON, ["SQL拼接", "危险execute", "未参数化"], "high", "CWE-89"),
            (VulnType.SQL_INJECTION, Language.JAVASCRIPT, "SQL Injection (JavaScript)",
             "检测 JavaScript 代码中的 SQL 注入漏洞", self.SQLI_JAVASCRIPT, ["SQL拼接", "危险query", "未参数化"], "high", "CWE-89"),
            (VulnType.COMMAND_INJECTION, Language.PYTHON, "Command Injection (Python)",
             "检测 Python 代码中的命令注入漏洞", self.CMDI_PYTHON, ["os.system", "shell=True", "命令拼接"], "critical", "CWE-78"),
            (VulnType.COMMAND_INJECTION, Language.JAVASCRIPT, "Command Injection (JavaScript)",
             "检测 JavaScript 代码中的命令注入漏洞", self.CMDI_JAVASCRIPT, ["child_process.exec", "eval", "命令拼接"], "critical", "CWE-78"),
            (VulnType.XSS, Language.PYTHON, "XSS (Python)",
             "检测 Python 代码中的 XSS 漏洞", self.XSS_PYTHON, ["直接输出", "innerHTML", "未转义"], "high", "CWE-79"),
            (VulnType.XSS, Language.JAVASCRIPT, "XSS (JavaScript)",
             "检测 JavaScript 代码中的 XSS 漏洞", self.XSS_JAVASCRIPT, ["直接输出", "模板未转义", "未消毒"], "high", "CWE-79"),
            (VulnType.PATH_TRAVERSAL, Language.PYTHON, "Path Traversal (Python)",
             "检测 Python 代码中的路径遍历漏洞", self.PATH_TRAVERSAL_PYTHON, ["open用户输入", "路径拼接", "未验证"], "high", "CWE-22"),
            (VulnType.PATH_TRAVERSAL, Language.JAVASCRIPT, "Path Traversal (JavaScript)",
             "检测 JavaScript 代码中的路径遍历漏洞", self.PATH_TRAVERSAL_JAVASCRIPT, ["fs.readFile用户输入", "路径拼接", "未验证"], "high", "CWE-22"),
            (VulnType.SSRF, Language.PYTHON, "SSRF (Python)",
             "检测 Python 代码中的 SSRF 漏洞", self.SSRF_PYTHON, ["requests用户URL", "URL拼接", "未验证"], "high", "CWE-918"),
            (VulnType.SSRF, Language.JAVASCRIPT, "SSRF (JavaScript)",
             "检测 JavaScript 代码中的 SSRF 漏洞", self.SSRF_JAVASCRIPT, ["fetch用户URL", "URL拼接", "未验证"], "high", "CWE-918"),
            (VulnType.HARDCODED_CREDENTIALS, Language.PYTHON, "Hardcoded Credentials (Python)",
             "检测 Python 代码中的硬编码凭证", self.HARDCODED_PYTHON, ["password赋值", "高熵字符串", "密钥"], "critical", "CWE-798"),
            (VulnType.HARDCODED_CREDENTIALS, Language.JAVASCRIPT, "Hardcoded Credentials (JavaScript)",
             "检测 JavaScript 代码中的硬编码凭证", self.HARDCODED_JAVASCRIPT, ["password赋值", "高熵字符串", "密钥"], "critical", "CWE-798"),
        ]

        for vuln_type, language, name, description, template, indicators, severity, cwe in templates_data:
            key = self._make_key(vuln_type, language)
            self._templates[key] = PoCTemplate(
                vuln_type=vuln_type,
                language=language,
                name=name,
                description=description,
                template=template,
                expected_indicators=indicators,
                severity=severity,
                cwe=cwe
            )

    @staticmethod
    def _make_key(vuln_type: VulnType, language: Language) -> str:
        """生成模板键"""
        return f"{vuln_type.value}:{language.value}"

    def get_template(
        self,
        vuln_type: VulnType | str,
        language: Language | str = Language.PYTHON
    ) -> Optional[PoCTemplate]:
        """
        获取指定漏洞类型和语言的模板

        Args:
            vuln_type: 漏洞类型
            language: 编程语言

        Returns:
            PoCTemplate 或 None
        """
        if isinstance(vuln_type, str):
            vuln_type = VulnType(vuln_type)
        if isinstance(language, str):
            language = Language(language)

        key = self._make_key(vuln_type, language)
        return self._templates.get(key)

    def render_template(
        self,
        vuln_type: VulnType | str,
        language: Language | str,
        target_file: str,
        extra_vars: Optional[Dict[str, Any]] = None
    ) -> Optional[str]:
        """
        渲染模板，替换占位符

        Args:
            vuln_type: 漏洞类型
            language: 编程语言
            target_file: 目标文件路径
            extra_vars: 额外变量

        Returns:
            渲染后的 PoC 代码
        """
        template = self.get_template(vuln_type, language)
        if not template:
            logger.warning(f"Template not found for {vuln_type}:{language}")
            return None

        code = template.template.replace("{{target_file}}", target_file)

        if extra_vars:
            for key, value in extra_vars.items():
                code = code.replace(f"{{{{{key}}}}}", str(value))

        return code

    def list_templates(self) -> List[Dict[str, str]]:
        """列出所有可用模板"""
        return [
            {
                "vuln_type": t.vuln_type.value,
                "language": t.language.value,
                "name": t.name,
                "description": t.description,
                "severity": t.severity,
                "cwe": t.cwe
            }
            for t in self._templates.values()
        ]

    def get_supported_vuln_types(self) -> List[str]:
        """获取支持的漏洞类型列表"""
        return [vt.value for vt in VulnType]

    def get_supported_languages(self) -> List[str]:
        """获取支持的语言列表"""
        return [lang.value for lang in Language]


# 全局模板库实例
_template_library: Optional[PoCTemplateLibrary] = None


def get_template_library() -> PoCTemplateLibrary:
    """获取全局模板库实例"""
    global _template_library
    if _template_library is None:
        _template_library = PoCTemplateLibrary()
    return _template_library
