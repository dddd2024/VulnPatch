"""
代码语言自动检测模块

基于代码内容和文件扩展名，自动识别编程语言。
支持：Python, JavaScript, TypeScript, Java, Go, PHP, C/C++, Rust
"""

from __future__ import annotations

import re


# 各语言的检测规则（按优先级排序）
# 每条规则: (正则表达式, 权重)
# 权重越高，匹配到该规则时该语言的得分越高

LANGUAGE_RULES: dict[str, list[tuple[str, int]]] = {
    "java": [
        (r"\bpublic\s+(static\s+)?(class|interface|enum)\b", 10),
        (r"\bpublic\s+static\s+void\s+main\s*\(", 10),
        (r"\bSystem\s*\.\s*out\s*\.\s*(print|println)\b", 8),
        (r"\bimport\s+java\s*\.\s*\w+", 8),
        (r"\bpackage\s+[\w.]+\s*;", 7),
        (r"@\b(RequestParam|PathVariable|RequestBody|GetMapping|PostMapping)\b", 10),
        (r"\b(HttpServletRequest|HttpServletResponse)\b", 8),
        (r"\bPreparedStatement\b", 6),
        (r"\bnew\s+(FileInputStream|FileOutputStream|BufferedReader)\b", 5),
        (r"\bDocumentBuilderFactory\b", 5),
    ],
    "python": [
        (r"^\s*def\s+\w+\s*\(", 8),
        (r"^\s*class\s+\w+", 7),
        (r"^\s*import\s+\w+", 6),
        (r"^\s*from\s+\w+\s+import", 7),
        (r"\bif\s+__name__\s*==\s*['\"]__main__['\"]", 10),
        (r"\bprint\s*\(", 5),
        (r"\bself\.\w+", 6),
        (r"\bNone\s*(==|!=)\s*None", 5),
        (r"#\s*.*", 2),  # 注释（权重低，因为很多语言都有）
        (r"@\w+\s*\n\s*def\s+", 7),  # 装饰器
        (r'"""\s*\n', 5),  # 三引号
        (r"\bflask\b", 6),
        (r"\brequests\.\w+", 5),
    ],
    "javascript": [
        (r"\bconst\s+\w+\s*=\s*(require\s*\(|[\[{])", 7),
        (r"\blet\s+\w+\s*=", 5),
        (r"\bvar\s+\w+\s*=", 5),
        (r"\bconsole\s*\.\s*log\b", 8),
        (r"\bmodule\s*\.\s*exports\b", 8),
        (r"\brequire\s*\(\s*['\"]", 7),
        (r"=>\s*\{", 6),
        (r"\bfunction\s*\w+\s*\(", 5),
        (r"\bdocument\s*\.\s*\w+", 4),
        (r"\bwindow\s*\.\s*\w+", 4),
        (r"\bapp\s*\.\s*(get|post|put|delete|use)\s*\(", 6),
        (r"\bexpress\s*\(\s*\)", 7),
        (r"\basync\s+function\b", 5),
        (r"\bawait\s+", 4),
    ],
    "typescript": [
        (r":\s*(string|number|boolean|void|any|never)\b", 8),
        (r"\binterface\s+\w+\s*\{", 8),
        (r"\btype\s+\w+\s*=", 7),
        (r"\benum\s+\w+\s*\{", 7),
        (r"\breadonly\s+\w+", 6),
        (r"<\w+>\s*\(", 5),
        (r"\bas\s+\w+\s*:", 5),
        (r"\bimport\s+.*\s+from\s+['\"]", 4),
        (r"\bnpm\s+install", 3),
    ],
    "go": [
        (r"\bpackage\s+main\b", 9),
        (r"\bfunc\s+\w+\s*\(", 7),
        (r"\bfmt\s*\.\s*(Println|Printf|Sprintf)\b", 8),
        (r"\bimport\s*\(\s*\"", 7),
        (r":=\s*", 6),
        (r"\bgo\s+func\b", 8),
        (r"\bchan\s+", 6),
        (r"\bdefer\s+", 5),
        (r"\berr\s*!=\s*nil", 5),
    ],
    "php": [
        (r"<\?php", 15),
        (r"\$\w+\s*=", 6),
        (r"\becho\s+", 5),
        (r"\bfunction\s+\w+\s*\(", 4),
        (r"->\w+", 5),
        (r"\bnamespace\s+", 7),
        (r"\buse\s+[\w\\]+", 5),
        (r"\b\$_(GET|POST|REQUEST|SESSION)\b", 10),
    ],
    "c": [
        (r"#include\s*<stdio\.h>", 10),
        (r"#include\s*<stdlib\.h>", 8),
        (r"\bprintf\s*\(", 7),
        (r"\bint\s+main\s*\(", 8),
        (r"\bmalloc\s*\(", 6),
        (r"\bvoid\s+\w+\s*\(", 5),
    ],
    "cpp": [
        (r"#include\s*<iostream>", 10),
        (r"\bstd\s*::\s*\w+", 8),
        (r"\bcout\s*<<", 8),
        (r"\bcin\s*>>", 8),
        (r"\bclass\s+\w+\s*(\{|:)", 5),
        (r"\btemplate\s*<", 7),
        (r"\bnamespace\s+", 6),
    ],
}

# 文件扩展名映射
EXTENSION_MAP: dict[str, str] = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".java": "java",
    ".go": "go",
    ".php": "php",
    ".c": "c",
    ".h": "c",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".cxx": "cpp",
    ".hpp": "cpp",
    ".rs": "rust",
}


def detect_language(code: str, filename: str | None = None) -> str:
    """
    自动检测代码语言

    Args:
        code: 代码内容
        filename: 可选的文件名（用于扩展名检测）

    Returns:
        语言标识符（如 "python", "javascript", "java" 等）
        默认返回 "python"
    """
    # 优先使用文件扩展名
    if filename:
        for ext, lang in EXTENSION_MAP.items():
            if filename.lower().endswith(ext):
                return lang

    # 基于代码内容评分
    scores: dict[str, float] = {}

    for lang, rules in LANGUAGE_RULES.items():
        score = 0.0
        for pattern, weight in rules:
            matches = re.findall(pattern, code, re.MULTILINE)
            score += weight * len(matches)
        if score > 0:
            scores[lang] = score

    if not scores:
        return "python"

    # TypeScript 需要特殊处理：如果匹配到 TS 特征，优先返回 TS
    # 否则如果同时匹配 JS 和 TS，优先 JS（因为 TS 包含 JS 子集）
    if "typescript" in scores and "javascript" in scores:
        # 如果有 TS 独有特征（interface, type, enum 等），判定为 TS
        ts_unique = sum(w for p, w in LANGUAGE_RULES["typescript"]
                        if re.search(p, code, re.MULTILINE))
        if ts_unique > 5:
            return "typescript"
        # 否则按分数比较
        if scores["typescript"] > scores["javascript"] * 1.3:
            return "typescript"
        del scores["typescript"]

    # C 和 C++ 需要特殊处理
    if "cpp" in scores and "c" in scores:
        if scores["cpp"] > scores["c"]:
            del scores["c"]
        else:
            del scores["cpp"]

    # 返回得分最高的语言
    return max(scores, key=scores.get)
