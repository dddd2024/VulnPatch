"""
Prompt templates for vulnerability analysis.

Provides structured prompts for different stages of the audit pipeline:
- Vulnerability explanation
- Attack surface identification
- Evidence chain summary
- Judge decision
"""

from typing import Any


# =============================================================================
# Vulnerability Explanation Prompts
# =============================================================================

def build_vulnerability_explanation_prompt(
    finding_type: str,
    file_path: str,
    line_number: int,
    code_snippet: str,
    cwe: str | None = None,
    evidence: dict[str, Any] | None = None,
    language: str = "zh",
) -> str:
    """
    Build prompt for vulnerability explanation.
    
    Args:
        finding_type: Vulnerability type (e.g., "SQL Injection")
        file_path: File path where vulnerability was found
        line_number: Line number
        code_snippet: Relevant code snippet
        cwe: CWE identifier (optional)
        evidence: Additional evidence (optional)
        language: Output language ("zh" or "en")
    
    Returns:
        Prompt string
    """
    if language == "zh":
        return f"""请分析以下漏洞并提供详细解释。

## 漏洞信息
- 类型: {finding_type}
- 文件: {file_path}
- 行号: {line_number}
- CWE: {cwe or "未知"}

## 相关代码
```
{code_snippet}
```

## 附加证据
{evidence or "无"}

请提供：
1. 漏洞成因分析
2. 攻击向量描述
3. 影响范围评估
4. 修复建议

输出格式要求：
- 使用 Markdown 格式
- 每个部分用标题分隔
- 语言简洁准确"""
    else:
        return f"""Analyze the following vulnerability and provide a detailed explanation.

## Vulnerability Information
- Type: {finding_type}
- File: {file_path}
- Line: {line_number}
- CWE: {cwe or "Unknown"}

## Relevant Code
```
{code_snippet}
```

## Additional Evidence
{evidence or "None"}

Please provide:
1. Root cause analysis
2. Attack vector description
3. Impact assessment
4. Remediation recommendations

Output format:
- Use Markdown format
- Separate sections with headers
- Be concise and accurate"""


# =============================================================================
# Attack Surface Identification Prompts
# =============================================================================

def build_attack_surface_prompt(
    code_content: str,
    file_path: str,
    language: str = "zh",
) -> str:
    """
    Build prompt for attack surface identification.
    
    Args:
        code_content: Full code content
        file_path: File path
        language: Output language
    
    Returns:
        Prompt string
    """
    if language == "zh":
        return f"""请分析以下代码并识别潜在攻击面。

## 文件信息
- 文件路径: {file_path}

## 代码内容
```
{code_content}
```

请识别以下攻击面类型：
1. Web 路由入口 (HTTP endpoints)
2. 用户输入接收点 (request parameters)
3. 文件操作点 (file read/write)
4. 数据库查询点 (SQL operations)
5. 命令执行点 (system commands)
6. 反序列化点 (deserialization)
7. 其他危险函数调用

输出格式：
- 每类攻击面列出具体位置（行号）
- 评估每个入口点的风险等级
- 标记需要重点关注的区域"""
    else:
        return f"""Analyze the following code and identify potential attack surfaces.

## File Information
- Path: {file_path}

## Code Content
```
{code_content}
```

Identify the following attack surface types:
1. Web route entry points (HTTP endpoints)
2. User input receivers (request parameters)
3. File operations (file read/write)
4. Database queries (SQL operations)
5. Command execution (system commands)
6. Deserialization points
7. Other dangerous function calls

Output format:
- List specific locations (line numbers) for each type
- Assess risk level for each entry point
- Mark areas requiring focused attention"""


# =============================================================================
# Evidence Chain Summary Prompts
# =============================================================================

def build_evidence_chain_prompt(
    finding_type: str,
    source_info: dict[str, Any] | None = None,
    sink_info: dict[str, Any] | None = None,
    propagation_path: list[dict[str, Any]] | None = None,
    language: str = "zh",
) -> str:
    """
    Build prompt for evidence chain summary.
    
    Args:
        finding_type: Vulnerability type
        source_info: Taint source information
        sink_info: Taint sink information
        propagation_path: Data flow path
        language: Output language
    
    Returns:
        Prompt string
    """
    source_str = str(source_info) if source_info else "未知"
    sink_str = str(sink_info) if sink_info else "未知"
    path_str = "\n".join(str(step) for step in propagation_path) if propagation_path else "无传播路径"
    
    if language == "zh":
        return f"""请总结以下漏洞的证据链。

## 漏洞类型
{finding_type}

## 污点源 (Source)
{source_str}

## 污点汇 (Sink)
{sink_str}

## 数据传播路径
{path_str}

请提供：
1. 数据流起点描述
2. 传播过程关键节点
3. 最终危险操作说明
4. 证据链完整性评估
5. 置信度评分依据

输出格式：
- 使用 Markdown 格式
- 清晰标注每个步骤
- 给出置信度等级（高/中/低）"""
    else:
        return f"""Summarize the evidence chain for the following vulnerability.

## Vulnerability Type
{finding_type}

## Taint Source
{source_str}

## Taint Sink
{sink_str}

## Data Propagation Path
{path_str}

Please provide:
1. Data flow origin description
2. Key propagation nodes
3. Final dangerous operation explanation
4. Evidence chain completeness assessment
5. Confidence scoring rationale

Output format:
- Use Markdown format
- Clearly mark each step
- Provide confidence level (high/medium/low)"""


# =============================================================================
# Judge Decision Prompts
# =============================================================================

def build_judge_decision_prompt(
    finding_type: str,
    hypothesis: str,
    reasoning_summary: str,
    evidence_summary: str,
    confidence: str,
    language: str = "zh",
) -> str:
    """
    Build prompt for judge decision.
    
    Args:
        finding_type: Vulnerability type
        hypothesis: Agent hypothesis
        reasoning_summary: Analysis reasoning
        evidence_summary: Evidence summary
        confidence: Initial confidence level
        language: Output language
    
    Returns:
        Prompt string
    """
    if language == "zh":
        return f"""请对以下漏洞假设进行裁决。

## 漏洞信息
- 类型: {finding_type}
- 初始置信度: {confidence}

## 分析假设
{hypothesis}

## 分析推理
{reasoning_summary}

## 证据摘要
{evidence_summary}

请做出裁决：
1. 裁决结果：确认 (confirmed) / 可疑 (suspicious) / 拒绝 (rejected)
2. 风险评分：0-100 分
3. 裁决理由：详细说明判断依据
4. 补充建议：如需进一步验证的事项

输出格式：
- 裁决结果必须明确
- 风险评分需有依据
- 使用 Markdown 格式"""
    else:
        return f"""Make a judgment on the following vulnerability hypothesis.

## Vulnerability Information
- Type: {finding_type}
- Initial Confidence: {confidence}

## Analysis Hypothesis
{hypothesis}

## Analysis Reasoning
{reasoning_summary}

## Evidence Summary
{evidence_summary}

Make a judgment:
1. Verdict: confirmed / suspicious / rejected
2. Risk Score: 0-100
3. Reason: Detailed explanation of judgment basis
4. Additional recommendations: Items requiring further verification

Output format:
- Verdict must be clear
- Risk score must have rationale
- Use Markdown format"""


# =============================================================================
# Combined Analysis Prompt
# =============================================================================

def build_full_analysis_prompt(
    finding_type: str,
    file_path: str,
    line_number: int,
    code_snippet: str,
    cwe: str | None = None,
    evidence: dict[str, Any] | None = None,
    language: str = "zh",
) -> str:
    """
    Build comprehensive analysis prompt combining all aspects.
    
    Args:
        finding_type: Vulnerability type
        file_path: File path
        line_number: Line number
        code_snippet: Code snippet
        cwe: CWE identifier
        evidence: Additional evidence
        language: Output language
    
    Returns:
        Comprehensive prompt string
    """
    if language == "zh":
        return f"""请对以下漏洞进行全面安全分析。

## 漏洞基本信息
- 类型: {finding_type}
- CWE: {cwe or "未知"}
- 文件: {file_path}
- 行号: {line_number}

## 相关代码片段
```
{code_snippet}
```

## 检测证据
{str(evidence) if evidence else "无"}

请提供以下分析内容：

### 1. 漏洞成因分析
分析漏洞产生的根本原因。

### 2. 攻击向量描述
描述攻击者如何利用此漏洞。

### 3. 影响范围评估
评估漏洞可能造成的安全影响。

### 4. 证据链分析
分析从攻击入口到漏洞触发的数据流。

### 5. 修复建议
提供具体的修复方案。

### 6. 裁决结论
- 裁决: 确认/可疑/拒绝
- 风险评分: 0-100
- 置信度: 高/中/低

输出要求：
- 使用 Markdown 格式
- 每个部分清晰分隔
- 内容准确、可执行"""
    else:
        return f"""Perform a comprehensive security analysis of the following vulnerability.

## Vulnerability Basic Information
- Type: {finding_type}
- CWE: {cwe or "Unknown"}
- File: {file_path}
- Line: {line_number}

## Relevant Code Snippet
```
{code_snippet}
```

## Detection Evidence
{str(evidence) if evidence else "None"}

Provide the following analysis:

### 1. Root Cause Analysis
Analyze the fundamental cause of the vulnerability.

### 2. Attack Vector Description
Describe how attackers can exploit this vulnerability.

### 3. Impact Assessment
Assess the potential security impact.

### 4. Evidence Chain Analysis
Analyze the data flow from attack entry to vulnerability trigger.

### 5. Remediation Recommendations
Provide specific remediation solutions.

### 6. Judgment Conclusion
- Verdict: confirmed/suspicious/rejected
- Risk Score: 0-100
- Confidence: high/medium/low

Output requirements:
- Use Markdown format
- Clearly separate each section
- Content must be accurate and actionable"""