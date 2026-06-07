from __future__ import annotations

import json
from typing import Any

from llm.exceptions import LLMResponseFormatError

# 知识图谱分析响应键
ANALYSIS_RESPONSE_KEYS = ("analysis", "impact_description", "mitigation_recommendation")


def validate_analysis_response(data: dict[str, Any]) -> dict[str, str]:
    """验证漏洞分析响应格式（非补丁生成）。"""
    if not isinstance(data, dict):
        raise LLMResponseFormatError("LLM analysis response must be a JSON object.")

    validated: dict[str, str] = {}
    for key in ANALYSIS_RESPONSE_KEYS:
        value = data.get(key)
        if value is not None and not isinstance(value, str):
            raise LLMResponseFormatError(
                f"LLM analysis response field {key} must be a string."
            )
        validated[key] = str(value) if value is not None else ""
    return validated


def parse_analysis_json(content: str) -> dict[str, str]:
    """解析漏洞分析 JSON 响应。"""
    try:
        data = json.loads(content)
    except json.JSONDecodeError as exc:
        raise LLMResponseFormatError("LLM analysis response is not valid JSON.") from exc
    return validate_analysis_response(data)
