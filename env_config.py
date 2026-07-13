from __future__ import annotations

import os
from pathlib import Path
from typing import Any

try:
    from dotenv import load_dotenv
except Exception:  # pragma: no cover - optional runtime dependency
    load_dotenv = None  # type: ignore[assignment]


ROOT = Path(__file__).resolve().parent


def load_project_env() -> None:
    if load_dotenv is None:
        return
    load_dotenv(ROOT / ".env", override=False)


def get_cloud_client_kwargs(api_key_override: str | None = None) -> dict[str, Any]:
    api_key = (api_key_override or "").strip() or os.getenv("OPENAI_API_KEY") or os.getenv("DOUBAO_API_KEY") or os.getenv("ARK_API_KEY")
    if not api_key:
        raise RuntimeError(
            "未配置 API Key。请在 .env 中设置 OPENAI_API_KEY 或 DOUBAO_API_KEY/ARK_API_KEY。"
        )
    base_url = os.getenv("OPENAI_BASE_URL") or os.getenv("DOUBAO_BASE_URL")
    kwargs: dict[str, Any] = {"api_key": api_key}
    if base_url:
        kwargs["base_url"] = base_url
    return kwargs


def get_cloud_model(default_model: str = "gpt-4.1") -> str:
    return os.getenv("OPENAI_MODEL") or os.getenv("DOUBAO_MODEL") or default_model


def get_llm_timeout(default: int = 25) -> int:
    value = os.getenv("LLM_TIMEOUT")
    if not value:
        return default
    try:
        timeout = int(value)
    except ValueError:
        return default
    return timeout if timeout > 0 else default


def get_llm_max_retries(default: int = 0) -> int:
    value = os.getenv("LLM_MAX_RETRIES")
    if not value:
        return default
    try:
        retries = int(value)
    except ValueError:
        return default
    return retries if retries >= 0 else default

