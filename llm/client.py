from __future__ import annotations

import json
import os
import subprocess
import urllib.error
import urllib.request

from env_config import (
    get_cloud_client_kwargs,
    get_cloud_model,
    get_llm_max_retries,
    get_llm_timeout,
    load_project_env,
)
from llm.exceptions import (
    LLMConfigError,
    LLMConnectionError,
    LLMError,
    LLMTimeoutError,
)

try:
    from openai import OpenAI
except Exception:  # pragma: no cover - optional runtime dependency
    OpenAI = None  # type: ignore[assignment]

load_project_env()


class LLMClient:
    def __init__(
        self,
        ai_mode: str,
        model_name: str | None = None,
        api_key: str | None = None,
    ) -> None:
        self.ai_mode = ai_mode
        self.model_name = (model_name or "").strip() or None
        self.api_key = (api_key or "").strip() or None

    def generate_text(self, prompt: str) -> tuple[str, str]:
        if self.ai_mode == "cloud":
            return self._generate_cloud_text(prompt)
        if self.ai_mode == "local":
            return self._generate_local_text(prompt)
        if self.ai_mode == "rule":
            raise LLMConfigError("rule mode does not allow external LLM calls.")
        raise LLMConfigError(f"unsupported ai_mode for LLM generation: {self.ai_mode}")

    def _generate_cloud_text(self, prompt: str) -> tuple[str, str]:
        if OpenAI is None:
            raise LLMConfigError("OpenAI SDK is unavailable.")

        try:
            client_kwargs = get_cloud_client_kwargs(api_key_override=self.api_key)
            client_kwargs["max_retries"] = get_llm_max_retries(default=0)
            client_kwargs["timeout"] = get_llm_timeout(default=25)
            client = OpenAI(**client_kwargs)
            used_model = self.model_name or get_cloud_model("gpt-4.1")
            response = client.chat.completions.create(
                model=used_model,
                messages=[{"role": "user", "content": prompt}],
            )
        except RuntimeError as exc:
            if self.model_name is None and self.api_key is None:
                copilot_result = self._try_copilot_cli(prompt)
                if copilot_result is not None:
                    return copilot_result
            raise LLMConfigError(str(exc)) from exc
        except Exception as exc:
            detail = str(exc).strip()
            suffix = f": {detail}" if detail else ""
            raise LLMConnectionError(
                f"cloud LLM request failed: {type(exc).__name__}{suffix}"
            ) from exc

        content = (response.choices[0].message.content or "").strip()
        return content, used_model

    def _try_copilot_cli(self, prompt: str) -> tuple[str, str] | None:
        try:
            completed = subprocess.run(
                ["gh", "copilot", "-p", prompt],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="ignore",
            )
        except (OSError, RuntimeError):
            return None

        if completed.returncode != 0 or not completed.stdout.strip():
            return None

        lines = []
        for line in completed.stdout.splitlines():
            line = line.rstrip()
            if not line:
                continue
            if line.startswith(("Changes", "Requests", "Tokens")):
                continue
            lines.append(line)
        cleaned = "\n".join(lines).strip()
        if not cleaned:
            return None
        return cleaned, "copilot-cli-default"

    def _generate_local_text(self, prompt: str) -> tuple[str, str]:
        selected_model = self.model_name or os.getenv(
            "LOCAL_LLM_MODEL", "qwen2.5-coder:7b"
        )
        url = os.getenv("LOCAL_LLM_URL", "http://127.0.0.1:11434/api/generate")
        body = json.dumps(
            {"model": selected_model, "prompt": prompt, "stream": False}
        ).encode("utf-8")
        request = urllib.request.Request(
            url, data=body, headers={"Content-Type": "application/json"}, method="POST"
        )

        try:
            with urllib.request.urlopen(
                request, timeout=get_llm_timeout(default=25)
            ) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except TimeoutError as exc:
            raise LLMTimeoutError("local LLM request timed out.") from exc
        except urllib.error.URLError as exc:
            raise LLMConnectionError("local LLM endpoint is unavailable.") from exc
        except json.JSONDecodeError as exc:
            raise LLMError("local LLM response is not valid JSON.") from exc

        return str(payload.get("response", "")).strip(), selected_model
