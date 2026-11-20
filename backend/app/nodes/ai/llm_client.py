from __future__ import annotations

from typing import Any

import httpx

from app.core.masking import mask_text, register_runtime_secret


class OpenAICompatibleClient:
    """Unified OpenAI-compatible client for Gemini, OpenAI, Ollama, and vLLM."""

    def __init__(
        self,
        base_url: str,
        model: str,
        api_key: str = "",
        timeout_seconds: float = 30.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.api_key = api_key.strip()
        self.timeout_seconds = timeout_seconds
        if self.api_key:
            register_runtime_secret(self.api_key)

    async def chat_json(self, system_prompt: str, user_prompt: str) -> str:
        url = f"{self.base_url}/chat/completions"
        headers: dict[str, str] = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        payload: dict[str, Any] = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": 0.2,
            "max_tokens": 4096,
            "response_format": {"type": "json_object"},
        }

        extra = (self.api_key,) if self.api_key else ()
        try:
            async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
                resp = await client.post(url, headers=headers, json=payload)
                if resp.status_code == 400 and "response_format" in resp.text:
                    # Fallback for local Ollama/vLLM builds that reject response_format
                    payload.pop("response_format", None)
                    resp = await client.post(url, headers=headers, json=payload)
        except Exception as exc:
            raise RuntimeError(mask_text(f"LLM request failed: {exc}", extra)) from exc

        if resp.status_code != 200:
            raise RuntimeError(mask_text(f"LLM HTTP {resp.status_code}: {resp.text[:400]}", extra))

        data = resp.json()
        choices = data.get("choices") or []
        if not choices:
            raise RuntimeError("LLM response contained no choices")
        content = (choices[0].get("message") or {}).get("content")
        if not isinstance(content, str) or not content.strip():
            raise RuntimeError("LLM returned empty content")
        return content
