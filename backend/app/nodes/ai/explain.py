from __future__ import annotations

import logging
from typing import Any

from pydantic import BaseModel, Field

from app.core.masking import register_runtime_secret
from app.core.models import Finding
from app.nodes.ai.llm_client import OpenAICompatibleClient
from app.nodes.ai.prompts import build_ai_prompts
from app.nodes.ai.validator import (
    AIValidationStats,
    build_fallback_ai_report,
    validate_ai_response,
)
from app.nodes.base import BaseNode, NodeContext, Port
from app.nodes.registry import register_node

logger = logging.getLogger(__name__)


def _extract_findings(raw_input: Any, fallback: list[Finding]) -> list[Finding]:
    if isinstance(raw_input, list):
        return [f if isinstance(f, Finding) else Finding.model_validate(f) for f in raw_input]
    if isinstance(raw_input, dict) and isinstance(raw_input.get("findings"), list):
        return [f if isinstance(f, Finding) else Finding.model_validate(f) for f in raw_input["findings"]]
    return list(fallback)


class AiExplainParams(BaseModel):
    credential_id: str = Field(default="", description="Optional credential ID for LLM API key (falls back to config LLM_API_KEY)")
    base_url: str = Field(default="", description="Optional override OpenAI-compatible base URL (defaults to config LLM_BASE_URL)")
    model: str = Field(default="", description="Optional override LLM model name (defaults to config LLM_MODEL)")
    language: str = Field(default="ru", description="Target language for developer explanations (ru/en)")


@register_node
class AiExplainNode(BaseNode):
    type = "ai.explain"
    label = "AI Explain & Validate"
    group = "ai"
    description = "Explains and aggregates findings via OpenAI-compatible LLM with strict hallucination validation and fallback."
    inputs = [Port(name="in", kind="Any", description="Findings or Report payload")]
    outputs = [
        Port(name="report", kind="Report", description="Validated AI explanation report + findings"),
        Port(name="findings", kind="Findings", description="Pass-through sanitized findings"),
    ]
    Params = AiExplainParams

    async def run(self, ctx: NodeContext, inputs: dict[str, Any], params: BaseModel) -> dict[str, Any]:
        assert isinstance(params, AiExplainParams)
        findings = _extract_findings(inputs.get("in"), ctx.last_findings)
        extra = tuple(ctx.extra_secrets)

        if not findings:
            ai_report = build_fallback_ai_report([], params.language, extra)
            validation = AIValidationStats(passed=True).to_dict()
            ctx.ai_report = {**ai_report, "validation": validation}
            return {
                "report": {"findings": [], "ai_report": ctx.ai_report, "validation": validation},
                "findings": [],
            }

        from app.api.settings import resolve_effective_llm_config

        cfg_base_url, cfg_model, cfg_api_key, _ = resolve_effective_llm_config()
        api_key = await ctx.get_credential(params.credential_id)
        if not api_key:
            api_key = cfg_api_key
            if api_key:
                register_runtime_secret(api_key)
                ctx.extra_secrets.add(api_key)
                extra = tuple(ctx.extra_secrets)

        base_url = params.base_url.strip() or cfg_base_url
        model = params.model.strip() or cfg_model

        system_prompt, user_prompt = build_ai_prompts(findings, params.language, extra)
        client = OpenAICompatibleClient(
            base_url=base_url,
            model=model,
            api_key=api_key or "",
            timeout_seconds=ctx.settings.llm_timeout_seconds,
        )

        retried = False
        final_report: dict[str, Any] | None = None
        final_stats = AIValidationStats(passed=False)

        # If no API key and not local Ollama/vLLM URL, go straight to deterministic fallback safely
        is_local_endpoint = any(h in base_url.lower() for h in ("localhost", "127.0.0.1", "ollama", "vllm"))
        if api_key or is_local_endpoint:
            for attempt in range(2):
                if attempt == 1:
                    retried = True
                try:
                    raw_content = await client.chat_json(system_prompt, user_prompt)
                    res = validate_ai_response(raw_content, findings, extra)
                    res.stats.retried = retried
                    final_stats = res.stats
                    if res.stats.passed and res.report is not None:
                        final_report = res.report
                        break
                    logger.warning("AI validation failed on attempt %d: %s", attempt + 1, res.stats.reasons)
                except Exception as exc:
                    logger.warning("AI call failed on attempt %d: %s", attempt + 1, exc)
                    final_stats = AIValidationStats(passed=False, retried=retried, reasons=["llm_error"])

        if final_report is None:
            final_report = build_fallback_ai_report(findings, params.language, extra)
            final_stats.used_fallback = True
            final_stats.retried = retried

        validation_dict = final_stats.to_dict()
        full_ai_report = {**final_report, "validation": validation_dict, "model": model}
        ctx.ai_report = full_ai_report
        ctx.last_findings = findings

        return {
            "report": {
                "findings": findings,
                "ai_report": full_ai_report,
                "validation": validation_dict,
            },
            "findings": findings,
        }
