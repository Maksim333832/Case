from __future__ import annotations

import asyncio
from typing import Any, Literal
from urllib.parse import urlparse

import httpx
from pydantic import BaseModel, Field

from app.core.masking import mask_text, register_runtime_secret
from app.core.models import Finding
from app.core.severity import max_severity, severity_counts
from app.nodes.base import BaseNode, NodeContext, Port
from app.nodes.registry import register_node


def _extract_payload(raw_input: Any, ctx: NodeContext) -> tuple[list[Finding], dict[str, Any] | None]:
    findings: list[Finding] = []
    ai_report: dict[str, Any] | None = ctx.ai_report
    if isinstance(raw_input, dict):
        if isinstance(raw_input.get("ai_report"), dict):
            ai_report = raw_input["ai_report"]
        elif "summary" in raw_input and "items" in raw_input:
            ai_report = raw_input
        raw_list = raw_input.get("findings")
        if isinstance(raw_list, list):
            findings = [f if isinstance(f, Finding) else Finding.model_validate(f) for f in raw_list]
    elif isinstance(raw_input, list):
        findings = [f if isinstance(f, Finding) else Finding.model_validate(f) for f in raw_input]
    if not findings and ctx.last_findings:
        findings = list(ctx.last_findings)
    return findings, ai_report


class WebhookNotifyParams(BaseModel):
    url: str = Field(default="", description="Target HTTP/HTTPS webhook URL")
    method: Literal["POST", "PUT"] = Field(default="POST", description="HTTP method")
    credential_id: str = Field(default="", description="Optional credential ID for Authorization header")
    auth_header: str = Field(default="Authorization", description="Header name for credential secret")
    auth_prefix: str = Field(default="Bearer ", description="Prefix prepended to credential value")
    only_on_findings: bool = Field(default=False, description="Skip webhook call if findings list is empty")
    timeout_seconds: float = Field(default=10.0, ge=1.0, le=60.0, description="HTTP request timeout")


@register_node
class WebhookNotifyNode(BaseNode):
    type = "notify.webhook"
    label = "HTTP Webhook Notify"
    group = "notify"
    description = "Sends sanitized JSON security summary and submission findings to an HTTP/HTTPS webhook."
    inputs = [Port(name="in", kind="Any", description="Report or Findings payload")]
    outputs = []
    Params = WebhookNotifyParams

    async def run(self, ctx: NodeContext, inputs: dict[str, Any], params: BaseModel) -> dict[str, Any]:
        assert isinstance(params, WebhookNotifyParams)
        findings, ai_report = _extract_payload(inputs.get("in"), ctx)
        if params.only_on_findings and not findings:
            return {"sent": False, "reason": "only_on_findings", "count": 0}

        target_url = str(ctx.runtime_params.get("webhook_url") or params.url).strip()
        parsed = urlparse(target_url)
        if parsed.scheme.lower() not in ("http", "https") or not parsed.netloc:
            raise ValueError("notify.webhook requires a valid http:// or https:// URL")

        secret_val = await ctx.get_credential(params.credential_id)
        if secret_val:
            register_runtime_secret(secret_val)
            ctx.extra_secrets.add(secret_val)
        extra = tuple(ctx.extra_secrets)

        headers: dict[str, str] = {"Content-Type": "application/json"}
        if secret_val:
            headers[params.auth_header] = f"{params.auth_prefix}{secret_val}"

        payload = {
            "run_id": ctx.run_id,
            "workflow_id": ctx.workflow_id,
            "count": len(findings),
            "max_severity": max_severity(findings),
            "by_severity": severity_counts(findings),
            "findings": [f.to_submission() for f in findings],
            "ai_summary": mask_text(str(ai_report.get("summary", "")), extra) if ai_report else None,
        }

        last_err: str | None = None
        for attempt in range(2):
            try:
                async with httpx.AsyncClient(timeout=params.timeout_seconds) as client:
                    resp = await client.request(params.method, target_url, json=payload, headers=headers)
                if 200 <= resp.status_code < 300:
                    return {
                        "sent": True,
                        "status_code": resp.status_code,
                        "count": len(findings),
                    }
                last_err = f"Webhook HTTP {resp.status_code}: {mask_text(resp.text[:300], extra)}"
            except Exception as exc:
                last_err = mask_text(f"Webhook request failed: {exc}", extra)
            if attempt == 0:
                await asyncio.sleep(0.3)

        raise RuntimeError(last_err or "Webhook notification failed")
