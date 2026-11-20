from __future__ import annotations

import asyncio
import html
from collections import Counter
from typing import Any, Literal

import httpx
from pydantic import BaseModel, Field

from app.core.masking import mask_text, register_runtime_secret
from app.core.models import Finding
from app.core.severity import severity_counts
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


def format_telegram_message(
    findings: list[Finding],
    ai_report: dict[str, Any] | None,
    parse_mode: str = "HTML",
    extra_secrets: tuple[str, ...] = (),
) -> str:
    sev = severity_counts(findings)
    cats = Counter(f.category for f in findings)
    esc = html.escape if parse_mode == "HTML" else (lambda s: s)

    if parse_mode == "HTML":
        header = "<b>AI Security Workflow — Отчёт проверки</b>"
    else:
        header = "AI Security Workflow — Отчёт проверки"

    parts = [
        header,
        f"Находок: {len(findings)}",
    ]
    if findings:
        sev_line = ", ".join(f"{k}: {sev[k]}" for k in ("CRITICAL", "HIGH", "MEDIUM", "LOW") if sev.get(k))
        cat_line = ", ".join(f"{k}: {cats[k]}" for k in ("SECRET", "SAST", "SCA") if cats.get(k))
        parts.append(f"Критичность: {esc(sev_line)}")
        parts.append(f"Категории: {esc(cat_line)}")
        parts.append("")
        parts.append("<b>Топ находок:</b>" if parse_mode == "HTML" else "Топ находок:")
        for idx, f in enumerate(findings[:8], start=1):
            if f.category == "SCA":
                label = f"{f.group}:{f.artifact}:{f.version} ({f.advisoryId})"
            else:
                label = f"{f.class_} @ {f.path}:{f.line}"
            desc = mask_text(f.description or "", extra_secrets)
            line = f"{idx}. [{f.category}/{f.severity or '-'}] {esc(label)}"
            if desc:
                line += f" — {esc(desc[:140])}"
            parts.append(line)
        if len(findings) > 8:
            parts.append(f"... и ещё {len(findings) - 8} находок")
    else:
        parts.append("Уязвимости не обнаружены.")

    if ai_report and ai_report.get("summary"):
        parts.append("")
        ai_sum = mask_text(str(ai_report["summary"]), extra_secrets)[:600]
        parts.append(("<b>AI-резюме:</b> " if parse_mode == "HTML" else "AI-резюме: ") + esc(ai_sum))

    text = "\n".join(parts)
    text = mask_text(text, extra_secrets)
    if len(text) > 3950:
        text = text[:3940] + "\n... (обрезано)"
    return text


class TelegramNotifyParams(BaseModel):
    credential_id: str = Field(default="", description="Encrypted credential ID storing Telegram bot token")
    chat_id: str = Field(default="", description="Target Telegram chat ID")
    parse_mode: Literal["HTML", "Markdown", "Plain"] = Field(default="HTML", description="Telegram message formatting")
    only_on_findings: bool = Field(default=False, description="Skip notification when findings count is 0")


@register_node
class TelegramNotifyNode(BaseNode):
    type = "notify.telegram"
    label = "Telegram Notify"
    group = "notify"
    description = "Sends masked security summary and recommendations to Telegram chat."
    inputs = [Port(name="in", kind="Any", description="Report or Findings payload")]
    outputs = []
    Params = TelegramNotifyParams

    async def run(self, ctx: NodeContext, inputs: dict[str, Any], params: BaseModel) -> dict[str, Any]:
        assert isinstance(params, TelegramNotifyParams)
        findings, ai_report = _extract_payload(inputs.get("in"), ctx)
        if params.only_on_findings and not findings:
            return {"sent": False, "reason": "only_on_findings", "count": 0}

        bot_token = await ctx.get_credential(params.credential_id)
        if not bot_token:
            bot_token = str(ctx.runtime_params.get("telegram_bot_token") or "").strip()
            if bot_token:
                register_runtime_secret(bot_token)
                ctx.extra_secrets.add(bot_token)

        chat_id = str(ctx.runtime_params.get("chat_id") or params.chat_id).strip()
        if not bot_token:
            raise ValueError("notify.telegram requires bot token via credential_id")
        if not chat_id:
            raise ValueError("notify.telegram requires non-empty chat_id")

        extra = tuple(ctx.extra_secrets)
        message_text = format_telegram_message(findings, ai_report, params.parse_mode, extra)
        body: dict[str, Any] = {"chat_id": chat_id, "text": message_text}
        if params.parse_mode in ("HTML", "Markdown"):
            body["parse_mode"] = params.parse_mode

        url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        last_err: str | None = None
        for attempt in range(2):
            try:
                async with httpx.AsyncClient(timeout=15.0) as client:
                    resp = await client.post(url, json=body)
                if resp.status_code == 200:
                    data = resp.json()
                    if data.get("ok"):
                        msg_id = (data.get("result") or {}).get("message_id")
                        return {"sent": True, "chat_id": chat_id, "message_id": msg_id, "count": len(findings)}
                    last_err = f"Telegram API returned ok=false: {mask_text(resp.text[:300], extra)}"
                else:
                    last_err = f"Telegram HTTP {resp.status_code}: {mask_text(resp.text[:300], extra)}"
            except Exception as exc:
                last_err = mask_text(f"Telegram request failed: {exc}", extra)
            if attempt == 0:
                await asyncio.sleep(0.5)

        raise RuntimeError(last_err or "Telegram notification failed")
