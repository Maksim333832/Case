from __future__ import annotations

import asyncio
import smtplib
from email.message import EmailMessage
from typing import Any

from pydantic import BaseModel, Field

from app.core.masking import mask_text
from app.core.models import Finding
from app.nodes.base import BaseNode, NodeContext, Port
from app.nodes.notify.webhook import _extract_payload
from app.nodes.registry import register_node


class SmtpNotifyParams(BaseModel):
    host: str = Field(default="localhost", description="SMTP server hostname")
    port: int = Field(default=587, ge=1, le=65535, description="SMTP server port")
    use_tls: bool = Field(default=True, description="Use STARTTLS")
    username: str = Field(default="", description="SMTP login username")
    credential_id: str = Field(default="", description="Encrypted credential ID storing SMTP password")
    from_email: str = Field(default="security-bot@repairdesk.local", description="Sender email address")
    to_email: str = Field(default="", description="Recipient email address")
    subject: str = Field(default="AI Security Workflow Report", description="Email subject")


def _send_smtp_sync(params: SmtpNotifyParams, password: str | None, body_text: str) -> None:
    msg = EmailMessage()
    msg["From"] = params.from_email
    msg["To"] = params.to_email
    msg["Subject"] = params.subject
    msg.set_content(body_text)

    with smtplib.SMTP(params.host, params.port, timeout=15) as server:
        if params.use_tls:
            server.starttls()
        if params.username and password:
            server.login(params.username, password)
        server.send_message(msg)


@register_node
class SmtpNotifyNode(BaseNode):
    type = "notify.smtp"
    label = "SMTP Email Notify"
    group = "notify"
    description = "Sends sanitized security report summary via SMTP email."
    inputs = [Port(name="in", kind="Any", description="Report or Findings payload")]
    outputs = []
    Params = SmtpNotifyParams

    async def run(self, ctx: NodeContext, inputs: dict[str, Any], params: BaseModel) -> dict[str, Any]:
        assert isinstance(params, SmtpNotifyParams)
        if not params.to_email.strip():
            raise ValueError("notify.smtp requires non-empty to_email")

        findings, ai_report = _extract_payload(inputs.get("in"), ctx)
        password = await ctx.get_credential(params.credential_id)
        extra = tuple(ctx.extra_secrets)

        lines = [
            f"Run ID: {ctx.run_id}",
            f"Total findings: {len(findings)}",
        ]
        for idx, f in enumerate(findings[:20], start=1):
            loc = f"{f.group}:{f.artifact}:{f.version} ({f.advisoryId})" if f.category == "SCA" else f"{f.class_} @ {f.path}:{f.line}"
            lines.append(f"{idx}. [{f.category}/{f.severity or '-'}] {loc}")
        if ai_report and ai_report.get("summary"):
            lines.append("")
            lines.append("AI Summary:")
            lines.append(mask_text(str(ai_report["summary"]), extra))

        body = mask_text("\n".join(lines), extra)
        try:
            await asyncio.to_thread(_send_smtp_sync, params, password, body)
        except Exception as exc:
            raise RuntimeError(mask_text(f"SMTP notification failed: {exc}", extra)) from exc
        return {"sent": True, "to": params.to_email, "count": len(findings)}
