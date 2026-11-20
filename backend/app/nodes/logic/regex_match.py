from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from app.nodes.base import BaseNode, NodeContext, Port
from app.nodes.logic._eval_helpers import extract_findings, resolve_selector, safe_regex_search
from app.nodes.registry import register_node


class RegexMatchParams(BaseModel):
    field: str = Field(default="findings.paths", description="Target selector (findings.paths, findings.descriptions, findings.classes, report.md)")
    pattern: str = Field(default=".*", description="Regular expression pattern (executed with ReDoS timeout & length cap)")


@register_node
class RegexMatchNode(BaseNode):
    type = "logic.regex"
    label = "Regex Match"
    group = "logic"
    description = "Matches safe bounded regular expression against finding fields or report text."
    inputs = [Port(name="in", kind="Any", description="Incoming payload")]
    outputs = [
        Port(name="true", kind="Any", description="Emitted when pattern matches"),
        Port(name="false", kind="Any", description="Emitted when pattern does not match"),
    ]
    Params = RegexMatchParams

    async def run(self, ctx: NodeContext, inputs: dict[str, Any], params: BaseModel) -> dict[str, Any]:
        assert isinstance(params, RegexMatchParams)
        payload = inputs.get("in")
        findings = extract_findings(payload, ctx.last_findings)
        md_text = ""
        if "md" in ctx.report_files and ctx.report_files["md"].is_file():
            md_text = ctx.report_files["md"].read_text(encoding="utf-8", errors="ignore")
        target_text = str(resolve_selector(params.field, findings, report_md_text=md_text))
        matched = safe_regex_search(params.pattern, target_text)
        forwarded = payload if payload is not None else {"findings": findings}
        return {"true": forwarded} if matched else {"false": forwarded}
