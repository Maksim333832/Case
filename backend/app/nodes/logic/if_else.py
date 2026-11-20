from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

from app.nodes.base import BaseNode, NodeContext, Port
from app.nodes.logic._eval_helpers import evaluate_condition, extract_findings
from app.nodes.registry import register_node


class IfElseParams(BaseModel):
    left: str = Field(default="findings.count", description="Left operand selector (e.g. findings.count, findings.max_severity, findings.by_category.SECRET, findings.by_severity.HIGH)")
    op: Literal["==", "!=", ">", ">=", "<", "<=", "in", "regex"] = Field(default=">", description="Comparison operator")
    right: Any = Field(default=0, description="Right comparison value")


@register_node
class IfElseNode(BaseNode):
    type = "logic.if_else"
    label = "If / Else"
    group = "logic"
    description = "Routes execution to 'true' or 'false' branch based on structural condition without eval."
    inputs = [Port(name="in", kind="Any", description="Incoming findings or report payload")]
    outputs = [
        Port(name="true", kind="Any", description="Emitted when condition evaluates to true"),
        Port(name="false", kind="Any", description="Emitted when condition evaluates to false"),
    ]
    Params = IfElseParams

    async def run(self, ctx: NodeContext, inputs: dict[str, Any], params: BaseModel) -> dict[str, Any]:
        assert isinstance(params, IfElseParams)
        payload = inputs.get("in")
        findings = extract_findings(payload, ctx.last_findings)
        md_text = ""
        if "md" in ctx.report_files and ctx.report_files["md"].is_file():
            md_text = ctx.report_files["md"].read_text(encoding="utf-8", errors="ignore")

        matched = evaluate_condition(params.left, params.op, params.right, findings, report_md_text=md_text)
        forwarded = payload if payload is not None else {"findings": findings}
        return {"true": forwarded} if matched else {"false": forwarded}
