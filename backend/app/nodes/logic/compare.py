from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

from app.nodes.base import BaseNode, NodeContext, Port
from app.nodes.logic._eval_helpers import evaluate_condition, extract_findings
from app.nodes.registry import register_node


class CompareParams(BaseModel):
    left: str = Field(default="findings.max_severity", description="Left value selector")
    op: Literal["==", "!=", ">", ">=", "<", "<=", "in"] = Field(default=">=", description="Comparison operator")
    right: Any = Field(default="HIGH", description="Right comparison value or severity level")


@register_node
class CompareNode(BaseNode):
    type = "logic.compare"
    label = "Compare"
    group = "logic"
    description = "Compares numeric, string, or severity metrics against threshold."
    inputs = [Port(name="in", kind="Any", description="Incoming payload")]
    outputs = [
        Port(name="true", kind="Any", description="Emitted when comparison holds"),
        Port(name="false", kind="Any", description="Emitted when comparison fails"),
    ]
    Params = CompareParams

    async def run(self, ctx: NodeContext, inputs: dict[str, Any], params: BaseModel) -> dict[str, Any]:
        assert isinstance(params, CompareParams)
        payload = inputs.get("in")
        findings = extract_findings(payload, ctx.last_findings)
        matched = evaluate_condition(params.left, params.op, params.right, findings)
        forwarded = payload if payload is not None else {"findings": findings}
        return {"true": forwarded} if matched else {"false": forwarded}
