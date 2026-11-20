from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from app.nodes.base import BaseNode, NodeContext, Port
from app.nodes.registry import register_node


class ManualTriggerParams(BaseModel):
    note: str = Field(default="", description="Optional operator note")


@register_node
class ManualTriggerNode(BaseNode):
    type = "trigger.manual"
    label = "Manual Trigger"
    group = "trigger"
    description = "Starts workflow manually via API or UI button."
    inputs = []
    outputs = [Port(name="out", kind="Any", description="Trigger signal")]
    Params = ManualTriggerParams

    async def run(self, ctx: NodeContext, inputs: dict[str, Any], params: BaseModel) -> dict[str, Any]:
        return {"out": {"trigger": ctx.trigger_type, "run_id": ctx.run_id, "params": ctx.runtime_params}}
