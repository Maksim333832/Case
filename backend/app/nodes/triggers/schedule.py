from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

from app.nodes.base import BaseNode, NodeContext, Port
from app.nodes.registry import register_node


class ScheduleTriggerParams(BaseModel):
    mode: Literal["cron", "interval"] = Field(default="cron", description="Schedule mode")
    cron: str = Field(default="0 14 * * *", description="5-field cron expression (min hour day month weekday)")
    interval_seconds: int = Field(default=3600, ge=10, description="Interval in seconds when mode='interval'")
    enabled: bool = Field(default=True, description="Whether automatic schedule is active")


@register_node
class ScheduleTriggerNode(BaseNode):
    type = "trigger.schedule"
    label = "Schedule Trigger"
    group = "trigger"
    description = "Starts workflow automatically on cron expression or fixed interval."
    inputs = []
    outputs = [Port(name="out", kind="Any", description="Scheduled trigger signal")]
    Params = ScheduleTriggerParams

    async def run(self, ctx: NodeContext, inputs: dict[str, Any], params: BaseModel) -> dict[str, Any]:
        return {"out": {"trigger": "schedule", "run_id": ctx.run_id, "params": ctx.runtime_params}}
