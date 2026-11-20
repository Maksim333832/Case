from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from app.nodes.base import BaseNode, NodeContext, Port
from app.nodes.registry import register_node
from app.nodes.scanners.base import run_scanner_adapter


class SastScannerParams(BaseModel):
    ruleset: str = Field(default="kotlin-spring-boot", description="Target ruleset name passed to SAST scanner")


@register_node
class SastScannerNode(BaseNode):
    type = "scanner.sast"
    label = "SAST Scanner"
    group = "scanner"
    description = "Adapts team SAST scanner implementing scan(root, params) -> list[Finding]."
    inputs = [Port(name="workspace", kind="Workspace", description="Resolved project root")]
    outputs = [Port(name="findings", kind="Findings", description="Detected SAST findings")]
    Params = SastScannerParams

    async def run(self, ctx: NodeContext, inputs: dict[str, Any], params: BaseModel) -> dict[str, Any]:
        findings = await run_scanner_adapter(
            "sast",
            inputs.get("workspace"),
            params.model_dump(),
            ctx.settings,
        )
        return {"findings": findings}
