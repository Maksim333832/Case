from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from app.nodes.base import BaseNode, NodeContext, Port
from app.nodes.registry import register_node
from app.nodes.scanners.base import run_scanner_adapter


class SecretsScannerParams(BaseModel):
    include_extensions: list[str] = Field(
        default_factory=lambda: [".kt", ".kts", ".yml", ".yaml", ".properties", ".json"],
        description="Optional file extensions filter passed to secrets scanner",
    )


@register_node
class SecretsScannerNode(BaseNode):
    type = "scanner.secrets"
    label = "Secrets Scanner"
    group = "scanner"
    description = "Adapts team Secrets scanner implementing scan(root, params) -> list[Finding]."
    inputs = [Port(name="workspace", kind="Workspace", description="Resolved project root")]
    outputs = [Port(name="findings", kind="Findings", description="Detected SECRET findings")]
    Params = SecretsScannerParams

    async def run(self, ctx: NodeContext, inputs: dict[str, Any], params: BaseModel) -> dict[str, Any]:
        findings = await run_scanner_adapter(
            "secrets",
            inputs.get("workspace"),
            params.model_dump(),
            ctx.settings,
        )
        return {"findings": findings}
