from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from app.nodes.base import BaseNode, NodeContext, Port
from app.nodes.registry import register_node
from app.nodes.scanners.base import run_scanner_adapter


class ScaScannerParams(BaseModel):
    vuln_db_path: str = Field(default="", description="Optional override path to Maven vulnerabilities.json (defaults to config VULN_DB_PATH)")
    lockfile_priority: bool = Field(default=True, description="Prefer resolved versions from gradle.lockfile when present")


@register_node
class ScaScannerNode(BaseNode):
    type = "scanner.sca"
    label = "SCA Scanner"
    group = "scanner"
    description = "Adapts team SCA dependency scanner implementing scan(root, params) -> list[Finding]."
    inputs = [Port(name="workspace", kind="Workspace", description="Resolved project root")]
    outputs = [Port(name="findings", kind="Findings", description="Detected SCA findings")]
    Params = ScaScannerParams

    async def run(self, ctx: NodeContext, inputs: dict[str, Any], params: BaseModel) -> dict[str, Any]:
        payload = params.model_dump()
        if not str(payload.get("vuln_db_path", "")).strip():
            payload["vuln_db_path"] = str(ctx.settings.vuln_db_path)
        findings = await run_scanner_adapter(
            "sca",
            inputs.get("workspace"),
            payload,
            ctx.settings,
        )
        return {"findings": findings}
