from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Awaitable, Callable, ClassVar, Literal

from pydantic import BaseModel

from app.config import Settings
from app.core.masking import mask_text, register_runtime_secret
from app.core.models import Finding, NodeTypeOut, PortSchema
from app.core.severity import severity_counts

PortKind = Literal["Workspace", "Findings", "Report", "Any"]


@dataclass(frozen=True)
class Port:
    name: str
    kind: PortKind
    required: bool = True
    multiple: bool = False
    description: str = ""

    def to_schema(self) -> PortSchema:
        return PortSchema(
            name=self.name,
            kind=self.kind,
            required=self.required,
            multiple=self.multiple,
            description=self.description,
        )


@dataclass
class NodeContext:
    run_id: str
    workflow_id: str
    workspace_dir: Path
    artifacts_dir: Path
    settings: Settings
    trigger_type: str = "manual"
    runtime_params: dict[str, Any] = field(default_factory=dict)
    credential_resolver: Callable[[str], Awaitable[str | None]] | None = None
    extra_secrets: set[str] = field(default_factory=set)
    ai_report: dict[str, Any] | None = None
    last_findings: list[Finding] = field(default_factory=list)
    report_files: dict[str, Path] = field(default_factory=dict)

    async def get_credential(self, credential_id: str | None) -> str | None:
        if not credential_id or self.credential_resolver is None:
            return None
        secret = await self.credential_resolver(credential_id)
        if secret:
            register_runtime_secret(secret)
            self.extra_secrets.add(secret)
        return secret


class EmptyParams(BaseModel):
    pass


class BaseNode(ABC):
    type: ClassVar[str]
    label: ClassVar[str]
    group: ClassVar[str]  # source | trigger | logic | scanner | ai | notify | findings
    description: ClassVar[str] = ""
    inputs: ClassVar[list[Port]] = []
    outputs: ClassVar[list[Port]] = []
    Params: ClassVar[type[BaseModel]] = EmptyParams

    @classmethod
    def to_node_type_out(cls) -> NodeTypeOut:
        return NodeTypeOut(
            type=cls.type,
            label=cls.label,
            group=cls.group,
            description=cls.description,
            inputs=[p.to_schema() for p in cls.inputs],
            outputs=[p.to_schema() for p in cls.outputs],
            params_schema=cls.Params.model_json_schema(),
        )

    @abstractmethod
    async def run(self, ctx: NodeContext, inputs: dict[str, Any], params: BaseModel) -> dict[str, Any]:
        """Execute node logic and return mapping {output_port_name: payload}."""
        raise NotImplementedError


def build_output_preview(outputs: dict[str, Any], extra_secrets: tuple[str, ...] = ()) -> dict[str, Any]:
    """Create a safe, secret-free preview dictionary for node_runs and WebSocket events."""
    if not outputs:
        return {"kind": "Empty", "active_ports": []}

    active_ports = list(outputs.keys())
    first_val = next(iter(outputs.values()))

    # Findings list
    if isinstance(first_val, list) and (not first_val or isinstance(first_val[0], Finding)):
        by_category: dict[str, int] = {}
        for f in first_val:
            by_category[f.category] = by_category.get(f.category, 0) + 1
        return {
            "kind": "Findings",
            "active_ports": active_ports,
            "count": len(first_val),
            "by_severity": severity_counts(first_val),
            "by_category": by_category,
        }

    if isinstance(first_val, dict):
        if "findings" in first_val and isinstance(first_val["findings"], list):
            items = first_val["findings"]
            preview: dict[str, Any] = {
                "kind": "Report",
                "active_ports": active_ports,
                "count": len(items),
                "by_severity": severity_counts(items),
            }
            if "validation" in first_val:
                preview["validation"] = first_val["validation"]
            if "formats" in first_val:
                preview["formats"] = first_val["formats"]
            return preview
        if "project_root" in first_val:
            return {
                "kind": "Workspace",
                "active_ports": active_ports,
                "project_root_name": Path(str(first_val["project_root"])).name,
                "source": mask_text(str(first_val.get("source", "")), extra_secrets),
            }
        safe_keys = {k: v for k, v in first_val.items() if k not in ("token", "secret", "api_key", "password") and isinstance(v, (str, int, float, bool, list))}
        if "sent" in first_val or "delivered" in first_val:
            return {"kind": "Notification", "active_ports": active_ports, **{k: mask_text(str(v), extra_secrets) if isinstance(v, str) else v for k, v in safe_keys.items()}}
        return {"kind": "Json", "active_ports": active_ports, "keys": list(first_val.keys())}

    if isinstance(first_val, (str, Path)):
        return {
            "kind": "Workspace",
            "active_ports": active_ports,
            "path": mask_text(str(first_val), extra_secrets),
        }

    return {"kind": "Any", "active_ports": active_ports}
