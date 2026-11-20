from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from app.core.models import Finding
from app.core.severity import severity_rank
from app.nodes.base import BaseNode, NodeContext, Port
from app.nodes.registry import register_node


def _finding_dedup_key(f: Finding) -> tuple[Any, ...]:
    if f.category == "SCA":
        return ("SCA", f.path, f.group, f.artifact, f.version, f.advisoryId)
    return (f.category, f.path, f.class_, f.line)


def _flatten_findings(raw: Any) -> list[Finding]:
    items: list[Finding] = []
    if raw is None:
        return items
    if isinstance(raw, Finding):
        return [raw]
    if isinstance(raw, dict):
        if "findings" in raw:
            return _flatten_findings(raw["findings"])
        return [Finding.model_validate(raw)]
    if isinstance(raw, list):
        for el in raw:
            items.extend(_flatten_findings(el))
    return items


class MergeFindingsParams(BaseModel):
    deduplicate: bool = Field(default=True, description="Deduplicate identical findings across scanners")


@register_node
class MergeFindingsNode(BaseNode):
    type = "findings.merge"
    label = "Merge Findings"
    group = "findings"
    description = "Merges, deduplicates, and sorts findings from multiple scanners by severity."
    inputs = [Port(name="in", kind="Findings", multiple=True, description="Findings lists from scanners")]
    outputs = [Port(name="findings", kind="Findings", description="Deduplicated and severity-sorted findings")]
    Params = MergeFindingsParams

    async def run(self, ctx: NodeContext, inputs: dict[str, Any], params: BaseModel) -> dict[str, Any]:
        assert isinstance(params, MergeFindingsParams)
        collected = _flatten_findings(inputs.get("in"))

        if params.deduplicate:
            merged_map: dict[tuple[Any, ...], Finding] = {}
            for item in collected:
                key = _finding_dedup_key(item)
                existing = merged_map.get(key)
                if existing is None:
                    merged_map[key] = item
                else:
                    updates: dict[str, Any] = {}
                    if severity_rank(item.severity) > severity_rank(existing.severity):
                        updates["severity"] = item.severity
                    if existing.endLine is None and item.endLine is not None:
                        updates["endLine"] = item.endLine
                    if not existing.description and item.description:
                        updates["description"] = item.description
                    if not existing.remediation and item.remediation:
                        updates["remediation"] = item.remediation
                    if item.aliases:
                        updates["aliases"] = sorted(set(existing.aliases) | set(item.aliases))
                    if updates:
                        merged_map[key] = existing.model_copy(update=updates)
            result = list(merged_map.values())
        else:
            result = list(collected)

        result.sort(
            key=lambda f: (
                -severity_rank(f.severity),
                f.category,
                f.path,
                f.line or 0,
                f.advisoryId or "",
            )
        )
        return {"findings": result}
