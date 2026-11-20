from __future__ import annotations

import json
import logging
import uuid
from typing import Any

from fastapi import APIRouter, Body, HTTPException
from pydantic import BaseModel, Field

from app.config import get_settings
from app.core.db import WorkflowORM, get_session_factory
from app.core.models import WorkflowGraphModel, WorkflowOut
from app.engine.graph import validate_and_sort_graph

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["templates"])


class TemplateCopyRequest(BaseModel):
    name: str | None = None
    description: str | None = None
    param_overrides: dict[str, dict[str, Any]] = Field(
        default_factory=dict,
        description="Optional per-node_id or per-node_type param overrides",
    )


class PublishTemplateRequest(BaseModel):
    name: str | None = None
    description: str | None = None


def _orm_to_out(row: WorkflowORM) -> WorkflowOut:
    return WorkflowOut(
        id=row.id,
        name=row.name,
        description=row.description,
        graph=WorkflowGraphModel.model_validate_json(row.graph_json),
        is_template=row.is_template,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


def seed_templates_from_disk() -> int:
    settings = get_settings()
    if not settings.templates_dir.is_dir():
        return 0
    factory = get_session_factory()
    added = 0
    with factory() as session:
        for path in sorted(settings.templates_dir.glob("*.json")):
            try:
                raw = json.loads(path.read_text(encoding="utf-8"))
                tpl_id = str(raw.get("id") or f"tpl_{path.stem}").strip()
                if session.get(WorkflowORM, tpl_id) is not None:
                    continue
                graph = WorkflowGraphModel.model_validate(raw["graph"])
                validate_and_sort_graph(graph)
                session.add(
                    WorkflowORM(
                        id=tpl_id,
                        name=str(raw.get("name") or path.stem),
                        description=str(raw.get("description") or ""),
                        graph_json=graph.model_dump_json(),
                        is_template=True,
                    )
                )
                added += 1
            except Exception as exc:
                logger.warning("Skipping template %s: %s", path.name, exc)
        if added:
            session.commit()
    return added


@router.get("/templates", response_model=list[WorkflowOut])
def list_templates() -> list[WorkflowOut]:
    factory = get_session_factory()
    with factory() as session:
        rows = (
            session.query(WorkflowORM)
            .filter(WorkflowORM.is_template.is_(True))
            .order_by(WorkflowORM.name.asc())
            .all()
        )
        return [_orm_to_out(r) for r in rows]


@router.post("/templates/{template_id}/copy", response_model=WorkflowOut, status_code=201)
def copy_template(
    template_id: str,
    payload: TemplateCopyRequest | None = Body(default=None),
) -> WorkflowOut:
    factory = get_session_factory()
    with factory() as session:
        tpl = session.get(WorkflowORM, template_id)
        if tpl is None or not tpl.is_template:
            raise HTTPException(status_code=404, detail="Template not found")

        graph = WorkflowGraphModel.model_validate_json(tpl.graph_json)
        if payload and payload.param_overrides:
            for node in graph.nodes:
                if node.id in payload.param_overrides:
                    node.params.update(payload.param_overrides[node.id])
                if node.type in payload.param_overrides:
                    node.params.update(payload.param_overrides[node.type])

        new_id = f"wf_{uuid.uuid4().hex[:12]}"
        new_name = (payload.name if payload and payload.name else f"{tpl.name} (Copy)")
        new_desc = (payload.description if payload and payload.description is not None else tpl.description)

        row = WorkflowORM(
            id=new_id,
            name=new_name,
            description=new_desc,
            graph_json=graph.model_dump_json(),
            is_template=False,
        )
        session.add(row)
        session.commit()
        session.refresh(row)
        return _orm_to_out(row)


@router.post("/workflows/{workflow_id}/publish", response_model=WorkflowOut, status_code=201)
def publish_workflow_as_template(
    workflow_id: str,
    payload: PublishTemplateRequest | None = Body(default=None),
) -> WorkflowOut:
    factory = get_session_factory()
    with factory() as session:
        src = session.get(WorkflowORM, workflow_id)
        if src is None:
            raise HTTPException(status_code=404, detail="Workflow not found")

        tpl_id = f"tpl_{uuid.uuid4().hex[:10]}"
        row = WorkflowORM(
            id=tpl_id,
            name=(payload.name if payload and payload.name else src.name),
            description=(payload.description if payload and payload.description is not None else src.description),
            graph_json=src.graph_json,
            is_template=True,
        )
        session.add(row)
        session.commit()
        session.refresh(row)
        return _orm_to_out(row)
