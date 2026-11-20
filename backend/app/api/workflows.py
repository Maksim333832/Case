from __future__ import annotations

import asyncio
import json
import uuid
from typing import Any

from fastapi import APIRouter, Body, HTTPException, Query

from app.core.db import WorkflowORM, get_session_factory
from app.core.models import RunRequest, WorkflowCreate, WorkflowGraphModel, WorkflowOut, WorkflowUpdate
from app.engine.executor import create_run_record, execute_workflow
from app.engine.graph import WorkflowValidationError, validate_and_sort_graph

router = APIRouter(prefix="/api", tags=["workflows"])

_BACKGROUND_TASKS: set[asyncio.Task[Any]] = set()


def _orm_to_workflow_out(row: WorkflowORM) -> WorkflowOut:
    return WorkflowOut(
        id=row.id,
        name=row.name,
        description=row.description,
        graph=WorkflowGraphModel.model_validate_json(row.graph_json),
        is_template=row.is_template,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


@router.get("/workflows", response_model=list[WorkflowOut])
def list_workflows(include_templates: bool = Query(default=True)) -> list[WorkflowOut]:
    factory = get_session_factory()
    with factory() as session:
        query = session.query(WorkflowORM)
        if not include_templates:
            query = query.filter(WorkflowORM.is_template.is_(False))
        rows = query.order_by(WorkflowORM.created_at.desc()).all()
        return [_orm_to_workflow_out(r) for r in rows]


@router.post("/workflows", response_model=WorkflowOut, status_code=201)
def create_workflow(payload: WorkflowCreate) -> WorkflowOut:
    try:
        validate_and_sort_graph(payload.graph)
    except WorkflowValidationError as exc:
        raise HTTPException(status_code=422, detail={"errors": exc.errors}) from exc

    wf_id = f"wf_{uuid.uuid4().hex[:12]}"
    factory = get_session_factory()
    with factory() as session:
        row = WorkflowORM(
            id=wf_id,
            name=payload.name,
            description=payload.description,
            graph_json=payload.graph.model_dump_json(),
            is_template=payload.is_template,
        )
        session.add(row)
        session.commit()
        session.refresh(row)
        out = _orm_to_workflow_out(row)

    try:
        from app.engine.scheduler import get_scheduler

        get_scheduler().sync_workflow(out)
    except Exception:
        pass
    return out


@router.get("/workflows/{workflow_id}", response_model=WorkflowOut)
def get_workflow(workflow_id: str) -> WorkflowOut:
    factory = get_session_factory()
    with factory() as session:
        row = session.get(WorkflowORM, workflow_id)
        if row is None:
            raise HTTPException(status_code=404, detail="Workflow not found")
        return _orm_to_workflow_out(row)


@router.put("/workflows/{workflow_id}", response_model=WorkflowOut)
def update_workflow(workflow_id: str, payload: WorkflowUpdate) -> WorkflowOut:
    factory = get_session_factory()
    with factory() as session:
        row = session.get(WorkflowORM, workflow_id)
        if row is None:
            raise HTTPException(status_code=404, detail="Workflow not found")

        if payload.graph is not None:
            try:
                validate_and_sort_graph(payload.graph)
            except WorkflowValidationError as exc:
                raise HTTPException(status_code=422, detail={"errors": exc.errors}) from exc
            row.graph_json = payload.graph.model_dump_json()

        if payload.name is not None:
            row.name = payload.name
        if payload.description is not None:
            row.description = payload.description
        if payload.is_template is not None:
            row.is_template = payload.is_template

        session.commit()
        session.refresh(row)
        out = _orm_to_workflow_out(row)

    try:
        from app.engine.scheduler import get_scheduler

        get_scheduler().sync_workflow(out)
    except Exception:
        pass
    return out


@router.delete("/workflows/{workflow_id}", status_code=204)
def delete_workflow(workflow_id: str) -> None:
    factory = get_session_factory()
    with factory() as session:
        row = session.get(WorkflowORM, workflow_id)
        if row is None:
            raise HTTPException(status_code=404, detail="Workflow not found")
        session.delete(row)
        session.commit()

    try:
        from app.engine.scheduler import get_scheduler

        get_scheduler().remove_workflow(workflow_id)
    except Exception:
        pass


@router.post("/workflows/{workflow_id}/run")
async def run_workflow(
    workflow_id: str,
    wait: bool = Query(default=False),
    payload: RunRequest | None = Body(default=None),
) -> dict[str, Any]:
    factory = get_session_factory()
    with factory() as session:
        row = session.get(WorkflowORM, workflow_id)
        if row is None:
            raise HTTPException(status_code=404, detail="Workflow not found")
        graph = WorkflowGraphModel.model_validate_json(row.graph_json)

    try:
        validate_and_sort_graph(graph)
    except WorkflowValidationError as exc:
        raise HTTPException(status_code=422, detail={"errors": exc.errors}) from exc

    trigger_type = payload.trigger if payload else "manual"
    runtime_params = payload.params if payload else {}
    run_id = create_run_record(workflow_id, trigger_type, graph)

    if wait:
        result = await execute_workflow(
            workflow_id=workflow_id,
            graph=graph,
            trigger_type=trigger_type,
            runtime_params=runtime_params,
            run_id=run_id,
        )
        return result

    task = asyncio.create_task(
        execute_workflow(
            workflow_id=workflow_id,
            graph=graph,
            trigger_type=trigger_type,
            runtime_params=runtime_params,
            run_id=run_id,
        )
    )
    _BACKGROUND_TASKS.add(task)
    task.add_done_callback(_BACKGROUND_TASKS.discard)
    return {"run_id": run_id, "status": "pending"}
