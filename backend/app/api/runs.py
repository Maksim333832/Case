from __future__ import annotations

import json
from typing import Any

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import PlainTextResponse, Response

from app.config import get_settings
from app.core.db import NodeRunORM, RunORM, get_session_factory
from app.core.models import NodeRunOut, RunOut

router = APIRouter(prefix="/api", tags=["runs"])


def _load_findings_for_run(run_id: str) -> list[dict[str, Any]]:
    settings = get_settings()
    run_dir = settings.artifacts_dir / run_id
    for candidate in ("report.json", "findings_snapshot.json"):
        p = run_dir / candidate
        if p.is_file():
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
                if isinstance(data, dict) and isinstance(data.get("findings"), list):
                    return data["findings"]
            except Exception:
                pass
    return []


def _orm_to_run_out(run: RunORM, node_runs: list[NodeRunORM], include_findings: bool = True) -> RunOut:
    nr_out = []
    for nr in node_runs:
        duration_ms = None
        if nr.started_at and nr.finished_at:
            duration_ms = int((nr.finished_at - nr.started_at).total_seconds() * 1000)
        nr_out.append(
            NodeRunOut(
                node_id=nr.node_id,
                status=nr.status,
                started_at=nr.started_at,
                finished_at=nr.finished_at,
                duration_ms=duration_ms,
                output_preview=json.loads(nr.output_preview_json) if nr.output_preview_json else None,
                error=nr.error,
            )
        )

    return RunOut(
        id=run.id,
        workflow_id=run.workflow_id,
        status=run.status,
        trigger=run.trigger,
        started_at=run.started_at,
        finished_at=run.finished_at,
        summary=json.loads(run.summary_json) if run.summary_json else None,
        ai_report=json.loads(run.ai_report_json) if run.ai_report_json else None,
        findings=_load_findings_for_run(run.id) if include_findings else [],
        node_runs=nr_out,
    )


@router.get("/runs", response_model=list[RunOut])
def list_runs(workflow_id: str | None = Query(default=None), limit: int = Query(default=50, ge=1, le=500)) -> list[RunOut]:
    factory = get_session_factory()
    with factory() as session:
        query = session.query(RunORM)
        if workflow_id:
            query = query.filter(RunORM.workflow_id == workflow_id)
        runs = query.order_by(RunORM.started_at.desc()).limit(limit).all()
        result = []
        for r in runs:
            nrs = session.query(NodeRunORM).filter(NodeRunORM.run_id == r.id).order_by(NodeRunORM.id.asc()).all()
            result.append(_orm_to_run_out(r, nrs, include_findings=False))
        return result


@router.get("/runs/{run_id}", response_model=RunOut)
def get_run(run_id: str) -> RunOut:
    factory = get_session_factory()
    with factory() as session:
        run = session.get(RunORM, run_id)
        if run is None:
            raise HTTPException(status_code=404, detail="Run not found")
        nrs = session.query(NodeRunORM).filter(NodeRunORM.run_id == run_id).order_by(NodeRunORM.id.asc()).all()
        return _orm_to_run_out(run, nrs, include_findings=True)


@router.get("/runs/{run_id}/report.json")
def get_run_report_json(run_id: str) -> Response:
    factory = get_session_factory()
    with factory() as session:
        if session.get(RunORM, run_id) is None:
            raise HTTPException(status_code=404, detail="Run not found")

    settings = get_settings()
    report_path = settings.artifacts_dir / run_id / "report.json"
    if not report_path.is_file():
        raise HTTPException(status_code=404, detail="report.json not generated for this run")
    return Response(content=report_path.read_text(encoding="utf-8"), media_type="application/json; charset=utf-8")


@router.get("/runs/{run_id}/report.md")
def get_run_report_md(run_id: str) -> PlainTextResponse:
    factory = get_session_factory()
    with factory() as session:
        if session.get(RunORM, run_id) is None:
            raise HTTPException(status_code=404, detail="Run not found")

    settings = get_settings()
    report_path = settings.artifacts_dir / run_id / "report.md"
    if not report_path.is_file():
        raise HTTPException(status_code=404, detail="report.md not generated for this run")
    return PlainTextResponse(content=report_path.read_text(encoding="utf-8"), media_type="text/markdown; charset=utf-8")
