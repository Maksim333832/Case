from __future__ import annotations

import hmac
from typing import Any, Literal

from fastapi import APIRouter, Body, Header, HTTPException, Query
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import BaseModel, Field

from app.config import get_settings
from app.core.db import WorkflowORM, get_session_factory
from app.core.models import WorkflowGraphModel
from app.core.severity import severity_rank
from app.engine.executor import create_run_record, execute_workflow
from app.engine.graph import WorkflowValidationError, validate_and_sort_graph

router = APIRouter(prefix="/api/ci", tags=["ci"])


class CIRunRequest(BaseModel):
    fail_on_severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"] = "HIGH"
    strict_http: bool = False
    params: dict[str, Any] = Field(default_factory=dict)


def _verify_ci_token(x_ci_token: str | None, authorization: str | None) -> None:
    expected = get_settings().ci_api_token.strip()
    if not expected:
        return
    provided = (x_ci_token or "").strip()
    if not provided and authorization and authorization.lower().startswith("bearer "):
        provided = authorization.split(None, 1)[1].strip()
    if not provided or not hmac.compare_digest(provided, expected):
        raise HTTPException(status_code=401, detail="Invalid or missing CI token")


@router.post("/workflows/{workflow_id}/run")
async def trigger_ci_run(
    workflow_id: str,
    payload: CIRunRequest | None = Body(default=None),
    x_ci_token: str | None = Header(default=None),
    authorization: str | None = Header(default=None),
) -> JSONResponse:
    _verify_ci_token(x_ci_token, authorization)

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

    req = payload or CIRunRequest()
    run_id = create_run_record(workflow_id, "ci", graph)
    result = await execute_workflow(
        workflow_id=workflow_id,
        graph=graph,
        trigger_type="ci",
        runtime_params=req.params,
        run_id=run_id,
    )

    threshold = severity_rank(req.fail_on_severity)
    findings = result.get("findings") or []
    blocking_count = sum(1 for f in findings if severity_rank(f.get("severity")) >= threshold)
    gate_passed = result["status"] == "success" and blocking_count == 0

    body = {
        "run_id": run_id,
        "workflow_id": workflow_id,
        "status": result["status"],
        "gate_passed": gate_passed,
        "fail_on_severity": req.fail_on_severity,
        "blocking_findings_count": blocking_count,
        "total_findings_count": len(findings),
        "summary": result["summary"],
        "report_json_url": f"/api/runs/{run_id}/report.json",
        "report_md_url": f"/api/runs/{run_id}/report.md",
    }
    status_code = 422 if (req.strict_http and not gate_passed) else 200
    return JSONResponse(content=body, status_code=status_code)


@router.get("/workflows/{workflow_id}/config")
def generate_ci_config(
    workflow_id: str,
    provider: Literal["github", "gitlab"] = Query(default="github"),
    fail_on_severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"] = Query(default="HIGH"),
) -> PlainTextResponse:
    factory = get_session_factory()
    with factory() as session:
        if session.get(WorkflowORM, workflow_id) is None:
            raise HTTPException(status_code=404, detail="Workflow not found")

    if provider == "gitlab":
        yaml_text = f"""security_workflow_gate:
  stage: test
  image: curlimages/curl:latest
  script:
    - |
      curl -fsSL -X POST "${{SECURITY_PLATFORM_URL}}/api/ci/workflows/{workflow_id}/run" \\
        -H "Content-Type: application/json" \\
        -H "X-CI-Token: ${{SECURITY_CI_TOKEN}}" \\
        -d '{{"fail_on_severity": "{fail_on_severity}", "strict_http": true}}'
  rules:
    - if: '$CI_PIPELINE_SOURCE == "merge_request_event" || $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH'
"""
    else:
        yaml_text = f"""name: AI Security Workflow Gate
on:
  push:
    branches: [ main ]
  pull_request:

jobs:
  security-gate:
    runs-on: ubuntu-latest
    steps:
      - name: Run AI Security Workflow
        run: |
          curl -fsSL -X POST "${{{{ secrets.SECURITY_PLATFORM_URL }}}}/api/ci/workflows/{workflow_id}/run" \\
            -H "Content-Type: application/json" \\
            -H "X-CI-Token: ${{{{ secrets.SECURITY_CI_TOKEN }}}}" \\
            -d '{{"fail_on_severity": "{fail_on_severity}", "strict_http": true}}'
"""
    return PlainTextResponse(content=yaml_text, media_type="text/yaml; charset=utf-8")
