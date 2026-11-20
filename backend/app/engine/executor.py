from __future__ import annotations

import asyncio
import json
import shutil
import uuid
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from app.config import Settings, get_settings
from app.core.crypto import decrypt_secret
from app.core.db import CredentialORM, NodeRunORM, RunORM, get_session_factory
from app.core.logging import sanitize_error_message
from app.core.masking import register_runtime_secret
from app.core.models import Finding, WorkflowEvent, WorkflowGraphModel
from app.core.severity import max_severity, severity_counts
from app.engine.events import get_event_broker
from app.engine.graph import ResolvedEdge, validate_and_sort_graph
from app.nodes.base import NodeContext, build_output_preview
from app.nodes.registry import create_node, get_node_class


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class _EdgeRuntimeState:
    resolved: ResolvedEdge
    active: bool = False
    value: Any = None


async def _resolve_credential_from_db(credential_id: str, settings: Settings) -> str | None:
    factory = get_session_factory()
    with factory() as session:
        cred = session.get(CredentialORM, credential_id)
        if cred is None:
            return None
        decrypted = decrypt_secret(cred.encrypted_value, settings=settings)
        register_runtime_secret(decrypted)
        return decrypted


def create_run_record(workflow_id: str, trigger_type: str, graph: WorkflowGraphModel, run_id: str | None = None) -> str:
    rid = run_id or f"run_{uuid.uuid4().hex[:12]}"
    factory = get_session_factory()
    now = _utcnow()
    with factory() as session:
        run_orm = RunORM(
            id=rid,
            workflow_id=workflow_id,
            status="pending",
            trigger=trigger_type,
            started_at=now,
        )
        session.add(run_orm)
        session.flush()
        for node in graph.nodes:
            session.add(
                NodeRunORM(
                    run_id=rid,
                    node_id=node.id,
                    status="pending",
                )
            )
        session.commit()
    return rid


def _update_run_row(run_id: str, **fields: Any) -> None:
    factory = get_session_factory()
    with factory() as session:
        run = session.get(RunORM, run_id)
        if run is not None:
            for k, v in fields.items():
                setattr(run, k, v)
            session.commit()


def _update_node_run_row(run_id: str, node_id: str, **fields: Any) -> None:
    factory = get_session_factory()
    with factory() as session:
        nr = (
            session.query(NodeRunORM)
            .filter(NodeRunORM.run_id == run_id, NodeRunORM.node_id == node_id)
            .one_or_none()
        )
        if nr is not None:
            for k, v in fields.items():
                setattr(nr, k, v)
            session.commit()


async def execute_workflow(
    workflow_id: str,
    graph: WorkflowGraphModel,
    trigger_type: str = "manual",
    runtime_params: dict[str, Any] | None = None,
    run_id: str | None = None,
    settings: Settings | None = None,
) -> dict[str, Any]:
    cfg = settings or get_settings()
    topo_order, resolved_edges = validate_and_sort_graph(graph)
    rid = run_id or create_run_record(workflow_id, trigger_type, graph)

    broker = get_event_broker()
    workspace_dir = cfg.runs_dir / rid
    artifacts_dir = cfg.artifacts_dir / rid
    workspace_dir.mkdir(parents=True, exist_ok=True)
    artifacts_dir.mkdir(parents=True, exist_ok=True)

    run_started_at = _utcnow()
    _update_run_row(rid, status="running", started_at=run_started_at)
    await broker.publish(
        WorkflowEvent(
            event="run_started",
            run_id=rid,
            status="running",
            started_at=run_started_at.isoformat(),
        )
    )

    ctx = NodeContext(
        run_id=rid,
        workflow_id=workflow_id,
        workspace_dir=workspace_dir,
        artifacts_dir=artifacts_dir,
        settings=cfg,
        trigger_type=trigger_type,
        runtime_params=dict(runtime_params or {}),
        credential_resolver=lambda cid: _resolve_credential_from_db(cid, cfg),
    )

    nodes_by_id = {n.id: n for n in graph.nodes}
    incoming_edges: dict[str, list[_EdgeRuntimeState]] = defaultdict(list)
    outgoing_edges: dict[str, list[_EdgeRuntimeState]] = defaultdict(list)
    for re_edge in resolved_edges:
        st = _EdgeRuntimeState(resolved=re_edge)
        incoming_edges[re_edge.edge.target].append(st)
        outgoing_edges[re_edge.edge.source].append(st)

    node_statuses: dict[str, str] = {}
    final_status = "failed"

    try:
        for node_id in topo_order:
            node_model = nodes_by_id[node_id]
            node_cls = get_node_class(node_model.type)
            in_states = incoming_edges.get(node_id, [])

            # Determine whether node should be skipped based on incoming edge states
            should_skip = False
            node_inputs: dict[str, Any] = {}
            if in_states:
                active_states = [st for st in in_states if st.active]
                if not active_states:
                    should_skip = True
                else:
                    by_port: dict[str, list[Any]] = defaultdict(list)
                    connected_ports: set[str] = set()
                    for st in in_states:
                        connected_ports.add(st.resolved.target_port)
                        if st.active:
                            by_port[st.resolved.target_port].append(st.value)

                    port_defs = {p.name: p for p in node_cls.inputs}
                    for port_name in connected_ports:
                        pdef = port_defs.get(port_name)
                        if pdef and pdef.required and not by_port.get(port_name):
                            should_skip = True
                            break

                    if not should_skip:
                        for port_name, values in by_port.items():
                            pdef = port_defs.get(port_name)
                            if pdef and pdef.multiple:
                                node_inputs[port_name] = values
                            else:
                                node_inputs[port_name] = values[0]

            if should_skip:
                node_statuses[node_id] = "skipped"
                now = _utcnow()
                _update_node_run_row(rid, node_id, status="skipped", started_at=now, finished_at=now)
                await broker.publish(
                    WorkflowEvent(
                        event="node_skipped",
                        run_id=rid,
                        node_id=node_id,
                        status="skipped",
                        started_at=now.isoformat(),
                        finished_at=now.isoformat(),
                        duration_ms=0,
                    ),
                    tuple(ctx.extra_secrets),
                )
                for st in outgoing_edges.get(node_id, []):
                    st.active = False
                continue

            # Execute node
            node_start = _utcnow()
            node_statuses[node_id] = "running"
            _update_node_run_row(rid, node_id, status="running", started_at=node_start)
            await broker.publish(
                WorkflowEvent(
                    event="node_started",
                    run_id=rid,
                    node_id=node_id,
                    status="running",
                    started_at=node_start.isoformat(),
                ),
                tuple(ctx.extra_secrets),
            )

            try:
                node_instance = create_node(node_model.type)
                parsed_params = node_cls.Params.model_validate(node_model.params)
                outputs = await asyncio.wait_for(
                    node_instance.run(ctx, node_inputs, parsed_params),
                    timeout=cfg.node_timeout_seconds,
                )
                if not isinstance(outputs, dict):
                    outputs = {}

                # Update context tracking for findings
                for out_val in outputs.values():
                    if isinstance(out_val, list) and all(isinstance(x, Finding) for x in out_val):
                        ctx.last_findings = list(out_val)
                    elif isinstance(out_val, dict) and isinstance(out_val.get("findings"), list):
                        raw_list = out_val["findings"]
                        if all(isinstance(x, Finding) for x in raw_list):
                            ctx.last_findings = list(raw_list)

                node_end = _utcnow()
                duration_ms = int((node_end - node_start).total_seconds() * 1000)
                preview = build_output_preview(outputs, tuple(ctx.extra_secrets))
                node_statuses[node_id] = "success"
                _update_node_run_row(
                    rid,
                    node_id,
                    status="success",
                    finished_at=node_end,
                    output_preview_json=json.dumps(preview, ensure_ascii=False),
                )
                await broker.publish(
                    WorkflowEvent(
                        event="node_finished",
                        run_id=rid,
                        node_id=node_id,
                        status="success",
                        started_at=node_start.isoformat(),
                        finished_at=node_end.isoformat(),
                        duration_ms=duration_ms,
                        output_preview=preview,
                    ),
                    tuple(ctx.extra_secrets),
                )

                for st in outgoing_edges.get(node_id, []):
                    port_name = st.resolved.source_port
                    if port_name in outputs:
                        st.active = True
                        st.value = outputs[port_name]
                    else:
                        st.active = False
                        st.value = None

            except Exception as exc:
                node_end = _utcnow()
                duration_ms = int((node_end - node_start).total_seconds() * 1000)
                safe_error = sanitize_error_message(
                    f"Timeout after {cfg.node_timeout_seconds}s" if isinstance(exc, asyncio.TimeoutError) else exc,
                    tuple(ctx.extra_secrets),
                )
                node_statuses[node_id] = "failed"
                _update_node_run_row(
                    rid,
                    node_id,
                    status="failed",
                    finished_at=node_end,
                    error=safe_error,
                )
                await broker.publish(
                    WorkflowEvent(
                        event="node_failed",
                        run_id=rid,
                        node_id=node_id,
                        status="failed",
                        started_at=node_start.isoformat(),
                        finished_at=node_end.isoformat(),
                        duration_ms=duration_ms,
                        error=safe_error,
                    ),
                    tuple(ctx.extra_secrets),
                )
                for st in outgoing_edges.get(node_id, []):
                    st.active = False
                    st.value = None

        # Compute overall run status
        failed_count = sum(1 for s in node_statuses.values() if s == "failed")
        non_trigger_success = sum(
            1
            for nid, s in node_statuses.items()
            if s == "success" and get_node_class(nodes_by_id[nid].type).group != "trigger"
        )
        if failed_count == 0:
            final_status = "success"
        elif non_trigger_success > 0:
            final_status = "partial"
        else:
            final_status = "failed"

        by_category: dict[str, int] = {}
        for f in ctx.last_findings:
            by_category[f.category] = by_category.get(f.category, 0) + 1

        summary: dict[str, Any] = {
            "status": final_status,
            "nodes": {
                "total": len(node_statuses),
                "success": sum(1 for s in node_statuses.values() if s == "success"),
                "failed": failed_count,
                "skipped": sum(1 for s in node_statuses.values() if s == "skipped"),
            },
            "findings": {
                "count": len(ctx.last_findings),
                "max_severity": max_severity(ctx.last_findings),
                "by_severity": severity_counts(ctx.last_findings),
                "by_category": by_category,
            },
            "reports": {fmt: p.name for fmt, p in ctx.report_files.items()},
        }

        # Persist submission JSON & findings snapshot for run details API
        if ctx.last_findings and "json" not in ctx.report_files:
            # Ensure findings snapshot exists even if no export node ran
            snapshot_path = artifacts_dir / "findings_snapshot.json"
            snapshot_path.write_text(
                json.dumps({"findings": [f.to_submission() for f in ctx.last_findings]}, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )

        run_finished_at = _utcnow()
        _update_run_row(
            rid,
            status=final_status,
            finished_at=run_finished_at,
            summary_json=json.dumps(summary, ensure_ascii=False),
            ai_report_json=json.dumps(ctx.ai_report, ensure_ascii=False) if ctx.ai_report else None,
        )
        await broker.publish(
            WorkflowEvent(
                event="run_finished",
                run_id=rid,
                status=final_status,
                finished_at=run_finished_at.isoformat(),
                summary=summary,
            ),
            tuple(ctx.extra_secrets),
        )
        return {
            "run_id": rid,
            "status": final_status,
            "summary": summary,
            "ai_report": ctx.ai_report,
            "findings": [f.to_submission() for f in ctx.last_findings],
        }
    finally:
        if workspace_dir.exists() and (final_status == "success" or not cfg.keep_failed_run_workspaces):
            shutil.rmtree(workspace_dir, ignore_errors=True)
