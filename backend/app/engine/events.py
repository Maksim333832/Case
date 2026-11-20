from __future__ import annotations

import asyncio
import json
from collections import defaultdict
from typing import Any

from app.core.db import NodeRunORM, RunORM, get_session_factory
from app.core.masking import mask_text
from app.core.models import WorkflowEvent


def _mask_nested(value: Any, extra_secrets: tuple[str, ...] = ()) -> Any:
    if isinstance(value, str):
        return mask_text(value, extra_secrets)
    if isinstance(value, list):
        return [_mask_nested(v, extra_secrets) for v in value]
    if isinstance(value, dict):
        return {k: _mask_nested(v, extra_secrets) for k, v in value.items()}
    return value


class RunEventBroker:
    """In-memory + DB-backed event broker with replay on WebSocket connect."""

    def __init__(self) -> None:
        self._history: dict[str, list[dict[str, Any]]] = defaultdict(list)
        self._subscribers: dict[str, set[asyncio.Queue[dict[str, Any]]]] = defaultdict(set)
        self._lock = asyncio.Lock()

    async def publish(self, event: WorkflowEvent, extra_secrets: tuple[str, ...] = ()) -> None:
        payload = event.model_dump(exclude_none=True)
        payload = _mask_nested(payload, extra_secrets)
        async with self._lock:
            self._history[event.run_id].append(payload)
            queues = list(self._subscribers.get(event.run_id, ()))
        for q in queues:
            await q.put(payload)

    def _load_history_from_db(self, run_id: str) -> list[dict[str, Any]]:
        factory = get_session_factory()
        with factory() as session:
            run = session.get(RunORM, run_id)
            if run is None:
                return []
            events: list[dict[str, Any]] = [
                {
                    "event": "run_started",
                    "run_id": run.id,
                    "status": "running",
                    "started_at": run.started_at.isoformat() if run.started_at else None,
                }
            ]
            node_runs = (
                session.query(NodeRunORM)
                .filter(NodeRunORM.run_id == run_id)
                .order_by(NodeRunORM.id.asc())
                .all()
            )
            for nr in node_runs:
                if nr.status == "pending":
                    continue
                ev_name = {
                    "running": "node_started",
                    "success": "node_finished",
                    "failed": "node_failed",
                    "skipped": "node_skipped",
                }.get(nr.status, "node_finished")
                duration_ms = None
                if nr.started_at and nr.finished_at:
                    duration_ms = int((nr.finished_at - nr.started_at).total_seconds() * 1000)
                preview = json.loads(nr.output_preview_json) if nr.output_preview_json else None
                item: dict[str, Any] = {
                    "event": ev_name,
                    "run_id": run_id,
                    "node_id": nr.node_id,
                    "status": nr.status,
                }
                if nr.started_at:
                    item["started_at"] = nr.started_at.isoformat()
                if nr.finished_at:
                    item["finished_at"] = nr.finished_at.isoformat()
                if duration_ms is not None:
                    item["duration_ms"] = duration_ms
                if preview is not None:
                    item["output_preview"] = preview
                if nr.error:
                    item["error"] = nr.error
                events.append(item)

            if run.finished_at is not None:
                summary = json.loads(run.summary_json) if run.summary_json else None
                fin: dict[str, Any] = {
                    "event": "run_finished",
                    "run_id": run.id,
                    "status": run.status,
                    "finished_at": run.finished_at.isoformat(),
                }
                if summary is not None:
                    fin["summary"] = summary
                events.append(fin)
            return events

    async def subscribe(self, run_id: str) -> tuple[list[dict[str, Any]], asyncio.Queue[dict[str, Any]]]:
        queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue()
        async with self._lock:
            history = list(self._history.get(run_id, []))
            if not history:
                history = self._load_history_from_db(run_id)
            self._subscribers[run_id].add(queue)
        return history, queue

    async def unsubscribe(self, run_id: str, queue: asyncio.Queue[dict[str, Any]]) -> None:
        async with self._lock:
            subs = self._subscribers.get(run_id)
            if subs:
                subs.discard(queue)
                if not subs:
                    self._subscribers.pop(run_id, None)


_BROKER = RunEventBroker()


def get_event_broker() -> RunEventBroker:
    return _BROKER
