from __future__ import annotations

import asyncio
import logging
from typing import Any

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger

from app.core.db import WorkflowORM, get_session_factory
from app.core.models import WorkflowGraphModel, WorkflowOut
from app.engine.executor import create_run_record, execute_workflow

logger = logging.getLogger(__name__)


class WorkflowScheduler:
    def __init__(self) -> None:
        self._scheduler = AsyncIOScheduler(timezone="UTC")
        self._started = False
        self._tasks: set[asyncio.Task[Any]] = set()

    def start(self) -> None:
        if not self._started:
            self._scheduler.start()
            self._started = True
        self.sync_from_db()

    def shutdown(self) -> None:
        if self._started:
            self._scheduler.shutdown(wait=False)
            self._started = False

    def sync_from_db(self) -> None:
        factory = get_session_factory()
        with factory() as session:
            rows = session.query(WorkflowORM).filter(WorkflowORM.is_template.is_(False)).all()
            for row in rows:
                try:
                    graph = WorkflowGraphModel.model_validate_json(row.graph_json)
                    wf = WorkflowOut(
                        id=row.id,
                        name=row.name,
                        description=row.description,
                        graph=graph,
                        is_template=row.is_template,
                        created_at=row.created_at,
                        updated_at=row.updated_at,
                    )
                    self.sync_workflow(wf)
                except Exception as exc:
                    logger.warning("Failed to restore schedule for workflow %s: %s", row.id, exc)

    def remove_workflow(self, workflow_id: str) -> None:
        prefix = f"wf_sched:{workflow_id}:"
        for job in list(self._scheduler.get_jobs()):
            if job.id.startswith(prefix):
                self._scheduler.remove_job(job.id)

    def sync_workflow(self, workflow: WorkflowOut) -> None:
        self.remove_workflow(workflow.id)
        if workflow.is_template or not self._started:
            return

        for node in workflow.graph.nodes:
            if node.type != "trigger.schedule":
                continue
            params = node.params or {}
            if not params.get("enabled", True):
                continue

            mode = str(params.get("mode", "cron"))
            job_id = f"wf_sched:{workflow.id}:{node.id}"
            try:
                if mode == "interval":
                    seconds = int(params.get("interval_seconds", 3600))
                    trigger = IntervalTrigger(seconds=max(10, seconds))
                else:
                    cron_expr = str(params.get("cron", "0 14 * * *")).strip()
                    trigger = CronTrigger.from_crontab(cron_expr)

                self._scheduler.add_job(
                    self._trigger_job,
                    trigger=trigger,
                    id=job_id,
                    replace_existing=True,
                    kwargs={"workflow_id": workflow.id},
                )
            except Exception as exc:
                logger.warning("Invalid schedule config on %s.%s: %s", workflow.id, node.id, exc)

    async def _trigger_job(self, workflow_id: str) -> None:
        factory = get_session_factory()
        with factory() as session:
            row = session.get(WorkflowORM, workflow_id)
            if row is None or row.is_template:
                return
            graph = WorkflowGraphModel.model_validate_json(row.graph_json)

        run_id = create_run_record(workflow_id, "schedule", graph)
        task = asyncio.create_task(
            execute_workflow(
                workflow_id=workflow_id,
                graph=graph,
                trigger_type="schedule",
                runtime_params={},
                run_id=run_id,
            )
        )
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    def list_job_ids(self) -> list[str]:
        return [j.id for j in self._scheduler.get_jobs()]


_SCHEDULER = WorkflowScheduler()


def get_scheduler() -> WorkflowScheduler:
    return _SCHEDULER
