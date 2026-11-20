from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.ci import router as ci_router
from app.api.credentials import register_existing_credentials_for_masking
from app.api.credentials import router as credentials_router
from app.api.node_types import router as node_types_router
from app.api.runs import router as runs_router
from app.api.templates import router as templates_router
from app.api.templates import seed_templates_from_disk
from app.api.uploads import router as uploads_router
from app.api.workflows import router as workflows_router
from app.api.ws import router as ws_router
from app.config import get_settings
from app.core.db import init_db
from app.core.logging import configure_logging
from app.engine.scheduler import get_scheduler
from app.nodes.registry import discover_nodes


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    configure_logging()
    init_db(settings.database_url)
    register_existing_credentials_for_masking()
    discover_nodes()
    seed_templates_from_disk()
    settings.uploads_dir.mkdir(parents=True, exist_ok=True)
    settings.artifacts_dir.mkdir(parents=True, exist_ok=True)
    scheduler = get_scheduler()
    scheduler.start()
    try:
        yield
    finally:
        scheduler.shutdown()


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title=settings.app_name,
        version="0.4.0",
        lifespan=lifespan,
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=False,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.include_router(node_types_router)
    app.include_router(workflows_router)
    app.include_router(templates_router)
    app.include_router(runs_router)
    app.include_router(uploads_router)
    app.include_router(credentials_router)
    app.include_router(ci_router)
    app.include_router(ws_router)

    @app.get("/health", tags=["health"])
    def health() -> dict[str, object]:
        return {
            "status": "ok",
            "app": settings.app_name,
            "use_stub_scanners": settings.use_stub_scanners,
        }

    return app


app = create_app()
