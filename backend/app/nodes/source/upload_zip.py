from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from app.core.db import UploadORM, get_session_factory
from app.nodes.base import BaseNode, NodeContext, Port
from app.nodes.registry import register_node
from app.nodes.source._project_root import detect_gradle_project_root, safe_extract_zip


class UploadZipParams(BaseModel):
    upload_id: str = Field(default="", description="Uploaded ZIP identifier from /api/uploads")
    subdir: str = Field(default="", description="Optional relative subdirectory inside archive")


@register_node
class UploadZipNode(BaseNode):
    type = "source.upload_zip"
    label = "Upload ZIP"
    group = "source"
    description = "Safely extracts an uploaded ZIP archive and auto-detects the Gradle project root."
    inputs = [Port(name="trigger", kind="Any", required=False, description="Optional trigger input")]
    outputs = [Port(name="workspace", kind="Workspace", description="Extracted project root")]
    Params = UploadZipParams

    async def run(self, ctx: NodeContext, inputs: dict[str, Any], params: BaseModel) -> dict[str, Any]:
        assert isinstance(params, UploadZipParams)
        upload_id = str(ctx.runtime_params.get("upload_id") or params.upload_id).strip()
        subdir = str(ctx.runtime_params.get("subdir") if "subdir" in ctx.runtime_params else params.subdir).strip()
        if not upload_id:
            raise ValueError("source.upload_zip requires 'upload_id'")

        factory = get_session_factory()
        with factory() as session:
            rec = session.get(UploadORM, upload_id)
            if rec is None:
                raise FileNotFoundError(f"Upload '{upload_id}' not found")
            zip_path = Path(rec.storage_path)

        if not zip_path.is_file():
            raise FileNotFoundError(f"Uploaded archive missing on disk for '{upload_id}'")

        extract_dir = ctx.workspace_dir / "src_zip"
        await asyncio.to_thread(
            safe_extract_zip,
            zip_path,
            extract_dir,
            ctx.settings.max_zip_files,
            ctx.settings.max_zip_size_bytes,
        )
        project_root = await asyncio.to_thread(detect_gradle_project_root, extract_dir, subdir or None)
        return {
            "workspace": {
                "project_root": str(project_root),
                "extract_root": str(extract_dir),
                "source": f"upload:{upload_id}",
            }
        }
