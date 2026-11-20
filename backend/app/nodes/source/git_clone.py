from __future__ import annotations

import asyncio
import os
import subprocess
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from app.nodes.base import BaseNode, NodeContext, Port
from app.nodes.registry import register_node
from app.nodes.source._project_root import detect_gradle_project_root, validate_repo_allowlist


def _git_shallow_clone(repo_url: str, target_dir: Path) -> None:
    env = dict(os.environ)
    env["GIT_TERMINAL_PROMPT"] = "0"
    proc = subprocess.run(
        ["git", "clone", "--depth", "1", repo_url, str(target_dir)],
        capture_output=True,
        text=True,
        timeout=60,
        env=env,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"git clone failed ({proc.returncode}): {proc.stderr.strip()[:400]}")


class GitCloneParams(BaseModel):
    repo_url: str = Field(default="https://github.com/TBagirov/training", description="HTTPS Git repository URL from allowlist")
    subdir: str = Field(default="", description="Optional relative subdirectory inside repository")


@register_node
class GitCloneNode(BaseNode):
    type = "source.git_clone"
    label = "Git Clone"
    group = "source"
    description = "Performs shallow clone from allowlisted repository and detects Gradle project root."
    inputs = [Port(name="trigger", kind="Any", required=False, description="Optional trigger input")]
    outputs = [Port(name="workspace", kind="Workspace", description="Cloned project root")]
    Params = GitCloneParams

    async def run(self, ctx: NodeContext, inputs: dict[str, Any], params: BaseModel) -> dict[str, Any]:
        assert isinstance(params, GitCloneParams)
        repo_url = str(ctx.runtime_params.get("repo_url") or params.repo_url).strip()
        subdir = str(ctx.runtime_params.get("subdir") if "subdir" in ctx.runtime_params else params.subdir).strip()
        allowed_url = validate_repo_allowlist(repo_url, ctx.settings.git_clone_allowlist)

        clone_dir = ctx.workspace_dir / "src_git"
        await asyncio.to_thread(_git_shallow_clone, allowed_url, clone_dir)
        project_root = await asyncio.to_thread(detect_gradle_project_root, clone_dir, subdir or None)
        return {
            "workspace": {
                "project_root": str(project_root),
                "clone_root": str(clone_dir),
                "source": allowed_url,
            }
        }
