from __future__ import annotations

import os
from pathlib import Path

from app.config import Settings, reload_settings
from tools.demo import run_demo


def test_default_config_never_enables_stub_scanners():
    old = os.environ.pop("USE_STUB_SCANNERS", None)
    try:
        cfg = Settings(_env_file=None)
        assert cfg.use_stub_scanners is False
    finally:
        if old is not None:
            os.environ["USE_STUB_SCANNERS"] = old
        reload_settings()


def test_demo_script_passes_with_explicit_dev_stubs(monkeypatch):
    for key in ("USE_STUB_SCANNERS", "DATABASE_URL", "UPLOADS_DIR", "ARTIFACTS_DIR", "RUNS_DIR"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("LLM_API_KEY", "")
    try:
        rc = run_demo(
            Path("/home/user/training/training-project"),
            Path("/home/user/training/ground-truth/training-findings.json"),
            use_stubs=True,
        )
        assert rc == 0
    finally:
        for key in ("USE_STUB_SCANNERS", "DATABASE_URL", "UPLOADS_DIR", "ARTIFACTS_DIR", "RUNS_DIR"):
            os.environ.pop(key, None)
        reload_settings()
