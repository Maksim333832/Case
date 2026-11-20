from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

BACKEND_ROOT = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=str(BACKEND_ROOT / ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_name: str = "AI Security Workflow"
    database_url: str = f"sqlite:///{(BACKEND_ROOT / 'data' / 'workflow.db').as_posix()}"
    uploads_dir: Path = BACKEND_ROOT / "data" / "uploads"
    artifacts_dir: Path = BACKEND_ROOT / "data" / "runs"
    templates_dir: Path = BACKEND_ROOT / "templates"
    runs_dir: Path = Path("/tmp/runs")
    keep_failed_run_workspaces: bool = False
    node_timeout_seconds: int = 120

    # Secret encryption key; auto-generated outside repository if empty
    app_secret_key: str = ""
    secret_key_file: Path = Path.home() / ".ai_security_workflow_secret.key"

    # Scanners: stubs are STRICTLY disabled by default (USE_STUB_SCANNERS=1 for dev only)
    use_stub_scanners: bool = False
    vuln_db_path: Path = BACKEND_ROOT / "data" / "vulnerabilities.json"
    scanner_secrets_impl: str = ""
    scanner_sca_impl: str = ""
    scanner_sast_impl: str = ""

    # Git clone allowlist
    git_clone_allowlist: list[str] = Field(
        default_factory=lambda: ["https://github.com/TBagirov/training"]
    )

    # Zip safety limits
    max_zip_size_bytes: int = 50 * 1024 * 1024
    max_zip_files: int = 2000

    # LLM OpenAI-compatible configuration
    llm_base_url: str = "https://generativelanguage.googleapis.com/v1beta/openai"
    llm_model: str = "gemini-3.5-flash-lite"
    llm_api_key: str = ""
    llm_timeout_seconds: float = 30.0

    # Optional CI endpoint protection token
    ci_api_token: str = ""

    @field_validator("git_clone_allowlist", mode="before")
    @classmethod
    def _parse_allowlist(cls, v: Any) -> list[str]:
        if isinstance(v, str):
            raw = v.strip()
            if raw.startswith("["):
                import json

                parsed = json.loads(raw)
                return [str(x).strip() for x in parsed if str(x).strip()]
            return [item.strip() for item in raw.split(",") if item.strip()]
        return list(v)

    @field_validator("uploads_dir", "artifacts_dir", "templates_dir", "vuln_db_path", mode="before")
    @classmethod
    def _resolve_backend_relative(cls, v: Any) -> Path:
        p = Path(v)
        if not p.is_absolute():
            return (BACKEND_ROOT / p).resolve()
        return p


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()


def reload_settings() -> Settings:
    get_settings.cache_clear()
    return get_settings()
