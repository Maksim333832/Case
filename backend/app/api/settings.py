from __future__ import annotations

from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.config import get_settings
from app.core.crypto import decrypt_secret, encrypt_secret, mask_credential_value
from app.core.db import AppSettingORM, get_session_factory
from app.core.masking import register_runtime_secret

router = APIRouter(prefix="/api", tags=["settings"])

_KEY_BASE_URL = "llm_base_url"
_KEY_MODEL = "llm_model"
_KEY_API_KEY = "llm_api_key"


class LlmSettingsOut(BaseModel):
    base_url: str
    model: str
    has_api_key: bool
    masked_api_key: str
    source: str


class LlmSettingsUpdate(BaseModel):
    base_url: str = Field(min_length=1, max_length=500)
    model: str = Field(min_length=1, max_length=200)
    api_key: str | None = Field(default=None, description="New API key (omit or empty to keep existing)")
    clear_api_key: bool = Field(default=False, description="Clear stored custom API key")


def resolve_effective_llm_config() -> tuple[str, str, str, str]:
    """Return (base_url, model, api_key, source)."""
    settings = get_settings()
    base_url = settings.llm_base_url
    model = settings.llm_model
    api_key = settings.llm_api_key.strip()
    source = "env"

    factory = get_session_factory()
    with factory() as session:
        rows = {
            r.key: r
            for r in session.query(AppSettingORM)
            .filter(AppSettingORM.key.in_([_KEY_BASE_URL, _KEY_MODEL, _KEY_API_KEY]))
            .all()
        }
        if _KEY_BASE_URL in rows and rows[_KEY_BASE_URL].value.strip():
            base_url = rows[_KEY_BASE_URL].value.strip()
            source = "database"
        if _KEY_MODEL in rows and rows[_KEY_MODEL].value.strip():
            model = rows[_KEY_MODEL].value.strip()
            source = "database"
        if _KEY_API_KEY in rows:
            enc = rows[_KEY_API_KEY].value
            if enc:
                try:
                    api_key = decrypt_secret(enc, settings=settings).strip()
                    if api_key:
                        register_runtime_secret(api_key)
                    source = "database"
                except Exception:
                    pass
            elif rows[_KEY_API_KEY].value == "":
                # Explicit clear stored in DB
                api_key = ""
                source = "database"

    if api_key:
        register_runtime_secret(api_key)
    return base_url, model, api_key, source


@router.get("/settings/llm", response_model=LlmSettingsOut)
def get_llm_settings() -> LlmSettingsOut:
    base_url, model, api_key, source = resolve_effective_llm_config()
    return LlmSettingsOut(
        base_url=base_url,
        model=model,
        has_api_key=bool(api_key),
        masked_api_key=mask_credential_value(api_key) if api_key else "",
        source=source,
    )


@router.put("/settings/llm", response_model=LlmSettingsOut)
def update_llm_settings(payload: LlmSettingsUpdate) -> LlmSettingsOut:
    settings = get_settings()
    factory = get_session_factory()
    with factory() as session:
        for k, v, is_sec in (
            (_KEY_BASE_URL, payload.base_url.strip(), False),
            (_KEY_MODEL, payload.model.strip(), False),
        ):
            row = session.get(AppSettingORM, k)
            if row is None:
                session.add(AppSettingORM(key=k, value=v, is_secret=is_sec))
            else:
                row.value = v

        if payload.clear_api_key:
            row = session.get(AppSettingORM, _KEY_API_KEY)
            if row is None:
                session.add(AppSettingORM(key=_KEY_API_KEY, value="", is_secret=True))
            else:
                row.value = ""
        elif payload.api_key is not None and payload.api_key.strip():
            raw_key = payload.api_key.strip()
            register_runtime_secret(raw_key)
            enc = encrypt_secret(raw_key, settings=settings)
            row = session.get(AppSettingORM, _KEY_API_KEY)
            if row is None:
                session.add(AppSettingORM(key=_KEY_API_KEY, value=enc, is_secret=True))
            else:
                row.value = enc
                row.is_secret = True

        session.commit()

    return get_llm_settings()
