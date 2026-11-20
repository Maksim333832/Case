from __future__ import annotations

import uuid

from fastapi import APIRouter, HTTPException

from app.config import get_settings
from app.core.crypto import decrypt_secret, encrypt_secret, mask_credential_value
from app.core.db import CredentialORM, get_session_factory
from app.core.masking import register_runtime_secret
from app.core.models import CredentialCreate, CredentialOut

router = APIRouter(prefix="/api", tags=["credentials"])


def register_existing_credentials_for_masking() -> None:
    """Ensure all stored credentials are registered in log/event masking filter at startup."""
    settings = get_settings()
    factory = get_session_factory()
    with factory() as session:
        rows = session.query(CredentialORM).all()
        for row in rows:
            try:
                raw = decrypt_secret(row.encrypted_value, settings=settings)
                register_runtime_secret(raw)
            except Exception:
                pass


def _to_credential_out(row: CredentialORM) -> CredentialOut:
    settings = get_settings()
    try:
        raw = decrypt_secret(row.encrypted_value, settings=settings)
        register_runtime_secret(raw)
        masked = mask_credential_value(raw)
    except Exception:
        masked = "****"
    return CredentialOut(
        id=row.id,
        name=row.name,
        kind=row.kind,
        masked_value=masked,
        created_at=row.created_at,
    )


@router.get("/credentials", response_model=list[CredentialOut])
def list_credentials() -> list[CredentialOut]:
    factory = get_session_factory()
    with factory() as session:
        rows = session.query(CredentialORM).order_by(CredentialORM.created_at.desc()).all()
        return [_to_credential_out(r) for r in rows]


@router.post("/credentials", response_model=CredentialOut, status_code=201)
def create_credential(payload: CredentialCreate) -> CredentialOut:
    settings = get_settings()
    factory = get_session_factory()
    with factory() as session:
        existing = session.query(CredentialORM).filter(CredentialORM.name == payload.name).one_or_none()
        if existing is not None:
            raise HTTPException(status_code=409, detail=f"Credential with name '{payload.name}' already exists")

        register_runtime_secret(payload.value)
        cred_id = f"cred_{uuid.uuid4().hex[:12]}"
        encrypted = encrypt_secret(payload.value, settings=settings)
        row = CredentialORM(
            id=cred_id,
            name=payload.name,
            kind=payload.kind,
            encrypted_value=encrypted,
        )
        session.add(row)
        session.commit()
        session.refresh(row)
        return _to_credential_out(row)


@router.delete("/credentials/{credential_id}", status_code=204)
def delete_credential(credential_id: str) -> None:
    factory = get_session_factory()
    with factory() as session:
        row = session.get(CredentialORM, credential_id)
        if row is None:
            raise HTTPException(status_code=404, detail="Credential not found")
        session.delete(row)
        session.commit()
