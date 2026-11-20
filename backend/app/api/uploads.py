from __future__ import annotations

import uuid
from pathlib import Path

from fastapi import APIRouter, File, HTTPException, UploadFile

from app.config import get_settings
from app.core.db import UploadORM, get_session_factory
from app.core.models import UploadOut

router = APIRouter(prefix="/api", tags=["uploads"])


@router.post("/uploads", response_model=UploadOut, status_code=201)
async def upload_zip(file: UploadFile = File(...)) -> UploadOut:
    settings = get_settings()
    filename = Path(file.filename or "upload.zip").name
    if not filename.lower().endswith(".zip"):
        raise HTTPException(status_code=400, detail="Only .zip archives are accepted")

    content = await file.read()
    if not content:
        raise HTTPException(status_code=400, detail="Uploaded file is empty")
    if len(content) > settings.max_zip_size_bytes:
        raise HTTPException(
            status_code=413,
            detail=f"ZIP archive exceeds maximum allowed size ({settings.max_zip_size_bytes} bytes)",
        )

    upload_id = f"up_{uuid.uuid4().hex[:12]}"
    settings.uploads_dir.mkdir(parents=True, exist_ok=True)
    storage_path = settings.uploads_dir / f"{upload_id}.zip"
    storage_path.write_bytes(content)

    factory = get_session_factory()
    with factory() as session:
        rec = UploadORM(
            id=upload_id,
            filename=filename,
            storage_path=str(storage_path),
            size_bytes=len(content),
        )
        session.add(rec)
        session.commit()
        session.refresh(rec)

    return UploadOut(
        upload_id=rec.id,
        filename=rec.filename,
        size_bytes=rec.size_bytes,
        created_at=rec.created_at,
    )
