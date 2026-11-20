from __future__ import annotations

import base64
import hashlib
import os
from pathlib import Path

from cryptography.fernet import Fernet

from app.config import Settings, get_settings


def _normalize_fernet_key(raw_key: str) -> bytes:
    candidate = raw_key.strip().encode("utf-8")
    try:
        decoded = base64.urlsafe_b64decode(candidate)
        if len(decoded) == 32:
            # Verify Fernet accepts it
            Fernet(candidate)
            return candidate
    except Exception:
        pass
    digest = hashlib.sha256(candidate).digest()
    return base64.urlsafe_b64encode(digest)


def load_or_create_fernet_key(settings: Settings | None = None) -> bytes:
    cfg = settings or get_settings()
    if cfg.app_secret_key.strip():
        return _normalize_fernet_key(cfg.app_secret_key)

    key_file: Path = cfg.secret_key_file
    if key_file.exists():
        raw = key_file.read_text(encoding="utf-8").strip()
        if raw:
            return _normalize_fernet_key(raw)

    key_file.parent.mkdir(parents=True, exist_ok=True)
    new_key = Fernet.generate_key()
    key_file.write_text(new_key.decode("utf-8"), encoding="utf-8")
    try:
        os.chmod(key_file, 0o600)
    except OSError:
        pass
    return new_key


def get_fernet(settings: Settings | None = None) -> Fernet:
    return Fernet(load_or_create_fernet_key(settings))


def encrypt_secret(value: str, settings: Settings | None = None) -> str:
    fernet = get_fernet(settings)
    return fernet.encrypt(value.encode("utf-8")).decode("utf-8")


def decrypt_secret(encrypted_value: str, settings: Settings | None = None) -> str:
    fernet = get_fernet(settings)
    return fernet.decrypt(encrypted_value.encode("utf-8")).decode("utf-8")


def mask_credential_value(value: str) -> str:
    """API credential preview: strictly '****' plus last 2-4 chars (never raw value)."""
    if not value:
        return "****"
    if len(value) >= 10:
        return f"****{value[-4:]}"
    if len(value) >= 6:
        return f"****{value[-2:]}"
    return "****"
