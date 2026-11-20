from __future__ import annotations

import re
import threading
from typing import Iterable

_RUNTIME_SECRETS_LOCK = threading.RLock()
_RUNTIME_SECRETS: set[str] = set()

_TOKEN_PATTERNS: tuple[re.Pattern[str], ...] = (
    # Telegram bot token: 8-12 digits : 20+ chars
    re.compile(r"\b\d{8,12}:[A-Za-z0-9_-]{20,}\b"),
    # Google / Gemini keys
    re.compile(r"\bAQ\.Ab[A-Za-z0-9_.-]{16,}\b"),
    re.compile(r"\bAIza[0-9A-Za-z_-]{20,}\b"),
    # Generic bearer tokens (require at least one digit, '.', '_', '-', or non-title mixed case)
    re.compile(r"(?i)\bBearer\s+(?=[A-Za-z0-9._-]*[0-9._-])[A-Za-z0-9._-]{8,}\b"),
    # Training / demo secrets
    re.compile(r"\bcg26_[A-Za-z0-9_]{6,}\b"),
    # Common cloud / Git / OpenAI tokens
    re.compile(r"\b(?:sk|pk|ghp|gho|ghu|ghs|glpat)-[A-Za-z0-9_-]{12,}\b"),
)

_SENSITIVE_ASSIGNMENT_RE = re.compile(
    r"""(?ix)
    \b(password|passwd|pwd|api[_-]?key|secret|token|authorization)\b
    (\s*[:=]\s*)(["'])(?!\*{4}|YOUR_|<|\$\{)([^"'\r\n]{6,})(\3)
    """
)


def register_runtime_secret(secret: str) -> None:
    if secret and len(secret) >= 4:
        with _RUNTIME_SECRETS_LOCK:
            _RUNTIME_SECRETS.add(secret)


def unregister_runtime_secret(secret: str) -> None:
    if secret:
        with _RUNTIME_SECRETS_LOCK:
            _RUNTIME_SECRETS.discard(secret)


def clear_runtime_secrets() -> None:
    with _RUNTIME_SECRETS_LOCK:
        _RUNTIME_SECRETS.clear()


def get_runtime_secrets() -> tuple[str, ...]:
    with _RUNTIME_SECRETS_LOCK:
        return tuple(sorted(_RUNTIME_SECRETS, key=len, reverse=True))


def mask_secret(value: str, prefix: int = 4, suffix: int = 2) -> str:
    if not value:
        return ""
    if len(value) <= 6:
        return "****"
    if len(value) <= prefix + suffix + 3:
        return f"{value[:2]}****{value[-2:]}"
    return f"{value[:prefix]}****{value[-suffix:]}"


def mask_text(text: str, extra_secrets: Iterable[str] = ()) -> str:
    if not text:
        return text

    masked = text
    secrets_to_mask = list(get_runtime_secrets())
    for item in extra_secrets:
        if item and len(item) >= 4:
            secrets_to_mask.append(item)

    # Replace longest first to avoid partial prefix masking leaks
    for secret in sorted(set(secrets_to_mask), key=len, reverse=True):
        if secret in masked:
            masked = masked.replace(secret, mask_secret(secret))

    for pattern in _TOKEN_PATTERNS:
        def _repl(match: re.Match[str]) -> str:
            raw = match.group(0)
            if raw.lower().startswith("bearer "):
                token_part = raw.split(None, 1)[1]
                return f"Bearer {mask_secret(token_part)}"
            return mask_secret(raw)

        masked = pattern.sub(_repl, masked)

    def _assign_repl(match: re.Match[str]) -> str:
        key, sep, quote, val, end_quote = match.groups()
        return f"{key}{sep}{quote}{mask_secret(val)}{end_quote}"

    masked = _SENSITIVE_ASSIGNMENT_RE.sub(_assign_repl, masked)
    return masked


def contains_raw_secret(text: str, extra_secrets: Iterable[str] = ()) -> bool:
    if not text:
        return False
    for secret in list(get_runtime_secrets()) + [s for s in extra_secrets if s and len(s) >= 4]:
        if secret in text:
            return True
    for pattern in _TOKEN_PATTERNS:
        for match in pattern.finditer(text):
            raw = match.group(0)
            if "****" not in raw:
                return True
    for match in _SENSITIVE_ASSIGNMENT_RE.finditer(text):
        if "****" not in match.group(4):
            return True
    return False
