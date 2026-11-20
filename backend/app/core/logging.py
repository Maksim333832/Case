from __future__ import annotations

import logging
from typing import Any

from app.core.masking import mask_text


class SecretMaskingFilter(logging.Filter):
    """Logging filter that strips registered credentials and known secret token patterns."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            rendered = record.getMessage()
            masked = mask_text(rendered)
            if masked != rendered:
                record.msg = masked
                record.args = ()
            if record.exc_info and record.exc_info[1] is not None:
                err_str = str(record.exc_info[1])
                masked_err = mask_text(err_str)
                if masked_err != err_str:
                    record.msg = f"{record.msg} [exc: {masked_err}]"
                    record.exc_info = None
                    record.exc_text = None
        except Exception:
            pass
        return True


def configure_logging(level: int = logging.INFO) -> None:
    root = logging.getLogger()
    if not root.handlers:
        logging.basicConfig(
            level=level,
            format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
        )
    else:
        root.setLevel(level)

    filt = SecretMaskingFilter()
    for logger_name in ("", "uvicorn", "uvicorn.error", "uvicorn.access", "httpx", "apscheduler"):
        logger = logging.getLogger(logger_name)
        if not any(isinstance(f, SecretMaskingFilter) for f in logger.filters):
            logger.addFilter(filt)
        for handler in logger.handlers:
            if not any(isinstance(f, SecretMaskingFilter) for f in handler.filters):
                handler.addFilter(filt)


def sanitize_error_message(exc: BaseException | str, extra_secrets: tuple[str, ...] = ()) -> str:
    return mask_text(str(exc), extra_secrets=extra_secrets)
