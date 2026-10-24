"""Logging that must not retain email bodies, secrets, or personal data."""

import logging
import re

from app.core.config import get_settings

LOGGER_NAME = "phishcatch"

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_URL_RE = re.compile(r"(?i)\b(?:https?|hxxps?)://\S+")
_SECRET_RE = re.compile(
    r"(?i)\b(api[_-]?key|authorization|bearer|token|password|secret)\b\s*[:=]\s*\S+"
)


class RedactFilter(logging.Filter):
    """Last-line defense. Call sites still must not log message content."""

    def filter(self, record: logging.LogRecord) -> bool:
        message = record.getMessage()
        redacted = _SECRET_RE.sub(r"\1=[redacted]", message)
        redacted = _EMAIL_RE.sub("[redacted-email]", redacted)
        redacted = _URL_RE.sub("[redacted-url]", redacted)
        if len(redacted) > 300:
            redacted = redacted[:300] + "...[truncated]"
        record.msg = redacted
        record.args = ()
        return True


def get_logger() -> logging.Logger:
    return logging.getLogger(LOGGER_NAME)


def setup_logging() -> None:
    level_name = get_settings().log_level.upper()
    level = getattr(logging, level_name, logging.INFO)
    logger = logging.getLogger(LOGGER_NAME)
    logger.setLevel(level)
    logger.propagate = True
    if not any(isinstance(item, RedactFilter) for item in logger.filters):
        logger.addFilter(RedactFilter())
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(
            logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s")
        )
        handler.addFilter(RedactFilter())
        logger.addHandler(handler)
