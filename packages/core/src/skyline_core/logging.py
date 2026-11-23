"""Structured JSON logging with mandatory redaction (CLAUDE.md rule 4, ARCHITECTURE §15).

Every log line, from structlog or from the standard library (uvicorn, SQLAlchemy, Alembic), goes
through :func:`redact_processor` before rendering. Use :func:`get_logger` everywhere; never call
``print`` or configure handlers elsewhere.
"""

from __future__ import annotations

import logging
import sys
import uuid
from collections.abc import MutableMapping
from typing import Any

import structlog
from structlog.typing import EventDict, Processor, WrappedLogger

from skyline_core.redaction import REDACTED, is_sensitive_log_key, redact_for_log

_CORRELATION_KEY = "correlation_id"


def redact_processor(_logger: WrappedLogger, _method: str, event_dict: EventDict) -> EventDict:
    """Mask secret-looking keys and values in a log event (including formatted tracebacks)."""
    for key in list(event_dict):
        if key in {"timestamp", "level", "logger"}:
            continue
        if is_sensitive_log_key(key):
            event_dict[key] = REDACTED
        else:
            event_dict[key] = redact_for_log(event_dict[key])
    return event_dict


def _shared_processors() -> list[Processor]:
    return [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.format_exc_info,
        redact_processor,
    ]


def configure_logging(level: str = "info", *, stream: Any = None) -> None:
    """Configure structlog and the stdlib root logger to emit redacted JSON lines."""
    handler = logging.StreamHandler(stream or sys.stdout)
    handler.setFormatter(
        structlog.stdlib.ProcessorFormatter(
            foreign_pre_chain=_shared_processors(),
            processors=[
                structlog.stdlib.ProcessorFormatter.remove_processors_meta,
                structlog.processors.JSONRenderer(),
            ],
        )
    )
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(level.upper())
    # Access logs would include query strings; the API writes its own sanitised access log.
    logging.getLogger("uvicorn.access").disabled = True
    for noisy in ("asyncio", "sqlalchemy.engine"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    structlog.configure(
        processors=[*_shared_processors(), structlog.stdlib.ProcessorFormatter.wrap_for_formatter],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=False,
    )


def get_logger(name: str) -> structlog.stdlib.BoundLogger:
    """Return a structured logger. Never pass secrets; the processor is a safety net only."""
    logger: structlog.stdlib.BoundLogger = structlog.stdlib.get_logger(name)
    return logger


def new_correlation_id() -> str:
    """A fresh, server-generated correlation ID."""
    return str(uuid.uuid4())


def parse_client_correlation_id(value: str | None) -> str | None:
    """Accept a client ``X-Request-ID`` only if it is a canonical UUID (no log injection)."""
    if not value or len(value) != 36:  # noqa: PLR2004 - canonical UUID length
        return None
    try:
        return str(uuid.UUID(value))
    except ValueError:
        return None


def bind_correlation_id(correlation_id: str) -> None:
    """Attach a correlation ID to every log line in the current context."""
    structlog.contextvars.bind_contextvars(**{_CORRELATION_KEY: correlation_id})


def current_correlation_id() -> str | None:
    """The correlation ID bound to the current context, if any."""
    ctx: MutableMapping[str, Any] = structlog.contextvars.get_contextvars()
    value = ctx.get(_CORRELATION_KEY)
    return value if isinstance(value, str) else None


def clear_context() -> None:
    """Drop all context variables (call at the end of a request or job)."""
    structlog.contextvars.clear_contextvars()
