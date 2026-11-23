from __future__ import annotations

import io
import json
import logging
import secrets
import uuid
from collections.abc import Iterator

import pytest

from skyline_core.logging import (
    bind_correlation_id,
    clear_context,
    configure_logging,
    current_correlation_id,
    get_logger,
    new_correlation_id,
    parse_client_correlation_id,
)

FAKE_AWS_KEY_ID = "AKIA" + "Z" * 16


@pytest.fixture
def log_stream() -> Iterator[io.StringIO]:
    stream = io.StringIO()
    configure_logging("debug", stream=stream)
    yield stream
    clear_context()
    logging.getLogger().handlers.clear()


def _lines(stream: io.StringIO) -> list[dict[str, object]]:
    return [json.loads(line) for line in stream.getvalue().splitlines() if line]


def test_structlog_output_is_json_and_redacted(log_stream: io.StringIO) -> None:
    secret = secrets.token_hex(8)
    bind_correlation_id("c0ffee00-0000-4000-8000-000000000000")
    get_logger("test").info("login", password=secret, note=f"key {FAKE_AWS_KEY_ID}", user="bob")
    (line,) = _lines(log_stream)
    assert line["event"] == "login"
    assert line["password"] == "[REDACTED]"
    assert FAKE_AWS_KEY_ID not in json.dumps(line)
    assert line["user"] == "bob"
    assert line["correlation_id"] == "c0ffee00-0000-4000-8000-000000000000"
    assert secret not in log_stream.getvalue()


def test_exceptions_are_redacted(log_stream: io.StringIO) -> None:
    secret = secrets.token_hex(8)
    try:
        raise RuntimeError(f"connect failed password={secret}")
    except RuntimeError:
        get_logger("test").exception("boom")
    assert secret not in log_stream.getvalue()
    assert "RuntimeError" in log_stream.getvalue()


def test_stdlib_loggers_are_redacted(log_stream: io.StringIO) -> None:
    logging.getLogger("thirdparty").warning("Bearer %s", secrets.token_urlsafe(24))
    (line,) = _lines(log_stream)
    assert "[REDACTED]" in str(line["event"])
    assert line["logger"] == "thirdparty"


def test_uvicorn_access_log_is_disabled(log_stream: io.StringIO) -> None:
    logging.getLogger("uvicorn.access").info('"GET /x?token=abc HTTP/1.1" 200')
    assert log_stream.getvalue() == ""


def test_correlation_id_helpers() -> None:
    clear_context()
    assert current_correlation_id() is None
    cid = new_correlation_id()
    bind_correlation_id(cid)
    assert current_correlation_id() == cid
    clear_context()


@pytest.mark.parametrize(
    "value",
    [None, "", "not-a-uuid", "x" * 36, "c0ffee00-0000-4000-8000-000000000000\nfake=1"],
)
def test_client_correlation_ids_must_be_uuids(value: str | None) -> None:
    assert parse_client_correlation_id(value) is None


def test_client_correlation_id_accepted_when_uuid() -> None:
    value = str(uuid.uuid4())
    assert parse_client_correlation_id(value.upper()) == value
