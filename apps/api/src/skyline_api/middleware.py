"""Pure ASGI middleware: correlation IDs and access log, security headers, body-size cap and
the Origin / Sec-Fetch-Site guard for unsafe methods (ADR-0008)."""

from __future__ import annotations

import contextlib
import json
import time
from collections.abc import Iterable
from typing import Final

from starlette.datastructures import Headers, MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from skyline_api.errors import error_body
from skyline_core.logging import (
    bind_correlation_id,
    clear_context,
    get_logger,
    new_correlation_id,
    parse_client_correlation_id,
)

_log = get_logger("skyline.api.access")

SAFE_METHODS: Final = frozenset({"GET", "HEAD", "OPTIONS"})


async def _send_error(send: Send, status: int, code: str, message: str) -> None:
    body = json.dumps(error_body(code, message)).encode()
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode()),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})


class RequestContextMiddleware:
    """A server-generated correlation ID per request, the sanitised access log (method, path
    without query string, status, duration) and the last-resort 500.

    The correlation ID is never taken from the client: it ends up in the audit log, where a
    chosen or colliding ID would muddle forensics. A client ``X-Request-ID`` (UUIDs only) is
    logged next to it as ``client_request_id``.

    Unhandled errors are caught here, *inside* the security-headers middleware and while
    the correlation ID is still bound, so even a 500 carries the headers, ``X-Request-ID``
    and a correlation ID the user can quote.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        client_request_id = parse_client_correlation_id(Headers(scope=scope).get("x-request-id"))
        correlation_id = new_correlation_id()
        bind_correlation_id(correlation_id)
        started = time.perf_counter()
        status = 500
        response_started = False

        async def send_wrapper(message: Message) -> None:
            nonlocal status, response_started
            if message["type"] == "http.response.start":
                status, response_started = message["status"], True
                MutableHeaders(scope=message).append("X-Request-ID", correlation_id)
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        except Exception as exc:
            _log.exception("unhandled_error", error_type=type(exc).__name__)
            if response_started:
                raise  # too late for a clean error response
            await _send_error(
                send_wrapper,
                500,
                "internal_error",
                "Something went wrong. Quote the correlation ID.",
            )
        finally:
            _log.info(
                "request",
                method=scope["method"],
                path=scope["path"][:200],
                status=status,
                duration_ms=round((time.perf_counter() - started) * 1000, 1),
                client_request_id=client_request_id,
            )
            clear_context()


class SecurityHeadersMiddleware:
    """Headers on every response. The API only ever returns JSON, so its CSP denies all."""

    def __init__(self, app: ASGIApp, *, hsts: bool) -> None:
        self.app = app
        self.headers: list[tuple[str, str]] = [
            ("Cache-Control", "no-store"),
            ("X-Content-Type-Options", "nosniff"),
            ("Referrer-Policy", "no-referrer"),
            ("X-Frame-Options", "DENY"),
            ("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'"),
            ("Cross-Origin-Resource-Policy", "same-origin"),
            ("Permissions-Policy", "camera=(), microphone=(), geolocation=()"),
        ]
        if hsts:
            self.headers.append(
                ("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
            )

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                for name, value in self.headers:
                    headers[name] = value
                if "server" in headers:
                    del headers["server"]
            await send(message)

        await self.app(scope, receive, send_wrapper)


class _BodyTooLargeError(Exception):
    pass


class BodySizeLimitMiddleware:
    """Reject request bodies over ``max_bytes`` (by Content-Length and while streaming)."""

    def __init__(self, app: ASGIApp, *, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        length = Headers(scope=scope).get("content-length")
        if length is not None and (not length.isdigit() or int(length) > self.max_bytes):
            await _send_error(send, 413, "payload_too_large", "The request body is too large")
            return
        received = 0
        too_large = False

        async def receive_wrapper() -> Message:
            nonlocal received, too_large
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_bytes:
                    too_large = True
                    raise _BodyTooLargeError
            return message

        started = False

        async def send_wrapper(message: Message) -> None:
            nonlocal started
            if too_large and not started:
                return  # the framework turned our error into its own 400: replace it below
            started = started or message["type"] == "http.response.start"
            await send(message)

        with contextlib.suppress(_BodyTooLargeError):
            await self.app(scope, receive_wrapper, send_wrapper)
        if too_large and not started:
            await _send_error(send, 413, "payload_too_large", "The request body is too large")


class OriginGuardMiddleware:
    """For unsafe methods: the ``Origin`` header must be the public origin, and requests the
    browser labels ``Sec-Fetch-Site: cross-site`` or ``same-site`` are refused. This blocks
    CSRF (including login CSRF) even before the CSRF token is checked."""

    def __init__(
        self, app: ASGIApp, *, allowed_origin: str, exempt_paths: Iterable[str] = ()
    ) -> None:
        self.app = app
        self.allowed_origin = allowed_origin
        self.exempt_paths = frozenset(exempt_paths)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if (
            scope["type"] != "http"
            or scope["method"] in SAFE_METHODS
            or scope["path"] in self.exempt_paths
        ):
            await self.app(scope, receive, send)
            return
        headers = Headers(scope=scope)
        fetch_site = headers.get("sec-fetch-site")
        if headers.get("origin") != self.allowed_origin or (
            fetch_site is not None and fetch_site not in {"same-origin", "none"}
        ):
            await _send_error(send, 403, "forbidden", "Cross-origin requests are not allowed")
            return
        await self.app(scope, receive, send)
