"""One error shape for every response: ``{"error": {code, message, correlation_id}}``.

Messages are generic. Stack traces, SQL and internal paths never reach a client; details go
to the (redacted) logs with the same correlation ID.
"""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from skyline_core.logging import current_correlation_id, get_logger

_log = get_logger(__name__)

_STATUS_CODES = {
    400: "bad_request",
    401: "unauthenticated",
    403: "forbidden",
    404: "not_found",
    405: "method_not_allowed",
    409: "conflict",
    413: "payload_too_large",
    415: "unsupported_media_type",
    422: "validation_error",
    429: "too_many_requests",
}


class ApiError(Exception):
    """An expected error with a safe, user-facing message."""

    def __init__(
        self,
        status: int,
        code: str,
        message: str,
        *,
        headers: dict[str, str] | None = None,
    ) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message
        self.headers = headers or {}


def error_body(code: str, message: str, **extra: Any) -> dict[str, Any]:
    return {
        "error": {
            "code": code,
            "message": message,
            "correlation_id": current_correlation_id(),
            **extra,
        }
    }


def not_found(what: str = "resource") -> ApiError:
    return ApiError(404, "not_found", f"The {what} was not found")


def install_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(ApiError)
    async def _api_error(_request: Request, exc: ApiError) -> JSONResponse:
        return JSONResponse(
            error_body(exc.code, exc.message), status_code=exc.status, headers=exc.headers
        )

    @app.exception_handler(StarletteHTTPException)
    async def _http_error(_request: Request, exc: StarletteHTTPException) -> JSONResponse:
        code = _STATUS_CODES.get(exc.status_code, "error")
        message = "The resource was not found" if exc.status_code == 404 else "Request failed"  # noqa: PLR2004
        return JSONResponse(error_body(code, message), status_code=exc.status_code)

    @app.exception_handler(RequestValidationError)
    async def _validation_error(_request: Request, exc: RequestValidationError) -> JSONResponse:
        # Field locations and error types only: never echo the submitted values.
        fields = [
            {"loc": [str(part) for part in err.get("loc", ())], "type": str(err.get("type", ""))}
            for err in exc.errors()[:20]
        ]
        return JSONResponse(
            error_body("validation_error", "The request is not valid", fields=fields),
            status_code=422,
        )

    @app.exception_handler(Exception)
    async def _unexpected(_request: Request, exc: Exception) -> JSONResponse:
        _log.exception("unhandled_error", error_type=type(exc).__name__)
        return JSONResponse(
            error_body("internal_error", "Something went wrong. Quote the correlation ID."),
            status_code=500,
        )
