"""The guarded API gateway (ADR-0005 layer 3).

:class:`GuardedGateway` wraps a provider :class:`Transport` and is the only object a connector
receives. It refuses calls outside the allowlist, and applies a timeout, retries with
jittered exponential backoff, ``Retry-After`` throttling, a page cap, repeated-token
detection and a response-size cap. Transports are the only modules allowed to import SDKs
or HTTP clients (enforced by an AST test).
"""

from __future__ import annotations

import asyncio
import json
import random
from collections.abc import AsyncIterator, Awaitable, Callable, Mapping
from dataclasses import dataclass
from typing import Final, Protocol

from skyline_connectors.base import (
    ApiCall,
    ApiNotAllowedError,
    PaginationLimitError,
    ResponseTooLargeError,
    ThrottledError,
    TransientError,
)
from skyline_core.types import JSON

_MAX_RETRY_AFTER_SECONDS: Final = 120.0


class Transport(Protocol):
    """Sends one request to a provider. Implementations hold the credentials."""

    async def send(self, api: ApiCall, params: Mapping[str, JSON]) -> Mapping[str, JSON]: ...


@dataclass(frozen=True, slots=True)
class GatewayLimits:
    timeout_seconds: float = 30.0
    max_attempts: int = 5
    backoff_base_seconds: float = 0.5
    backoff_cap_seconds: float = 20.0
    max_pages: int = 1000
    max_response_bytes: int = 10 * 1024 * 1024


class GuardedGateway:
    """Implements :class:`skyline_connectors.base.ApiGateway`."""

    page_token_param: str = "NextToken"  # noqa: S105 - a parameter name, not a secret
    page_token_field: str = "NextToken"  # noqa: S105

    def __init__(
        self,
        transport: Transport,
        allowlist: frozenset[ApiCall],
        limits: GatewayLimits | None = None,
        *,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        self._transport = transport
        self._allowlist = allowlist
        self._limits = limits or GatewayLimits()
        self._sleep = sleep
        self.calls: list[ApiCall] = []

    def _backoff(self, attempt: int) -> float:
        ceiling = min(
            self._limits.backoff_cap_seconds, self._limits.backoff_base_seconds * 2**attempt
        )
        return random.uniform(0, ceiling)  # noqa: S311 - jitter, not security sensitive

    async def call(self, api: ApiCall, /, **params: JSON) -> Mapping[str, JSON]:
        if api not in self._allowlist:
            raise ApiNotAllowedError(api)
        last_error: TransientError | None = None
        for attempt in range(self._limits.max_attempts):
            self.calls.append(api)
            try:
                async with asyncio.timeout(self._limits.timeout_seconds):
                    response = await self._transport.send(api, params)
            except ThrottledError as exc:
                last_error = exc
                delay = exc.retry_after if exc.retry_after is not None else self._backoff(attempt)
                await self._sleep(min(max(delay, 0.0), _MAX_RETRY_AFTER_SECONDS))
                continue
            except TransientError as exc:
                last_error = exc
                await self._sleep(self._backoff(attempt))
                continue
            except TimeoutError:
                last_error = TransientError("the provider did not respond in time")
                await self._sleep(self._backoff(attempt))
                continue
            self._check_size(response)
            return response
        assert last_error is not None  # noqa: S101 - loop ran at least once
        raise last_error

    def _check_size(self, response: Mapping[str, JSON]) -> None:
        size = len(json.dumps(response, separators=(",", ":"), default=str))
        if size > self._limits.max_response_bytes:
            raise ResponseTooLargeError

    async def paginate(self, api: ApiCall, /, **params: JSON) -> AsyncIterator[Mapping[str, JSON]]:
        token: str | None = None
        seen: set[str] = set()
        for _ in range(self._limits.max_pages):
            page_params = dict(params)
            if token is not None:
                page_params[self.page_token_param] = token
            page = await self.call(api, **page_params)
            yield page
            next_token = page.get(self.page_token_field)
            if not next_token:
                return
            if not isinstance(next_token, str) or next_token in seen:
                raise PaginationLimitError
            seen.add(next_token)
            token = next_token
        raise PaginationLimitError
