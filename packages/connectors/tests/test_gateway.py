from __future__ import annotations

import asyncio
from collections.abc import Mapping

import pytest

from skyline_connectors.base import (
    ApiCall,
    PaginationLimitError,
    ResponseTooLargeError,
    ThrottledError,
    TransientError,
)
from skyline_connectors.gateway import GatewayLimits, GuardedGateway
from skyline_core.types import JSON

LIST = ApiCall("fake", "ListThings")


class ScriptedTransport:
    """Returns (or raises) scripted results in order."""

    def __init__(self, *script: object) -> None:
        self.script = list(script)
        self.params: list[Mapping[str, JSON]] = []

    async def send(self, api: ApiCall, params: Mapping[str, JSON]) -> Mapping[str, JSON]:
        del api
        self.params.append(dict(params))
        item = self.script.pop(0)
        if isinstance(item, BaseException):
            raise item
        if item == "hang":
            await asyncio.sleep(10)
        assert isinstance(item, dict)
        return item


class Sleeps:
    def __init__(self) -> None:
        self.delays: list[float] = []

    async def __call__(self, delay: float) -> None:
        self.delays.append(delay)


def _gateway(transport: ScriptedTransport, sleeps: Sleeps, **limits: float) -> GuardedGateway:
    return GuardedGateway(
        transport,
        frozenset({LIST}),
        GatewayLimits(**limits),  # type: ignore[arg-type]
        sleep=sleeps,
    )


async def test_retries_transient_errors_with_backoff() -> None:
    sleeps = Sleeps()
    transport = ScriptedTransport(TransientError(), TransientError(), {"ok": True})
    assert await _gateway(transport, sleeps).call(LIST) == {"ok": True}
    assert len(sleeps.delays) == 2
    assert all(0 <= d <= 20 for d in sleeps.delays)


async def test_throttling_honours_retry_after_with_a_cap() -> None:
    sleeps = Sleeps()
    transport = ScriptedTransport(ThrottledError(3.0), ThrottledError(10_000), {"ok": True})
    await _gateway(transport, sleeps).call(LIST)
    assert sleeps.delays == [3.0, 120.0]


async def test_gives_up_after_max_attempts() -> None:
    sleeps = Sleeps()
    transport = ScriptedTransport(*(TransientError() for _ in range(3)))
    with pytest.raises(TransientError):
        await _gateway(transport, sleeps, max_attempts=3).call(LIST)


async def test_timeouts_are_retried_then_reported() -> None:
    sleeps = Sleeps()
    transport = ScriptedTransport("hang", "hang")
    with pytest.raises(TransientError, match="did not respond"):
        await _gateway(transport, sleeps, max_attempts=2, timeout_seconds=0.01).call(LIST)


async def test_oversized_responses_are_rejected() -> None:
    transport = ScriptedTransport({"blob": "x" * 2000})
    with pytest.raises(ResponseTooLargeError):
        await _gateway(transport, Sleeps(), max_response_bytes=1000).call(LIST)


async def test_pagination_follows_tokens() -> None:
    transport = ScriptedTransport(
        {"Items": [1], "NextToken": "a"}, {"Items": [2], "NextToken": "b"}, {"Items": [3]}
    )
    pages = [page async for page in _gateway(transport, Sleeps()).paginate(LIST, Region="r")]
    assert [p["Items"] for p in pages] == [[1], [2], [3]]
    assert transport.params == [
        {"Region": "r"},
        {"Region": "r", "NextToken": "a"},
        {"Region": "r", "NextToken": "b"},
    ]


async def test_pagination_detects_repeated_tokens() -> None:
    transport = ScriptedTransport({"NextToken": "a"}, {"NextToken": "a"})
    with pytest.raises(PaginationLimitError):
        _ = [page async for page in _gateway(transport, Sleeps()).paginate(LIST)]


async def test_pagination_cap() -> None:
    transport = ScriptedTransport({"NextToken": "a"}, {"NextToken": "b"}, {"NextToken": "c"})
    with pytest.raises(PaginationLimitError):
        _ = [page async for page in _gateway(transport, Sleeps(), max_pages=2).paginate(LIST)]


async def test_non_string_tokens_are_rejected() -> None:
    transport = ScriptedTransport({"NextToken": 5})
    with pytest.raises(PaginationLimitError):
        _ = [page async for page in _gateway(transport, Sleeps()).paginate(LIST)]
