"""Read-only allowlist validation (ADR-0005 layer 2).

Every allowlist entry must look like a read operation for its connector's API style:

* ``sdk``  (AWS-style operation names): must start with ``Describe``, ``List`` or ``Get``
  followed by an upper-case letter, e.g. ``DescribeInstances``.
* ``http`` (Graph, Google, Azure REST): must be ``GET <path>``. Read-only POSTs (query
  endpoints) need an ADR note and an explicit entry in ``REVIEWED_READ_ONLY_POSTS``.

This is checked when a connector is registered, so a write API can't even be declared.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from enum import StrEnum
from typing import Final

from skyline_connectors.base import ApiCall, ReadOnlyViolationError

_SDK_READ: Final = re.compile(r"^(Describe|List|Get)[A-Z][A-Za-z0-9]*$")
_HTTP_GET: Final = re.compile(r"^GET /[A-Za-z0-9._~/{}$=,:@-]*$")
_SERVICE: Final = re.compile(r"^[a-z][a-z0-9-]{1,40}$")

#: Reviewed read-only POST endpoints, each with an ADR reference. Empty in Phase 0.
REVIEWED_READ_ONLY_POSTS: Final[frozenset[ApiCall]] = frozenset()


class AllowlistStyle(StrEnum):
    SDK = "sdk"
    HTTP = "http"


def is_read_only(api: ApiCall, style: AllowlistStyle) -> bool:
    """True if ``api`` is an acceptable read-only operation for ``style``."""
    if not _SERVICE.match(api.service):
        return False
    if style is AllowlistStyle.SDK:
        return bool(_SDK_READ.match(api.operation))
    return bool(_HTTP_GET.match(api.operation)) or api in REVIEWED_READ_ONLY_POSTS


def validate_allowlist(calls: Iterable[ApiCall], style: AllowlistStyle) -> frozenset[ApiCall]:
    """Return the allowlist, or raise :class:`ReadOnlyViolationError` naming bad entries."""
    allowlist = frozenset(calls)
    if not allowlist:
        msg = "a connector must declare at least one API call"
        raise ReadOnlyViolationError(msg)
    bad = sorted(str(api) for api in allowlist if not is_read_only(api, style))
    if bad:
        msg = f"allowlist contains non-read-only operations: {', '.join(bad)}"
        raise ReadOnlyViolationError(msg)
    return allowlist
