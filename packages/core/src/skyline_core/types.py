"""Shared type aliases and small value types."""

from __future__ import annotations

from typing import Final

type JSON = str | int | float | bool | dict[str, JSON] | list[JSON] | None
"""Any JSON value as produced by :func:`json.loads`."""

type JSONObject = dict[str, JSON]

_MASK: Final = "***"


class Sensitive[T]:
    """Wraps a secret so it can't be printed, logged or pickled by accident.

    Call :meth:`reveal` at the single point where the value is used. ``repr``/``str`` return
    ``***``, and pickling raises.
    """

    __slots__ = ("_value",)

    def __init__(self, value: T) -> None:
        self._value = value

    def reveal(self) -> T:
        """Return the wrapped value. Keep the result in a local variable only."""
        return self._value

    def __repr__(self) -> str:
        return f"Sensitive({_MASK})"

    __str__ = __repr__

    def __format__(self, format_spec: str) -> str:
        return repr(self)

    def __reduce__(self) -> str:
        msg = "Sensitive values cannot be pickled"
        raise TypeError(msg)
