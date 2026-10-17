"""`SessionRelevanceResults`: one result per queried deployment or connection."""

from __future__ import annotations

from collections.abc import Iterable, Iterator, Sequence
from typing import Any, overload

from .result import SessionRelevanceResult

UNREACHABLE_KINDS = frozenset({"connection", "timeout"})


class SessionRelevanceResults(Sequence[SessionRelevanceResult]):
    """An immutable sequence of results from a fan-out query."""

    __slots__ = ("_items",)

    def __init__(self, items: Iterable[SessionRelevanceResult] = ()) -> None:
        self._items: tuple[SessionRelevanceResult, ...] = tuple(items)

    @overload
    def __getitem__(self, index: int) -> SessionRelevanceResult: ...
    @overload
    def __getitem__(self, index: slice) -> SessionRelevanceResults: ...
    def __getitem__(self, index: int | slice) -> SessionRelevanceResult | SessionRelevanceResults:
        if isinstance(index, slice):
            return SessionRelevanceResults(self._items[index])
        return self._items[index]

    def __len__(self) -> int:
        return len(self._items)

    def __iter__(self) -> Iterator[SessionRelevanceResult]:
        return iter(self._items)

    def __repr__(self) -> str:
        return f"SessionRelevanceResults({list(self._items)!r})"

    def __eq__(self, other: object) -> bool:
        if isinstance(other, SessionRelevanceResults):
            return self._items == other._items
        return NotImplemented

    __hash__ = None  # type: ignore[assignment]

    @property
    def ok(self) -> bool:
        """True when there is at least one result and none failed."""
        return bool(self._items) and all(r.ok for r in self._items)

    @property
    def successful(self) -> tuple[SessionRelevanceResult, ...]:
        return tuple(r for r in self._items if r.ok)

    @property
    def failed(self) -> tuple[SessionRelevanceResult, ...]:
        return tuple(r for r in self._items if not r.ok)

    @property
    def unreachable(self) -> tuple[SessionRelevanceResult, ...]:
        return tuple(
            r for r in self._items if r.error is not None and r.error.kind in UNREACHABLE_KINDS
        )

    def first_ok(self) -> SessionRelevanceResult | None:
        return next((r for r in self._items if r.ok), None)

    def by_connection(self) -> dict[str, SessionRelevanceResult]:
        return {str(r.connection): r for r in self._items}

    def by_deployment(self) -> dict[str, SessionRelevanceResult]:
        """Keyed by deployment id, or the connection name when the id is unknown."""
        return {str(r.deployment_id or r.connection): r for r in self._items}

    def raise_for_error(self) -> SessionRelevanceResults:
        for r in self._items:
            r.raise_for_error()
        return self

    def to_dict(self, *, include_raw: bool = False) -> list[dict[str, Any]]:
        return [r.to_dict(include_raw=include_raw) for r in self._items]
