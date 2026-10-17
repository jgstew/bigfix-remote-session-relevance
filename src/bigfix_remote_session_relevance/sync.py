"""`SessionRelevanceClient`: the synchronous face of the async client.

The async client runs on its own event loop in a background thread (an
anyio blocking portal), so the sync API also works when the caller is
already inside a running loop, such as a notebook or an async web app,
where ``asyncio.run`` would fail.
"""

from __future__ import annotations

import functools
from collections.abc import Callable, Iterable, Mapping
from contextlib import AbstractContextManager
from typing import TYPE_CHECKING, Any, Self, TypeVar

from anyio.from_thread import BlockingPortal, start_blocking_portal

from .client import AsyncSessionRelevanceClient
from .results import SessionRelevanceResults

if TYPE_CHECKING:
    from types import TracebackType

T = TypeVar("T")


class SessionRelevanceClient:
    """Same API as `AsyncSessionRelevanceClient`, as plain methods."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        self._portal_cm: AbstractContextManager[BlockingPortal] | None = start_blocking_portal()
        self._portal: BlockingPortal | None = self._portal_cm.__enter__()
        try:
            # Built on the portal's loop, where its locks and semaphores live.
            self._client: AsyncSessionRelevanceClient = self._portal.call(
                functools.partial(_make_client, *args, **kwargs)
            )
        except BaseException:
            self.close()
            raise

    def _call(self, func: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        if self._portal is None:
            raise RuntimeError("SessionRelevanceClient is closed")
        return self._portal.call(functools.partial(func, *args, **kwargs))

    def evaluate(self, relevance: str) -> SessionRelevanceResults:
        result: SessionRelevanceResults = self._call(self._client.evaluate, relevance)
        return result

    def evaluate_many(self, relevances: Iterable[str]) -> list[SessionRelevanceResults]:
        result: list[SessionRelevanceResults] = self._call(
            self._client.evaluate_many, list(relevances)
        )
        return result

    def evaluate_explorer(
        self,
        relevance: str,
        *,
        keys: str | None = None,
        filters: Mapping[str, str] | None = None,
    ) -> SessionRelevanceResults:
        result: SessionRelevanceResults = self._call(
            self._client.evaluate_explorer, relevance, keys=keys, filters=filters
        )
        return result

    def discover_deployments(self, *, force: bool = False) -> dict[str, str | None]:
        result: dict[str, str | None] = self._call(self._client.discover_deployments, force=force)
        return result

    @property
    def connections(self) -> Any:
        return self._client.connections

    def close(self) -> None:
        portal, self._portal = self._portal, None
        portal_cm, self._portal_cm = self._portal_cm, None
        if portal is not None and hasattr(self, "_client"):
            portal.call(self._client.aclose)
        if portal_cm is not None:
            portal_cm.__exit__(None, None, None)

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()


async def _make_client(*args: Any, **kwargs: Any) -> AsyncSessionRelevanceClient:
    return AsyncSessionRelevanceClient(*args, **kwargs)


def evaluate_session_relevance(relevance: str, **kwargs: Any) -> SessionRelevanceResults:
    """One-shot sync query across the configured connections (default config)."""
    with SessionRelevanceClient(**kwargs) as client:
        return client.evaluate(relevance)


async def async_evaluate_session_relevance(
    relevance: str, **kwargs: Any
) -> SessionRelevanceResults:
    """One-shot async query across the configured connections (default config)."""
    async with AsyncSessionRelevanceClient(**kwargs) as client:
        return await client.evaluate(relevance)
