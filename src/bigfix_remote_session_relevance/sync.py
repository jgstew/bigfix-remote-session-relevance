"""`SessionRelevanceClient`: the synchronous face of the async client.

The async client runs on its own event loop in a background thread (an
anyio blocking portal), so the sync API also works when the caller is
already inside a running loop, such as a notebook or an async web app,
where ``asyncio.run`` would fail.

That thread is a daemon the client owns, not ``start_blocking_portal``'s
executor thread: interpreter shutdown joins non-daemon threads before
running atexit hooks, so a client that was never closed (a long-lived
server just exits) would wait forever on a loop nobody stops. A
``weakref.finalize`` (an atexit hook, run while daemon threads still
run) closes such a client cleanly instead.

The ``*_stream`` methods hand each result to the calling thread through a
queue the moment the loop thread receives it.
"""

from __future__ import annotations

import functools
import queue
import threading
import weakref
from collections.abc import AsyncGenerator, Callable, Iterable, Iterator, Mapping
from contextlib import aclosing
from typing import TYPE_CHECKING, Any, Self, TypeVar

import anyio
from anyio.from_thread import BlockingPortal

from .backends.explorer_extras import explorer_body
from .client import AsyncSessionRelevanceClient
from .result import SessionRelevanceResult
from .results import SessionRelevanceResults

if TYPE_CHECKING:
    from types import TracebackType

T = TypeVar("T")


class SessionRelevanceClient:
    """Same API as `AsyncSessionRelevanceClient`, as plain methods."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        portal, thread = _start_portal_thread()
        self._portal: BlockingPortal | None = portal
        try:
            # Built on the portal's loop, where its locks and semaphores live.
            client: AsyncSessionRelevanceClient = portal.call(
                functools.partial(_make_client, *args, **kwargs)
            )
        except BaseException:
            _shut_down(portal, thread, None)
            self._portal = None
            raise
        self._client: AsyncSessionRelevanceClient = client
        # Holds no reference to self, so it also fires when the client is
        # garbage collected; calling it again is a no-op.
        self._finalizer = weakref.finalize(self, _shut_down, portal, thread, client)

    def _call(self, func: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        if self._portal is None:
            raise RuntimeError("SessionRelevanceClient is closed")
        return self._portal.call(functools.partial(func, *args, **kwargs))

    def evaluate(self, session_relevance: str) -> SessionRelevanceResults:
        result: SessionRelevanceResults = self._call(self._client.evaluate, session_relevance)
        return result

    def evaluate_stream(self, session_relevance: str) -> Iterator[SessionRelevanceResult]:
        """`evaluate`, yielding each result as it lands (completion order)."""
        return self._iterate(self._client.evaluate_stream, session_relevance)

    def evaluate_many(self, session_relevances: Iterable[str]) -> list[SessionRelevanceResults]:
        result: list[SessionRelevanceResults] = self._call(
            self._client.evaluate_many, list(session_relevances)
        )
        return result

    def evaluate_explorer(
        self,
        session_relevance: str,
        *,
        keys: str | None = None,
        filters: Mapping[str, str] | None = None,
    ) -> SessionRelevanceResults:
        result: SessionRelevanceResults = self._call(
            self._client.evaluate_explorer, session_relevance, keys=keys, filters=filters
        )
        return result

    def evaluate_explorer_stream(
        self,
        session_relevance: str,
        *,
        keys: str | None = None,
        filters: Mapping[str, str] | None = None,
    ) -> Iterator[SessionRelevanceResult]:
        explorer_body(session_relevance, keys, filters)  # invalid input raises here, not mid-stream
        return self._iterate(
            self._client.evaluate_explorer_stream, session_relevance, keys=keys, filters=filters
        )

    def result_count(self) -> int | None:
        result: int | None = self._call(self._client.result_count)
        return result

    def _iterate(
        self, stream: Callable[..., AsyncGenerator[T]], *args: Any, **kwargs: Any
    ) -> Iterator[T]:
        if self._portal is None:
            raise RuntimeError("SessionRelevanceClient is closed")
        return self._drain(self._portal, functools.partial(stream, *args, **kwargs))

    @staticmethod
    def _drain(portal: BlockingPortal, stream: Callable[[], AsyncGenerator[T]]) -> Iterator[T]:
        # A generator, so nothing starts until the first next(): an iterator
        # that is created and dropped never queries anything.
        items: queue.Queue[tuple[str, Any]] = queue.Queue()

        async def pump() -> None:
            try:
                async with aclosing(stream()) as results:
                    async for item in results:
                        items.put(("item", item))
            except Exception as exc:  # noqa: BLE001 - re-raised in the caller's thread
                items.put(("error", exc))
            finally:
                items.put(("done", None))

        future = portal.start_task_soon(pump)
        try:
            while True:
                kind, value = items.get()
                if kind == "done":
                    return
                if kind == "error":
                    raise value
                yield value
        finally:
            # An abandoned iteration cancels the queries still running.
            future.cancel()

    def discover_deployments(self, *, force: bool = False) -> dict[str, str | None]:
        result: dict[str, str | None] = self._call(self._client.discover_deployments, force=force)
        return result

    @property
    def connections(self) -> Any:
        return self._client.connections

    def close(self) -> None:
        self._portal = None
        if hasattr(self, "_finalizer"):
            self._finalizer()

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()


def _start_portal_thread() -> tuple[BlockingPortal, threading.Thread]:
    ready: queue.Queue[BlockingPortal | BaseException] = queue.Queue()

    async def host() -> None:
        async with BlockingPortal() as portal:
            ready.put(portal)
            await portal.sleep_until_stopped()

    def run() -> None:
        try:
            anyio.run(host)
        except BaseException as exc:  # noqa: BLE001 - re-raised in the caller's thread
            ready.put(exc)

    thread = threading.Thread(target=run, name="SessionRelevanceClient", daemon=True)
    thread.start()
    started = ready.get()
    if isinstance(started, BaseException):
        raise started
    return started, thread


def _shut_down(
    portal: BlockingPortal, thread: threading.Thread, client: AsyncSessionRelevanceClient | None
) -> None:
    if threading.current_thread() is thread:
        # Garbage collected on its own loop thread, which can't wait on
        # itself; the daemon thread is abandoned rather than deadlocked.
        return
    try:
        if client is not None:
            portal.call(client.aclose)
    finally:
        portal.call(portal.stop)
        thread.join()


async def _make_client(*args: Any, **kwargs: Any) -> AsyncSessionRelevanceClient:
    return AsyncSessionRelevanceClient(*args, **kwargs)


def evaluate_session_relevance(session_relevance: str, **kwargs: Any) -> SessionRelevanceResults:
    """One-shot sync query across the configured connections (default config)."""
    with SessionRelevanceClient(**kwargs) as client:
        return client.evaluate(session_relevance)


async def async_evaluate_session_relevance(
    session_relevance: str, **kwargs: Any
) -> SessionRelevanceResults:
    """One-shot async query across the configured connections (default config)."""
    async with AsyncSessionRelevanceClient(**kwargs) as client:
        return await client.evaluate(session_relevance)
