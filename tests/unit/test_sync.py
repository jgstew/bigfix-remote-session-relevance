from __future__ import annotations

import dataclasses
import threading
import time
from typing import Any

import anyio
import anyio.to_thread
import httpx
import pytest

from bigfix_remote_session_relevance import (
    SessionRelevanceClient,
    async_evaluate_session_relevance,
    evaluate_session_relevance,
)
from bigfix_remote_session_relevance.config import Config, ConnectionConfig

D1 = "1" * 64


def _config() -> Config:
    return Config(
        connections=(
            ConnectionConfig(
                name="a",
                backend="rest",
                server="a.example.com",
                username="u",
                password="p",
                deployment_id=D1,
                verify=True,
                connect_timeout=1,
                read_timeout=5,
            ),
        )
    )


def _factory(conn: ConnectionConfig) -> httpx.AsyncBaseTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        if b'"keys"' in request.content:
            return httpx.Response(200, json={"result": [{"id": 1}], "plural": True})
        return httpx.Response(200, json={"result": [42], "plural": False, "type": "integer"})

    return httpx.MockTransport(handler)


KW: dict[str, Any] = {"transport_factory": _factory, "trust": None}


def test_sync_client() -> None:
    with SessionRelevanceClient(_config(), **KW) as client:
        results = client.evaluate("q")
        assert results.ok
        assert results[0].answers == (42,)
        assert [r[0].answers for r in client.evaluate_many(["1", "2"])] == [(42,), (42,)]
        assert client.evaluate_explorer("q", keys="id")[0].answers == ({"id": 1},)
        assert client.discover_deployments() == {"a": D1}


async def test_sync_client_works_inside_a_running_event_loop() -> None:
    # e.g. a notebook or an async web app calling the sync API.
    with SessionRelevanceClient(_config(), **KW) as client:
        assert client.evaluate("q").ok


def test_close_is_idempotent() -> None:
    client = SessionRelevanceClient(_config(), **KW)
    client.close()
    client.close()
    with pytest.raises(RuntimeError, match="closed"):
        client.evaluate("q")


def test_convenience_sync() -> None:
    results = evaluate_session_relevance("q", config=_config(), **KW)
    assert results[0].answers == (42,)


async def test_convenience_async() -> None:
    results = await async_evaluate_session_relevance("q", config=_config(), **KW)
    assert results[0].answers == (42,)


def _two_deployments() -> Config:
    (a,) = _config().connections
    b = dataclasses.replace(a, name="b", server="b.example.com", deployment_id="2" * 64)
    return Config(connections=(a, b))


def test_sync_evaluate_stream_hands_over_each_result_as_it_lands() -> None:
    release = threading.Event()

    def factory(conn: ConnectionConfig) -> httpx.AsyncBaseTransport:
        async def handler(request: httpx.Request) -> httpx.Response:
            if conn.name == "a":
                # Answers only once the caller has already received b's result.
                await anyio.to_thread.run_sync(release.wait, 2)
            return httpx.Response(200, json={"result": [conn.name], "plural": False})

        return httpx.MockTransport(handler)

    seen = []
    with SessionRelevanceClient(_two_deployments(), transport_factory=factory, trust=None) as c:
        assert c.result_count() == 2
        for result in c.evaluate_stream("q"):
            seen.append(result.answers)
            release.set()
        assert [r.answers for r in c.evaluate_explorer_stream("q", keys="id")] != []
    assert seen == [("b",), ("a",)]


def test_sync_stream_propagates_errors() -> None:
    with (
        SessionRelevanceClient(_config(), **KW) as client,
        pytest.raises(ValueError),
    ):
        list(client.evaluate_explorer_stream("q", filters={"": ""}))


def test_sync_stream_does_nothing_until_iterated() -> None:
    calls: list[str] = []

    def factory(conn: ConnectionConfig) -> httpx.AsyncBaseTransport:
        def handler(request: httpx.Request) -> httpx.Response:
            calls.append(conn.name)
            return httpx.Response(200, json={"result": [1], "plural": False})

        return httpx.MockTransport(handler)

    with SessionRelevanceClient(_config(), transport_factory=factory, trust=None) as client:
        stream = client.evaluate_stream("q")
        time.sleep(0.1)
        assert calls == []
        assert [r.answers for r in stream] == [(1,)]


def test_abandoned_sync_stream_cancels_running_queries() -> None:
    cancelled = threading.Event()

    def factory(conn: ConnectionConfig) -> httpx.AsyncBaseTransport:
        async def handler(request: httpx.Request) -> httpx.Response:
            if conn.name == "a":
                try:
                    await anyio.sleep(30)
                except BaseException:
                    cancelled.set()
                    raise
            return httpx.Response(200, json={"result": [1], "plural": False})

        return httpx.MockTransport(handler)

    with SessionRelevanceClient(_two_deployments(), transport_factory=factory, trust=None) as c:
        stream = c.evaluate_stream("q")
        assert next(stream).connection == "b"
        stream.close()  # type: ignore[attr-defined]
        assert cancelled.wait(2)


def test_sync_explorer_stream_validates_on_call() -> None:
    with SessionRelevanceClient(_config(), **KW) as client, pytest.raises(ValueError):
        client.evaluate_explorer_stream("q", keys="id {")
