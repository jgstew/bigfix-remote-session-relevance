from __future__ import annotations

from typing import Any

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
