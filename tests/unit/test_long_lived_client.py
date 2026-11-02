"""What one long-lived client needs (#33, from bigfix-relevance-debugger).

`Config.with_timeouts`, a per-call ``read_timeout``, config problems as
results rather than raised mid-stream, and the result display helpers.
"""

from __future__ import annotations

import argparse
import asyncio
import json
from typing import Any

import httpx
import pytest

from bigfix_remote_session_relevance import cli, render
from bigfix_remote_session_relevance.client import AsyncSessionRelevanceClient
from bigfix_remote_session_relevance.config import Config, ConnectionConfig
from bigfix_remote_session_relevance.exceptions import ConfigError
from bigfix_remote_session_relevance.result import ERROR_KINDS, ResultError, SessionRelevanceResult
from bigfix_remote_session_relevance.results import SessionRelevanceResults
from bigfix_remote_session_relevance.sync import SessionRelevanceClient

D1 = "1" * 64
D2 = "2" * 64


def _conn(name: str, backend: str = "rest", dep: str | None = D1, **kw: Any) -> ConnectionConfig:
    fields: dict[str, Any] = {
        "server": f"{name}.example.com",
        "username": "u",
        "password": "p",
        "verify": True,
        "connect_timeout": 2,
        "read_timeout": 30,
    }
    fields.update(kw)
    return ConnectionConfig(name=name, backend=backend, deployment_id=dep, **fields)


# -- 1. Config.with_timeouts --------------------------------------------------------


def test_with_timeouts_none_is_the_same_config() -> None:
    config = Config(connections=(_conn("a"),))
    assert config.with_timeouts() is config
    assert config.with_timeouts(connect=None, read=None) is config


def test_with_timeouts_replaces_only_what_is_given() -> None:
    config = Config(
        connections=(_conn("a"), _conn("b", connect_timeout=None, read_timeout=None)),
        backend_preference=("rest",),
    )
    read = config.with_timeouts(read=7)
    assert [(c.connect_timeout, c.read_timeout) for c in read.connections] == [(2, 7), (None, 7)]
    connect = config.with_timeouts(connect=1.5)
    assert [(c.connect_timeout, c.read_timeout) for c in connect.connections] == [
        (1.5, 30),
        (1.5, None),
    ]
    both = config.with_timeouts(connect=1, read=9)
    assert [(c.connect_timeout, c.read_timeout) for c in both.connections] == [(1, 9), (1, 9)]
    assert both.backend_preference == ("rest",)
    assert [c.name for c in both.connections] == ["a", "b"]
    assert config.connections[0].read_timeout == 30  # unchanged: a copy


def test_cli_timeouts_use_with_timeouts() -> None:
    config = Config(connections=(_conn("a"),))
    args = argparse.Namespace(connect_timeout=None, timeout=None)
    assert cli._apply_timeouts(config, args) is config
    args = argparse.Namespace(connect_timeout=3.0, timeout=11.0)
    assert cli._apply_timeouts(config, args) == config.with_timeouts(connect=3.0, read=11.0)


# -- 2. per-call read_timeout ----------------------------------------------------------


class Recorder:
    """Records every request's timeouts (what httpx hands the transport)."""

    def __init__(self) -> None:
        self.seen: list[tuple[str, str, dict[str, float]]] = []

    def transport(self, conn: ConnectionConfig) -> httpx.AsyncBaseTransport:
        def handle(request: httpx.Request) -> httpx.Response:
            self.seen.append((conn.name, request.url.path, dict(request.extensions["timeout"])))
            if request.url.path == "/auth/v1/user/login":
                body = {"status": 200, "data": {"iat": 0, "exp": 3600, "pids": {"bf": {"1": {}}}}}
                return httpx.Response(
                    200, json=body, headers={"set-cookie": "accessToken=A; Path=/; Secure"}
                )
            if request.url.path == "/bfproxy/v2/relevance":
                data = {"answer": [D1], "plural": False, "type": "string", "evaltime": 1}
                return httpx.Response(200, json={"status": 200, "data": data})
            if "sha256" in request.content.decode() or "sha256" in str(request.url):
                return httpx.Response(200, json={"result": [D1], "plural": False, "type": "string"})
            return httpx.Response(200, json={"result": [1], "plural": False, "type": "integer"})

        return httpx.MockTransport(handle)

    def reads(self, path: str | None = None) -> list[float]:
        return [t["read"] for _, p, t in self.seen if path is None or p == path]


def _client(conns: list[ConnectionConfig], rec: Recorder, **kw: Any) -> AsyncSessionRelevanceClient:
    return AsyncSessionRelevanceClient(
        Config(connections=tuple(conns)), transport_factory=rec.transport, trust=None, **kw
    )


async def test_read_timeout_per_call_on_one_client() -> None:
    rec = Recorder()
    async with _client([_conn("a")], rec) as client:
        assert (await client.evaluate("1", read_timeout=5)).ok
        assert (await client.evaluate("1", read_timeout=60)).ok
        assert (await client.evaluate("1")).ok
    assert rec.reads() == [5, 60, 30]
    # The connect timeout stays the client's.
    assert {t["connect"] for _, _, t in rec.seen} == {2}


async def test_read_timeout_on_every_evaluate_method() -> None:
    rec = Recorder()
    async with _client([_conn("a", "explorer")], rec) as client:
        await client.evaluate("1", read_timeout=4)
        [r async for r in client.evaluate_stream("1", read_timeout=5)]
        await client.evaluate_many(["1", "2"], read_timeout=6)
        await client.evaluate_explorer("1", keys="{id}", read_timeout=7)
        [r async for r in client.evaluate_explorer_stream("1", keys="{id}", read_timeout=8)]
    assert rec.reads() == [4, 5, 6, 6, 7, 8]


async def test_read_timeout_keeps_one_saas_sign_in() -> None:
    # The point of a per-call timeout: one client, so one sign-in, rather
    # than one client (and one sign-in) per timeout.
    conn = _conn("saas", "saas", server="login.bigfix.com", username="op@example.com", sid="bf1")
    rec = Recorder()
    async with _client([conn], rec) as client:
        assert (await client.evaluate("1", read_timeout=5)).ok
        assert (await client.evaluate("1", read_timeout=60)).ok
    assert rec.reads("/bfproxy/v2/relevance") == [5, 60]
    assert len(rec.reads("/auth/v1/user/login")) == 1


async def test_read_timeout_does_not_bound_discovery() -> None:
    rec = Recorder()
    async with _client([_conn("a", dep=None)], rec) as client:
        assert (await client.evaluate("1", read_timeout=5)).ok
    discovery = [t["read"] for _, _, t in rec.seen[:-1]]
    assert discovery and set(discovery) == {30}
    assert rec.reads()[-1] == 5


async def test_concurrent_calls_keep_their_own_read_timeouts() -> None:
    rec = Recorder()
    async with _client([_conn("a")], rec) as client:
        await asyncio.gather(
            client.evaluate("1", read_timeout=5), client.evaluate("2", read_timeout=60)
        )
    assert sorted(rec.reads()) == [5, 60]


@pytest.mark.parametrize("bad", [0, -1, float("nan")])
async def test_read_timeout_must_be_positive(bad: float) -> None:
    rec = Recorder()
    async with _client([_conn("a")], rec) as client:
        with pytest.raises(ValueError, match="read_timeout"):
            await client.evaluate("1", read_timeout=bad)
        with pytest.raises(ValueError, match="read_timeout"):
            client.evaluate_stream("1", read_timeout=bad)
    assert rec.seen == []


def test_sync_client_read_timeout() -> None:
    rec = Recorder()
    with SessionRelevanceClient(
        [_conn("a", "explorer")], transport_factory=rec.transport, trust=None
    ) as client:
        client.evaluate("1", read_timeout=4)
        list(client.evaluate_stream("1", read_timeout=5))
        client.evaluate_many(["1"], read_timeout=6)
        client.evaluate_explorer("1", keys="{id}", read_timeout=7)
        list(client.evaluate_explorer_stream("1", keys="{id}", read_timeout=8))
    assert rec.reads() == [4, 5, 6, 7, 8]


# -- 3. config problems as results ------------------------------------------------------


def test_config_is_an_error_kind() -> None:
    assert "config" in ERROR_KINDS
    result = SessionRelevanceResult.failure("q", ResultError(kind="config", message="bad"))
    with pytest.raises(ConfigError):
        result.raise_for_error()


def _broken(name: str = "broken", dep: str | None = D2, **kw: Any) -> ConnectionConfig:
    # As BES_ROOT_SERVER can give it: a path, found only when the backend is built.
    return _conn(name, dep=dep, server="https://root.example.com:52311/some/path", **kw)


@pytest.mark.parametrize("mode", ["per_deployment", "all"])
async def test_config_problem_is_a_result_and_the_rest_still_run(mode: str) -> None:
    rec = Recorder()
    async with _client([_broken(), _conn("good")], rec, mode=mode) as client:
        streamed = [r async for r in client.evaluate_stream("1")]
        collected = await client.evaluate("1")
    for results in (streamed, list(collected)):
        by_name = {r.connection: r for r in results}
        assert set(by_name) == {"broken", "good"}
        assert by_name["good"].ok
        error = by_name["broken"].error
        assert error is not None and error.kind == "config"
        assert "path" in error.message
        assert by_name["broken"].backend == "rest"
        assert by_name["broken"].deployment_id == D2
    assert {name for name, _, _ in rec.seen} == {"good"}


async def test_config_problem_is_asked_no_password() -> None:
    asked: list[str] = []
    conn = _broken(password=None)
    rec = Recorder()

    def prompt(message: str) -> str:
        asked.append(message)
        return "pw"

    async with _client([conn], rec, prompt=prompt) as client:
        results = await client.evaluate("1")
    assert results[0].error is not None and results[0].error.kind == "config"
    assert asked == []


async def test_config_problem_alone_and_with_raise_errors() -> None:
    rec = Recorder()
    async with _client([_broken()], rec) as client:
        results = await client.evaluate("1")
        assert client.result_count() == 1
        assert await client.discover_deployments() == {"broken": D2}
    assert [r.error.kind for r in results if r.error] == ["config"]
    async with _client([_broken()], rec, raise_errors=True) as client:
        with pytest.raises(ConfigError, match="path"):
            await client.evaluate("1")


async def test_result_count_counts_config_problems() -> None:
    rec = Recorder()
    async with _client([_broken(), _conn("good")], rec) as client:
        results = await client.evaluate("1")
        assert client.result_count() == len(results) == 2


def test_constructor_mistakes_still_raise() -> None:
    with pytest.raises(ConfigError, match="nope"):
        AsyncSessionRelevanceClient(
            Config(connections=(_conn("a"),)), connections=["nope"], trust=None
        )
    with pytest.raises(ConfigError, match="unknown backend"):
        AsyncSessionRelevanceClient(
            Config(connections=(_conn("a"),)), backends=["nope"], trust=None
        )


def test_cli_exit_code_for_config_problems() -> None:
    bad = SessionRelevanceResult.failure("q", ResultError(kind="config", message="x"))
    good = SessionRelevanceResult.from_values("q", [1], type="integer")
    assert render.exit_code(SessionRelevanceResults([bad])) == render.EXIT_USAGE
    assert render.exit_code(SessionRelevanceResults([good, bad])) == render.EXIT_USAGE


def test_config_problem_to_dict() -> None:
    bad = SessionRelevanceResult.failure("q", ResultError(kind="config", message="x"))
    assert json.loads(json.dumps(bad.to_dict()))["error"]["kind"] == "config"


# -- 4. display helpers ------------------------------------------------------------------


@pytest.mark.parametrize(
    ("server", "host"),
    [
        ("https://h:52311", "h"),
        ("https://H.Example.com:52311", "h.example.com"),
        ("h:52311", "h"),
        ("https://[2001:db8::1]:52311", "2001:db8::1"),
        ("https://api.bigfix.com", "api.bigfix.com"),
        (None, None),
        ("", None),
        ("https://[bad", None),
    ],
)
def test_host(server: str | None, host: str | None) -> None:
    assert SessionRelevanceResult("q", server=server).host == host


@pytest.mark.parametrize(
    ("ms", "text"),
    [
        (0.049, "0.049ms"),
        (4.0, "4ms"),
        (1e-07, "0ms"),
        (1234567.0, "1234567ms"),
        (12.5, "12.5ms"),
        (0.0, "0ms"),
        (None, None),
    ],
)
def test_evaluation_time_text(ms: float | None, text: str | None) -> None:
    assert SessionRelevanceResult("q", evaluation_time_ms=ms).evaluation_time_text == text
    assert "e" not in (text or "")


def test_display_helpers_are_not_part_of_to_dict() -> None:
    data = SessionRelevanceResult("q", server="https://h:52311").to_dict()
    assert "host" not in data and "evaluation_time_text" not in data


# -- review findings ---------------------------------------------------------------------


async def test_a_short_read_timeout_does_not_shorten_the_saas_sign_in() -> None:
    # A login cut short is resent next query, its outcome unknown: a wrong
    # password then costs a failed login per query, toward the lockout.
    conn = _conn("saas", "saas", server="login.bigfix.com", username="op@example.com", sid="bf1")
    rec = Recorder()
    async with _client([conn], rec) as client:
        assert (await client.evaluate("1", read_timeout=5)).ok
        assert (await client.evaluate("1", read_timeout=60)).ok
    assert rec.reads("/auth/v1/user/login") == [30]  # the configured one
    assert rec.reads("/bfproxy/v2/relevance") == [5, 60]
    assert all("bfrsr" not in str(k) for _, _, t in rec.seen for k in t)


async def test_result_count_before_the_first_run_with_a_config_problem_in_a_deployment() -> None:
    rec = Recorder()
    async with _client([_conn("good"), _broken(dep=D1)], rec) as client:
        before = client.result_count()
        results = await client.evaluate("1")
        assert before == client.result_count() == len(results) == 2
