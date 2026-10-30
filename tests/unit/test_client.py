from __future__ import annotations

import asyncio
import json
import os
from collections.abc import Callable
from pathlib import Path
from typing import Any
from urllib.parse import unquote_plus

import httpx
import pytest

from bigfix_remote_session_relevance.client import AsyncSessionRelevanceClient
from bigfix_remote_session_relevance.config import Config, ConnectionConfig, load_config
from bigfix_remote_session_relevance.deployment import DEPLOYMENT_ID_SESSION_RELEVANCE
from bigfix_remote_session_relevance.exceptions import ConfigError, SessionRelevanceEvaluationError

D1 = "1" * 64
D2 = "2" * 64


def _conn(name: str, backend: str = "rest", dep: str | None = None, **kw: Any) -> ConnectionConfig:
    return ConnectionConfig(
        name=name,
        backend=backend,
        server=f"{name}.example.com",
        username="u",
        password="p",
        deployment_id=dep,
        verify=True,
        connect_timeout=1,
        read_timeout=5,
        **kw,
    )


def _ok(value: Any = 1, type_: str = "integer") -> httpx.Response:
    return httpx.Response(200, json={"result": [value], "plural": False, "type": type_})


REFUSED = httpx.ConnectError("[Errno 61] Connection refused")


class Router:
    """Per-connection fake transports, keyed by the request host."""

    def __init__(self, routes: dict[str, Callable[[httpx.Request], Any] | list[Any]]) -> None:
        self.calls: list[str] = []
        self.routes = routes

    def transport_for(self, conn: ConnectionConfig) -> httpx.AsyncBaseTransport:
        async def handler(request: httpx.Request) -> httpx.Response:
            self.calls.append(conn.name)
            route = self.routes[conn.name]
            if callable(route):
                item = route(request)
                if asyncio.iscoroutine(item):
                    item = await item
            else:
                item = route.pop(0) if len(route) > 1 else route[0]
            if isinstance(item, BaseException):
                raise item
            return item

        return httpx.MockTransport(handler)


def _client(
    conns: list[ConnectionConfig], router: Router, **kw: Any
) -> AsyncSessionRelevanceClient:
    return AsyncSessionRelevanceClient(
        Config(connections=tuple(conns)), transport_factory=router.transport_for, trust=None, **kw
    )


async def test_one_result_per_deployment_with_preference_order() -> None:
    conns = [
        _conn("d1-wr", "webreports", D1),
        _conn("d1-root", "rest", D1),
        _conn("d1-ex", "explorer", D1),
        _conn("d2-root", "rest", D2),
    ]
    router = Router({n.name: [_ok()] for n in conns})
    async with _client(conns, router) as client:
        results = await client.evaluate("1")
    # explorer > rest > webreports within d1; d2 has one connection.
    assert sorted(str(r.connection) for r in results) == ["d1-ex", "d2-root"]
    assert {r.deployment_id for r in results} == {D1, D2}
    assert "d1-wr" not in router.calls and "d1-root" not in router.calls


async def test_failover_within_deployment_in_preference_order() -> None:
    conns = [_conn("d1-root", "rest", D1), _conn("d1-ex", "explorer", D1)]
    router = Router({"d1-ex": [REFUSED], "d1-root": [_ok(7)]})
    async with _client(conns, router) as client:
        (result,) = await client.evaluate("q")
    assert result.ok
    assert result.connection == "d1-root"
    assert result.answers == (7,)
    assert router.calls == ["d1-ex", "d1-root"]


@pytest.mark.parametrize(
    "first_failure",
    [
        REFUSED,
        httpx.ConnectTimeout("t"),
        httpx.Response(401, text="no"),
        httpx.Response(500, text="boom"),
        httpx.Response(200, text="<html>login</html>", headers={"content-type": "text/html"}),
    ],
)
async def test_failover_kinds(first_failure: Any) -> None:
    conns = [_conn("a-ex", "explorer", D1), _conn("a-root", "rest", D1)]
    router = Router({"a-ex": [first_failure], "a-root": [_ok()]})
    async with _client(conns, router) as client:
        (result,) = await client.evaluate("q")
    assert result.connection == "a-root"


async def test_no_failover_on_relevance_error() -> None:
    conns = [_conn("a-ex", "explorer", D1), _conn("a-root", "rest", D1)]
    error = httpx.Response(200, json={"result": [], "error": 'The operator "foo" is not defined.'})
    router = Router({"a-ex": [error], "a-root": [_ok()]})
    async with _client(conns, router) as client:
        (result,) = await client.evaluate("foo")
    assert result.error is not None
    assert result.error.kind == "session_relevance"
    assert router.calls == ["a-ex"]


@pytest.mark.parametrize("code", ["pin_mismatch", "pinned_cert_invalid"])
async def test_no_failover_on_pin_errors(monkeypatch: pytest.MonkeyPatch, code: str) -> None:
    from bigfix_remote_session_relevance.backends import base
    from bigfix_remote_session_relevance.result import ResultError, SessionRelevanceResult

    conns = [_conn("a-ex", "explorer", D1), _conn("a-root", "rest", D1)]
    router = Router({"a-ex": [_ok()], "a-root": [_ok()]})

    original = base.Backend._run_with_trust

    async def fake(self: Any, session_relevance: str, op: Any) -> SessionRelevanceResult:
        if self.connection == "a-ex":
            return SessionRelevanceResult.failure(
                session_relevance, ResultError(kind="tls", code=code, message="changed")
            )
        return await original(self, session_relevance, op)

    monkeypatch.setattr(base.Backend, "_run_with_trust", fake)
    async with _client(conns, router) as client:
        (result,) = await client.evaluate("q")
    assert result.error is not None
    assert result.error.code == code
    assert router.calls == []


async def test_all_unreachable_gives_one_error_listing_what_was_tried() -> None:
    conns = [_conn("a-ex", "explorer", D1), _conn("a-root", "rest", D1)]
    router = Router({"a-ex": [REFUSED], "a-root": [httpx.ConnectTimeout("t")]})
    async with _client(conns, router) as client:
        results = await client.evaluate("q")
    (result,) = results
    assert result.error is not None
    assert result.error.kind == "connection"
    assert "a-ex" in result.error.message and "a-root" in result.error.message
    assert results.unreachable == (result,)


async def test_authentication_error_preferred_over_unreachable_in_summary() -> None:
    conns = [_conn("a-ex", "explorer", D1), _conn("a-root", "rest", D1)]
    router = Router({"a-ex": [REFUSED], "a-root": [httpx.Response(401, text="no")]})
    async with _client(conns, router) as client:
        (result,) = await client.evaluate("q")
    assert result.error is not None
    assert result.error.kind == "authentication"


async def test_working_connection_becomes_sticky() -> None:
    conns = [_conn("a-ex", "explorer", D1), _conn("a-root", "rest", D1)]
    router = Router({"a-ex": [REFUSED], "a-root": [_ok()]})
    async with _client(conns, router) as client:
        await client.evaluate("1")
        await client.evaluate("2")
    assert router.calls == ["a-ex", "a-root", "a-root"]


async def test_groups_really_run_concurrently() -> None:
    barrier = asyncio.Barrier(2)

    async def gated(request: httpx.Request) -> httpx.Response:
        await asyncio.wait_for(barrier.wait(), timeout=2)
        return _ok()

    conns = [_conn("d1", "rest", D1), _conn("d2", "rest", D2)]
    router = Router({"d1": gated, "d2": gated})
    async with _client(conns, router) as client:
        results = await client.evaluate("1")
    assert results.ok


async def test_mode_all_queries_every_connection() -> None:
    conns = [_conn("a-ex", "explorer", D1), _conn("a-root", "rest", D1), _conn("b", "rest", D2)]
    router = Router({"a-ex": [REFUSED], "a-root": [_ok()], "b": [_ok()]})
    async with _client(conns, router, mode="all") as client:
        results = await client.evaluate("1")
    assert [r.connection for r in results] == ["a-ex", "a-root", "b"]
    assert [r.ok for r in results] == [False, True, True]


def _saas_conn(sid: str, email: str = "operator@example.com") -> ConnectionConfig:
    return ConnectionConfig(
        name=f"saas-{sid}",
        backend="saas",
        server="login.bigfix.com",
        username=email,
        password="pw",
        sid=sid,
        verify=True,
    )


def _saas_route(logins: list[str], login: httpx.Response) -> Callable[[httpx.Request], Any]:
    """One BigFix SaaS account; each sid reports its own deployment id."""

    async def route(request: httpx.Request) -> httpx.Response:
        await asyncio.sleep(0.01)  # let concurrent connections overlap
        if request.url.path == "/auth/v1/user/login":
            logins.append(request.url.path)
            return login
        sid = json.loads(request.content)["sid"]
        answer = sid[-1] * 64 if "sha256" in json.loads(request.content)["data"]["query"] else 1
        data = {"answer": [answer], "plural": False, "type": "string", "evaltime": 1}
        return httpx.Response(200, json={"status": 200, "data": data})

    return route


_SAAS_LOGIN_OK = httpx.Response(
    200,
    json={"status": 200, "data": {"iat": 0, "exp": 3600, "pids": {"bf": {"1": {}, "2": {}}}}},
    headers={"set-cookie": "accessToken=A; Path=/; HttpOnly; Secure"},
)


@pytest.mark.parametrize("mode", ["per_deployment", "all"])
async def test_saas_connections_of_one_account_sign_in_once(mode: str) -> None:
    # --setup saves one connection per sid; they must share one sign-in.
    conns = [_saas_conn("bf1"), _saas_conn("bf2"), _saas_conn("bf3")]
    logins: list[str] = []
    route = _saas_route(logins, _SAAS_LOGIN_OK)
    router = Router({c.name: route for c in conns})
    async with _client(conns, router, mode=mode) as client:
        first = await client.evaluate("1")  # per_deployment: discovery first, concurrently
        second = await client.evaluate("1")
    assert first.ok and second.ok
    assert len(first) == 3
    assert len(logins) == 1


async def test_rejected_saas_login_is_sent_once_per_client() -> None:
    conns = [_saas_conn("bf1"), _saas_conn("bf2"), _saas_conn("bf3")]
    logins: list[str] = []
    rejected = httpx.Response(401, json={"status": 401, "data": {"errorMessage": "Incorrect."}})
    router = Router({c.name: _saas_route(logins, rejected) for c in conns})
    async with _client(conns, router) as client:
        results = [*await client.evaluate("1"), *await client.evaluate("2")]
    assert len(logins) == 1
    assert all(r.error is not None and r.error.code == "login_failed" for r in results)


async def test_saas_connections_of_different_accounts_sign_in_separately() -> None:
    conns = [_saas_conn("bf1"), _saas_conn("bf2", email="someone.else@example.com")]
    logins: list[str] = []
    route = _saas_route(logins, _SAAS_LOGIN_OK)
    router = Router({c.name: route for c in conns})
    async with _client(conns, router, mode="all") as client:
        assert (await client.evaluate("1")).ok
    assert len(logins) == 2


async def test_filters_by_name_and_backend() -> None:
    conns = [_conn("a-ex", "explorer", D1), _conn("a-root", "rest", D1), _conn("b", "rest", D2)]
    router = Router({c.name: [_ok()] for c in conns})
    async with _client(conns, router, backends=["rest"]) as client:
        results = await client.evaluate("1")
    assert sorted(str(r.connection) for r in results) == ["a-root", "b"]
    async with _client(conns, router, connections=["b"]) as client:
        results = await client.evaluate("1")
    assert [r.connection for r in results] == ["b"]
    with pytest.raises(ConfigError, match="nope"):
        _client(conns, router, connections=["nope"])


async def test_disabled_connections_are_skipped() -> None:
    conns = [_conn("a", "rest", D1, enabled=False), _conn("b", "rest", D2)]
    router = Router({c.name: [_ok()] for c in conns})
    async with _client(conns, router) as client:
        results = await client.evaluate("1")
    assert [r.connection for r in results] == ["b"]


async def test_no_connections_gives_empty_results() -> None:
    async with _client([], Router({})) as client:
        results = await client.evaluate("1")
    assert len(results) == 0
    assert not results.ok


async def test_raise_errors() -> None:
    conns = [_conn("a", "rest", D1)]
    router = Router({"a": [httpx.Response(200, json={"result": [], "error": "bad"})]})
    async with _client(conns, router, raise_errors=True) as client:
        with pytest.raises(SessionRelevanceEvaluationError):
            await client.evaluate("q")


async def test_evaluate_many() -> None:
    conns = [_conn("a", "rest", D1)]
    router = Router({"a": lambda req: _ok(len(req.content))})
    async with _client(conns, router) as client:
        batches = await client.evaluate_many(["1", "22"])
    assert [b[0].session_relevance for b in batches] == ["1", "22"]


# -- deployment discovery -------------------------------------------------------


CONFIG_TEXT = """\
# dev systems
[[connections]]
name = "root"   # keep me
backend = "rest"
server = "root.example.com"
username = "u"
password = "p"
verify = true

[[connections]]
name = "wr"
backend = "webreports"
server = "wr.example.com"
username = "u"
password = "p"
verify = true
"""


def _wr_hash(value: str) -> httpx.Response:
    return httpx.Response(
        200,
        headers={"content-type": "text/xml"},
        text=(
            '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">'
            '<soapenv:Body><GetStructuredRelevanceResultResponse xmlns="http://schemas.bigfix.com/'
            f'Relevance"><StructuredRelevanceResult><results><String>{value}</String></results>'
            "<plural>false</plural><type>string</type><evaltime>1</evaltime>"
            "</StructuredRelevanceResult></GetStructuredRelevanceResultResponse></soapenv:Body>"
            "</soapenv:Envelope>"
        ),
    )


async def test_discovery_groups_and_writes_back(tmp_path: Path) -> None:
    path = tmp_path / "c.toml"
    path.write_text(CONFIG_TEXT)
    os.chmod(path, 0o600)
    config = load_config(path)

    def root_route(request: httpx.Request) -> httpx.Response:
        body = request.content.decode()
        if "sha256" in body:
            return httpx.Response(200, json={"result": [D1], "plural": False, "type": "string"})
        return _ok(5)

    wr_calls: list[str] = []

    def wr_route(request: httpx.Request) -> httpx.Response:
        wr_calls.append(request.content.decode())
        if DEPLOYMENT_ID_SESSION_RELEVANCE in request.content.decode():
            return _wr_hash(D1)
        raise AssertionError("same deployment as root: must not be queried")

    router = Router({"root": root_route, "wr": wr_route})
    async with AsyncSessionRelevanceClient(
        config, transport_factory=router.transport_for, trust=None
    ) as client:
        results = await client.evaluate("number of bes computers")
    (result,) = results
    assert result.connection == "root"  # rest preferred over webreports
    assert result.deployment_id == D1
    text = path.read_text()
    assert "# keep me" in text
    assert [c.deployment_id for c in load_config(path).connections] == [D1, D1]


async def test_failed_discovery_groups_by_name_and_is_not_written(tmp_path: Path) -> None:
    path = tmp_path / "c.toml"
    path.write_text(CONFIG_TEXT)
    os.chmod(path, 0o600)
    router = Router({"root": [REFUSED], "wr": [_wr_hash(D1), _wr_hash(D1)]})
    async with AsyncSessionRelevanceClient(
        load_config(path), transport_factory=router.transport_for, trust=None
    ) as client:
        results = await client.evaluate("1")
    assert len(results) == 2  # root is its own (unreachable) group this run
    assert load_config(path).connections[0].deployment_id is None


async def test_discovery_can_be_disabled() -> None:
    conns = [_conn("a", "rest"), _conn("b", "rest")]
    router = Router({c.name: [_ok()] for c in conns})
    async with _client(conns, router, discover=False) as client:
        results = await client.evaluate("1")
    assert len(results) == 2
    assert all("sha256" not in json.dumps(r.session_relevance) for r in results)


# -- explorer extras --------------------------------------------------------------


async def test_evaluate_explorer_uses_only_capable_connections() -> None:
    conns = [
        _conn("d1-wr", "webreports", D1),
        _conn("d1-root", "rest", D1),
        _conn("d2-wr", "webreports", D2),
    ]
    keyed = httpx.Response(200, json={"result": [{"id": 1}], "plural": True, "type": "integer"})
    router = Router({"d1-wr": [_ok()], "d1-root": [keyed], "d2-wr": [_ok()]})
    async with _client(conns, router) as client:
        results = await client.evaluate_explorer("q", keys="id")
    by_dep = results.by_deployment()
    assert by_dep[D1].connection == "d1-root"
    assert by_dep[D1].answers == ({"id": 1},)
    d2_error = by_dep[D2].error
    assert d2_error is not None
    assert d2_error.kind == "unsupported_feature"
    assert "d1-wr" not in router.calls and "d2-wr" not in router.calls


async def test_evaluate_stream_yields_in_completion_order() -> None:
    fast_done = asyncio.Event()

    async def slow(request: httpx.Request) -> httpx.Response:
        await asyncio.wait_for(fast_done.wait(), timeout=2)
        return _ok(1)

    conns = [_conn("d1", "rest", D1), _conn("d2", "rest", D2)]
    router = Router({"d1": slow, "d2": [_ok(2)]})
    seen: list[str] = []
    async with _client(conns, router) as client:
        async for result in client.evaluate_stream("q"):
            seen.append(str(result.connection))
            fast_done.set()  # d1 can only answer after d2's result was handed over
        # The batch form keeps deployment order regardless of who answers first.
        fast_done.clear()
        batch = client.evaluate("q")
        await asyncio.sleep(0)
        fast_done.set()
        assert [str(r.connection) for r in await batch] == ["d1", "d2"]
    assert seen == ["d2", "d1"]


async def test_evaluate_stream_mode_all_and_explorer() -> None:
    conns = [_conn("a", "rest", D1), _conn("b", "webreports", D1)]
    router = Router({"a": [_ok(1)], "b": [_ok(1)]})
    async with _client(conns, router, mode="all", discover=False) as client:
        streamed = [r async for r in client.evaluate_stream("q")]
        assert sorted(str(r.connection) for r in streamed) == ["a", "b"]
        explorer = [r async for r in client.evaluate_explorer_stream("q", keys="id")]
    kinds = {str(r.connection): r.error.kind if r.error else None for r in explorer}
    assert kinds["b"] == "unsupported_feature"


async def test_evaluate_stream_stops_remaining_work_when_abandoned() -> None:
    started = asyncio.Event()
    cancelled = asyncio.Event()

    async def hang(request: httpx.Request) -> httpx.Response:
        started.set()
        try:
            await asyncio.sleep(30)
        except asyncio.CancelledError:
            cancelled.set()
            raise
        return _ok()  # pragma: no cover

    conns = [_conn("d1", "rest", D1), _conn("d2", "rest", D2)]
    router = Router({"d1": hang, "d2": [_ok()]})
    async with _client(conns, router) as client:
        stream = client.evaluate_stream("q")
        first = await anext(stream)
        assert first.connection == "d2"
        await asyncio.wait_for(started.wait(), timeout=2)
        await stream.aclose()
    assert cancelled.is_set()


def _is_discovery(request: httpx.Request) -> bool:
    return DEPLOYMENT_ID_SESSION_RELEVANCE in unquote_plus(request.content.decode())


async def test_known_deployments_stream_before_discovery_finishes() -> None:
    release = asyncio.Event()

    async def late(request: httpx.Request) -> httpx.Response:
        if _is_discovery(request):
            await asyncio.wait_for(release.wait(), timeout=2)
            return _ok(D2, "string")
        return _ok(2)

    conns = [_conn("known", "rest", D1), _conn("late", "rest", None)]
    router = Router({"known": [_ok(1)], "late": late})
    seen: list[str] = []
    async with _client(conns, router, record_deployment_ids=False) as client:
        async for result in client.evaluate_stream("q"):
            seen.append(str(result.connection))
            release.set()  # discovery of "late" only ends after "known" streamed
    assert seen == ["known", "late"]


async def test_late_discovered_member_still_serves_as_failover() -> None:
    def late(request: httpx.Request) -> httpx.Response:
        return _ok(D1, "string") if _is_discovery(request) else _ok(7)

    conns = [_conn("d1-root", "rest", D1), _conn("d1-late", "rest", None)]
    router = Router({"d1-root": [REFUSED], "d1-late": late})
    async with _client(conns, router, record_deployment_ids=False) as client:
        (result,) = await client.evaluate("q")
    assert result.ok
    assert result.connection == "d1-late"
    assert result.answers == (7,)


async def test_batch_order_is_group_order_even_when_groups_start_late() -> None:
    def late(request: httpx.Request) -> httpx.Response:
        return _ok(D2, "string") if _is_discovery(request) else _ok(2)

    conns = [_conn("first", "rest", None), _conn("second", "rest", D1)]
    router = Router({"first": late, "second": [_ok(1)]})
    async with _client(conns, router, record_deployment_ids=False) as client:
        results = await client.evaluate("q")
    assert [str(r.connection) for r in results] == ["first", "second"]


async def test_result_count() -> None:
    conns = [_conn("a", "rest", D1), _conn("b", "webreports", D1), _conn("c", "rest", None)]

    def disc(request: httpx.Request) -> httpx.Response:
        return _ok(D2, "string")

    router = Router({"a": [_ok()], "b": [_ok()], "c": disc})
    async with _client(conns, router, record_deployment_ids=False) as client:
        assert client.result_count() is None  # depends on c's deployment id
        await client.evaluate("q")
        assert client.result_count() == 2
    async with _client(conns, router, discover=False) as client:
        assert client.result_count() == 2
    async with _client(conns, router, mode="all") as client:
        assert client.result_count() == 3


async def test_explorer_stream_validates_on_call() -> None:
    conns = [_conn("a", "rest", D1)]
    router = Router({"a": [_ok()]})
    async with _client(conns, router) as client:
        with pytest.raises(ValueError):
            client.evaluate_explorer_stream("q", keys="id {")
    assert router.calls == []


async def test_evaluate_stream_raise_errors_raises_at_the_failure() -> None:
    conns = [_conn("d1", "rest", D1)]
    error = httpx.Response(200, json={"result": [], "error": "bad"})
    router = Router({"d1": [error]})
    async with _client(conns, router, raise_errors=True) as client:
        with pytest.raises(SessionRelevanceEvaluationError):
            async for _ in client.evaluate_stream("q"):
                pass  # pragma: no cover


# -- %XX escapes (issue #5) --------------------------------------------------------


def _wr_strings(*leaves: str) -> httpx.Response:
    body = "".join(f"<String>{leaf}</String>" for leaf in leaves)
    return httpx.Response(
        200,
        headers={"content-type": "text/xml"},
        text=(
            '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">'
            '<soapenv:Body><GetStructuredRelevanceResultResponse xmlns="http://schemas.bigfix.com/'
            f'Relevance"><StructuredRelevanceResult><results>{body}</results>'
            "<plural>true</plural><type>string</type><evaltime>1</evaltime>"
            "</StructuredRelevanceResult></GetStructuredRelevanceResultResponse>"
            "</soapenv:Body></soapenv:Envelope>"
        ),
    )


def _escape_router() -> tuple[list[ConnectionConfig], Router]:
    conns = [_conn("r", "rest", D1), _conn("e", "explorer", D1), _conn("w", "webreports", D1)]
    decoded = httpx.Response(
        200, json={"result": ["a%b", "x\ny"], "plural": True, "type": "string"}
    )
    return conns, Router({"r": [decoded], "e": [decoded], "w": [_wr_strings("a%25b", "x%0ay")]})


async def test_answers_are_decoded_on_every_backend_by_default() -> None:
    conns, router = _escape_router()
    async with _client(conns, router, mode="all") as client:
        results = await client.evaluate("q")
    assert [r.answers for r in results] == [("a%b", "x\ny")] * 3


async def test_keep_escapes_agrees_on_every_backend() -> None:
    conns, router = _escape_router()
    async with _client(conns, router, mode="all") as client:
        results = await client.evaluate("q", unescape=False)
        streamed = [r async for r in client.evaluate_stream("q", unescape=False)]
        (many,) = await client.evaluate_many(["q"], unescape=False)
    for batch in (list(results), streamed, list(many)):
        assert sorted(str(r.connection) for r in batch) == ["e", "r", "w"]
        assert {r.answers for r in batch} == {("a%25b", "x%0ay")}
        assert {r.answer_strings for r in batch} == {("a%25b", "x%0ay")}


async def test_keep_escapes_on_explorer_extras() -> None:
    # Explorer `keys` answers are dicts: values are answer text, keys are not.
    conns = [_conn("e", "explorer", D1)]
    body = {
        "result": [{"id": 1, "name": {"label": "a\tb", "flag": True}}],
        "plural": True,
        "type": "( integer, ( string, boolean ) )",
    }
    async with _client(conns, Router({"e": [httpx.Response(200, json=body)]})) as client:
        keys = "{id name {label flag}}"
        results = await client.evaluate_explorer("q", keys=keys, unescape=False)
        streamed = [
            r async for r in client.evaluate_explorer_stream("q", keys=keys, unescape=False)
        ]
    expected = ({"id": 1, "name": {"label": "a%09b", "flag": True}},)
    assert results[0].answers == streamed[0].answers == expected
    assert "a%09b" in results[0].answer_strings[0]


async def test_keep_escapes_on_webreports_plain_method() -> None:
    fault = httpx.Response(
        500,
        headers={"content-type": "text/xml"},
        text=(
            '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">'
            "<soapenv:Body><soapenv:Fault><faultcode>soapenv:Server</faultcode>"
            "<faultstring>No such operation 'GetStructuredRelevanceResult'</faultstring>"
            "</soapenv:Fault></soapenv:Body></soapenv:Envelope>"
        ),
    )
    plain = httpx.Response(
        200,
        headers={"content-type": "text/xml"},
        text=(
            '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">'
            '<soapenv:Body><GetRelevanceResultResponse xmlns="http://schemas.bigfix.com/'
            'Relevance"><a>a%25b</a><a>x%0ay</a></GetRelevanceResultResponse>'
            "</soapenv:Body></soapenv:Envelope>"
        ),
    )
    conns = [_conn("w", "webreports", D1)]
    async with _client(conns, Router({"w": [fault, plain, plain]})) as client:
        decoded = await client.evaluate("q")
        escaped = await client.evaluate("q", unescape=False)
    assert decoded[0].answers == ("a%b", "x\ny")
    assert escaped[0].answers == ("a%25b", "x%0ay")
