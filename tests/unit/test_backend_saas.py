"""BigFix SaaS backend: login, envelope, relevance parsing, lockout safety.

Request shapes come from the service's OpenAPI spec and a live login
(2026-10-17); response bodies are captured (tests/fixtures/saas/captured).
"""

from __future__ import annotations

import asyncio
import json
import uuid
from collections import Counter
from pathlib import Path
from typing import Any

import httpx
import pytest

from bigfix_remote_session_relevance.backends.explorer_extras import supports_explorer_extras
from bigfix_remote_session_relevance.backends.rest import RestBackend
from bigfix_remote_session_relevance.backends.saas import (
    SaasBackend,
    SaasSessionPool,
    saas_api_address,
)
from bigfix_remote_session_relevance.exceptions import ConfigError
from bigfix_remote_session_relevance.server_address import normalize_server

FIXTURES = Path(__file__).parent.parent / "fixtures"
LOGIN_OK_BODY = (FIXTURES / "saas" / "shape_login_ok.json").read_text()


def _login_ok() -> httpx.Response:
    return httpx.Response(
        200,
        text=LOGIN_OK_BODY,
        headers=[
            ("content-type", "application/json; charset=utf-8"),
            ("set-cookie", "accessToken=ACCESS-1; Path=/; HttpOnly; Secure; SameSite=Strict"),
            ("set-cookie", "refreshToken=REFRESH-1; Path=/; HttpOnly; Secure; SameSite=Strict"),
        ],
    )


def _captured(name: str) -> httpx.Response:
    return httpx.Response(
        200,
        text=(FIXTURES / "saas" / "captured" / f"{name}.json").read_text(),
        headers={"content-type": "application/json; charset=utf-8"},
    )


def _auth_fail(signal: str | None = None, status: int = 401) -> httpx.Response:
    data = (
        {"errorMessage": signal} if signal else {"errorMessage": "Incorrect username or password."}
    )
    return httpx.Response(status, json={"status": status, "message": "Unauthorized", "data": data})


def _backend(rec: Any, **kw: Any) -> SaasBackend:
    return SaasBackend(
        "login.bigfix.com",
        username="operator@example.com",
        password="pw",
        transport=rec.transport,
        **kw,
    )


def _body(request: httpx.Request) -> dict[str, Any]:
    return json.loads(request.content)


# -- addressing ---------------------------------------------------------------------


@pytest.mark.parametrize(
    ("server", "api"),
    [
        ("login.bigfix.com", "https://api.bigfix.com"),
        ("https://login.bigfix.com", "https://api.bigfix.com"),
        ("eulogin.bigfix.com", "https://euapi.bigfix.com"),
        ("api.bigfix.com", "https://api.bigfix.com"),
        ("euapi.bigfix.com", "https://euapi.bigfix.com"),
    ],
)
def test_login_host_maps_to_api_host(server: str, api: str) -> None:
    assert saas_api_address(normalize_server(server, "saas")).base_url == api
    assert SaasBackend(server, username="u", password="p").address.base_url == api


@pytest.mark.parametrize(
    "server", ["tenant.example.com", "http://login.bigfix.com", "evillogin.attacker.com"]
)
def test_password_is_only_ever_sent_to_allowlisted_hosts(server: str) -> None:
    # The login POST carries the password, so the host is allowlisted
    # (https://login., eulogin., api., euapi.) rather than trusted from config.
    with pytest.raises(ConfigError, match="SaaS"):
        SaasBackend(server, username="u", password="p")


def test_no_explorer_extras() -> None:
    assert not supports_explorer_extras(SaasBackend("login.bigfix.com", username="u", password="p"))


# -- login and request shape ----------------------------------------------------------


async def test_login_then_query_request_shapes(recording_transport: type) -> None:
    rec = recording_transport([_login_ok(), _captured("singular_integer")])
    async with _backend(rec) as backend:
        result = await backend.evaluate("number of bes computers")
    login, query = rec.requests
    assert (login.method, login.url.path) == ("POST", "/auth/v1/user/login")
    assert (query.method, query.url.path) == ("POST", "/bfproxy/v2/relevance")
    for request in (login, query):
        assert request.url.host == "api.bigfix.com"
        assert request.headers["x-bfnow-csrf-protection"] == "1"
        assert request.headers["content-type"] == "application/json"
        assert "authorization" not in request.headers
        body = _body(request)
        uuid.UUID(body["requestId"])
        assert body["timestamp"].isdigit()
        assert "sid" not in body
    assert _body(login)["data"] == {"email": "operator@example.com", "password": "pw"}
    assert _body(query)["data"] == {"query": "number of bes computers"}
    assert _body(login)["requestId"] != _body(query)["requestId"]
    # The session lives in the cookies the login set.
    assert "accessToken=ACCESS-1" in query.headers["cookie"]
    assert result.ok
    assert result.answers == (2,)
    assert result.backend == "saas"
    assert result.server == "https://api.bigfix.com"


async def test_logs_in_once_for_many_queries(recording_transport: type) -> None:
    rec = recording_transport(
        [_login_ok(), _captured("singular_string"), _captured("singular_integer")]
    )
    async with _backend(rec) as backend:
        await backend.evaluate('"hello"')
        await backend.evaluate("number of bes computers")
    assert [r.url.path for r in rec.requests] == [
        "/auth/v1/user/login",
        "/bfproxy/v2/relevance",
        "/bfproxy/v2/relevance",
    ]


async def test_sid_selects_the_server(recording_transport: type) -> None:
    rec = recording_transport([_login_ok(), _captured("singular_integer")])
    async with _backend(rec, sid="bf160001489") as backend:
        await backend.evaluate("number of bes computers")
    assert "sid" not in _body(rec.requests[0])  # the auth service takes no sid
    assert _body(rec.requests[1])["sid"] == "bf160001489"


async def test_servers_from_login(recording_transport: type) -> None:
    rec = recording_transport([_login_ok(), _captured("singular_integer")])
    async with _backend(rec) as backend:
        await backend.evaluate("1")
        assert backend.servers == ("bf160001489",)


# -- parsing --------------------------------------------------------------------------

SUCCESS = {
    "singular_integer": ((2,), "integer", False),
    "plural_tuples": (((1, "a", True), (2, "b", False)), "( integer, string, boolean )", True),
    "empty_plural": ((), "integer", True),
    "nested_tuple": (((1, (2, "x")),), "( integer, ( integer, string ) )", False),
    "special_chars": (("a+b & c \" <q> 's' \\ / ?x=1#y",), "string", False),
    "singular_string": (("hello",), "string", False),
    "time": (("Sat, 17 Oct 2026 23:11:52 +0000",), "time", False),
    "deployment_id": (("5" * 64,), "string", False),
}


@pytest.mark.parametrize("name", sorted(SUCCESS))
async def test_captured_success(name: str, recording_transport: type) -> None:
    rec = recording_transport([_login_ok(), _captured(name)])
    async with _backend(rec) as backend:
        result = await backend.evaluate("q")
    assert result.ok, result.error
    assert (result.answers, result.type, result.plural) == SUCCESS[name]
    assert result.evaluation_time_ms is not None
    assert result.raw is not None
    assert result.raw.format == "json"


async def test_captured_relevance_error(recording_transport: type) -> None:
    rec = recording_transport([_login_ok(), _captured("error_unknown")])
    async with _backend(rec) as backend:
        result = await backend.evaluate("foo bar baz")
    assert result.error is not None
    assert result.error.kind == "session_relevance"
    assert result.error.message == 'The operator "foo bar baz" is not defined.'
    assert result.answers == ()
    assert result.plural is None


@pytest.mark.parametrize("name", ["nested_tuple", "empty_plural", "error_unknown"])
async def test_agrees_with_rest(name: str, recording_transport: type) -> None:
    rest_dir = FIXTURES / "rest" / "captured"
    meta = json.loads((rest_dir / f"{name}.meta.json").read_text())
    rest_response = httpx.Response(meta["status"], text=(rest_dir / f"{name}.body").read_text())
    rec = recording_transport([rest_response])
    async with RestBackend("h", username="u", password="p", transport=rec.transport) as b:
        rest = await b.evaluate("q")
    rec2 = recording_transport([_login_ok(), _captured(name)])
    async with _backend(rec2) as backend:
        saas = await backend.evaluate("q")
    assert (saas.answers, saas.answer_strings, saas.type, saas.plural) == (
        rest.answers,
        rest.answer_strings,
        rest.type,
        rest.plural,
    )
    assert (saas.error and (saas.error.kind, saas.error.message)) == (
        rest.error and (rest.error.kind, rest.error.message)
    )


async def test_server_error_is_http(recording_transport: type) -> None:
    rec = recording_transport([_login_ok(), httpx.Response(502, text="Bad Gateway")])
    async with _backend(rec) as backend:
        result = await backend.evaluate("1")
    assert result.error is not None
    assert (result.error.kind, result.error.http_status) == ("http", 502)


async def test_non_json_is_response_format(recording_transport: type) -> None:
    rec = recording_transport(
        [
            _login_ok(),
            httpx.Response(200, text="<html>x</html>", headers={"content-type": "text/html"}),
        ]
    )
    async with _backend(rec) as backend:
        result = await backend.evaluate("1")
    assert result.error is not None
    assert result.error.kind == "response_format"


# -- authentication failures and lockout safety ---------------------------------------


async def test_bad_credentials_are_never_retried(recording_transport: type) -> None:
    # 100 failed logins lock a SaaS account permanently, so a rejected
    # password must not be POSTed again by this backend.
    rec = recording_transport([_auth_fail()])
    async with _backend(rec) as backend:
        first = await backend.evaluate("1")
        second = await backend.evaluate("1")
    assert len(rec.requests) == 1
    for result in (first, second):
        assert result.error is not None
        assert result.error.kind == "authentication"
        assert result.error.message == "credentials rejected"
        assert result.error.code == "login_failed"


@pytest.mark.parametrize(
    "signal",
    [
        "activate_mfa_required",
        "password_change_required",
        "mfa_mismatch",
        "max_concurrent_sessions_reached",
    ],
)
async def test_known_login_signals_become_codes(signal: str, recording_transport: type) -> None:
    rec = recording_transport([_auth_fail(signal)])
    async with _backend(rec) as backend:
        result = await backend.evaluate("1")
    assert result.error is not None
    assert (result.error.kind, result.error.code) == ("authentication", signal)
    assert len(rec.requests) == 1


async def test_totp_required_without_prompt(recording_transport: type) -> None:
    rec = recording_transport([_auth_fail("totp_required")])
    async with _backend(rec) as backend:
        result = await backend.evaluate("1")
    assert result.error is not None
    assert (result.error.kind, result.error.code) == ("authentication", "totp_required")
    assert len(rec.requests) == 1


async def test_totp_challenge_with_prompt(recording_transport: type) -> None:
    rec = recording_transport(
        [_auth_fail("totp_required"), _login_ok(), _captured("singular_integer")]
    )
    prompts: list[str] = []

    def prompt(message: str) -> str:
        prompts.append(message)
        return "123456"

    async with _backend(rec, totp_prompt=prompt) as backend:
        result = await backend.evaluate("1")
    assert result.ok, result.error
    assert len(prompts) == 1
    assert _body(rec.requests[1])["data"] == {
        "email": "operator@example.com",
        "password": "pw",
        "totp": "123456",
    }


async def test_expired_session_refreshes_then_retries(recording_transport: type) -> None:
    refreshed = httpx.Response(
        200,
        text=LOGIN_OK_BODY,
        headers=[("set-cookie", "accessToken=ACCESS-2; Path=/; HttpOnly; Secure")],
    )
    rec = recording_transport(
        [_login_ok(), _auth_fail(status=401), refreshed, _captured("singular_integer")]
    )
    async with _backend(rec) as backend:
        result = await backend.evaluate("1")
    assert result.ok, result.error
    assert [r.url.path for r in rec.requests] == [
        "/auth/v1/user/login",
        "/bfproxy/v2/relevance",
        "/auth/v1/token/refresh",
        "/bfproxy/v2/relevance",
    ]
    assert _body(rec.requests[2])["data"] is None
    assert "accessToken=ACCESS-2" in rec.requests[3].headers["cookie"]


async def test_failed_refresh_logs_in_again_once(recording_transport: type) -> None:
    rec = recording_transport(
        [
            _login_ok(),
            _auth_fail(status=401),  # query: session gone
            _auth_fail(status=401),  # refresh rejected
            _login_ok(),  # a fresh login: the earlier one succeeded, so this is safe
            _captured("singular_integer"),
        ]
    )
    async with _backend(rec) as backend:
        result = await backend.evaluate("1")
    assert result.ok, result.error
    assert [r.url.path for r in rec.requests][-2:] == [
        "/auth/v1/user/login",
        "/bfproxy/v2/relevance",
    ]


async def test_no_password_makes_no_request(recording_transport: type) -> None:
    rec = recording_transport([_login_ok()])
    async with SaasBackend(
        "login.bigfix.com", username="u", password=None, transport=rec.transport
    ) as backend:
        result = await backend.evaluate("1")
    assert result.error is not None
    assert result.error.kind == "authentication"
    assert rec.requests == []


def test_secrets_not_in_repr() -> None:
    assert "s3cret" not in repr(SaasBackend("login.bigfix.com", username="u", password="s3cret"))


# -- one sign-in per account ------------------------------------------------------------


class Account:
    """A fake BigFix SaaS account: counts requests per path across connections.

    Handlers yield to the event loop before answering, so concurrent
    connections really overlap while a login or refresh is in flight.
    ``logins`` are answered in order; the last one repeats.
    """

    def __init__(self, *logins: httpx.Response) -> None:
        self.paths: Counter[str] = Counter()
        self.sids: list[str | None] = []
        self.cookies: list[str] = []
        self._logins = list(logins) or [_login_ok()]
        self.refreshed = False

    def transport(self) -> httpx.AsyncBaseTransport:
        return httpx.MockTransport(self._handle)

    async def _handle(self, request: httpx.Request) -> httpx.Response:
        self.paths[request.url.path] += 1
        await asyncio.sleep(0.01)
        if request.url.path == "/auth/v1/user/login":
            return self._logins.pop(0) if len(self._logins) > 1 else self._logins[0]
        if request.url.path == "/auth/v1/token/refresh":
            self.refreshed = True
            return httpx.Response(
                200,
                text=LOGIN_OK_BODY,
                headers=[("set-cookie", "accessToken=ACCESS-2; Path=/; HttpOnly; Secure")],
            )
        cookie = request.headers.get("cookie", "")
        self.cookies.append(cookie)
        self.sids.append(_body(request).get("sid"))
        if self.refreshed and "accessToken=ACCESS-2" not in cookie:
            return _auth_fail(status=401)
        return _captured("singular_integer")


def _pooled(
    pool: SaasSessionPool,
    account: Account,
    *,
    server: str = "login.bigfix.com",
    email: str = "operator@example.com",
    password: str = "pw",
    sid: str | None = None,
    totp_prompt: Any = None,
) -> SaasBackend:
    backend = SaasBackend(
        server,
        username=email,
        password=password,
        sid=sid,
        totp_prompt=totp_prompt,
        transport=account.transport(),
    )
    pool.attach(backend)
    return backend


async def test_connections_of_one_account_share_one_login() -> None:
    # --setup saves one connection per sid; N servers must not mean N logins.
    account, pool = Account(), SaasSessionPool()
    backends = [_pooled(pool, account, sid=f"bf{n}") for n in (1, 2, 3)]
    results = await asyncio.gather(*(b.evaluate("1") for b in backends))
    results += await asyncio.gather(*(b.evaluate("2") for b in backends))
    for b in backends:
        await b.aclose()
    assert all(r.ok for r in results), [r.error for r in results]
    assert account.paths["/auth/v1/user/login"] == 1
    assert account.paths["/bfproxy/v2/relevance"] == 6
    assert Counter(account.sids) == Counter({"bf1": 2, "bf2": 2, "bf3": 2})
    # Every connection uses the one session's cookies.
    assert all("accessToken=ACCESS-1" in c for c in account.cookies)
    assert all(b.servers == ("bf160001489",) for b in backends)


async def test_rejected_login_is_shared_and_never_resent() -> None:
    # 100 failed logins lock the account for good: a wrong password must
    # cost one failure per run, not one per server.
    account, pool = Account(_auth_fail()), SaasSessionPool()
    backends = [_pooled(pool, account, sid=f"bf{n}") for n in (1, 2, 3)]
    results = await asyncio.gather(*(b.evaluate("1") for b in backends))
    for b in backends:
        results.append(await b.evaluate("2"))
        await b.aclose()
    assert account.paths == Counter({"/auth/v1/user/login": 1})
    for result in results:
        assert result.error is not None
        assert (result.error.kind, result.error.code) == ("authentication", "login_failed")


async def test_totp_is_asked_once_for_the_account() -> None:
    account = Account(_auth_fail("totp_required"), _login_ok())
    pool = SaasSessionPool()
    prompts: list[str] = []

    def prompt(message: str) -> str:
        prompts.append(message)
        return "123456"

    backends = [_pooled(pool, account, sid=f"bf{n}", totp_prompt=prompt) for n in (1, 2)]
    results = await asyncio.gather(*(b.evaluate("1") for b in backends))
    assert all(r.ok for r in results), [r.error for r in results]
    assert len(prompts) == 1
    assert account.paths["/auth/v1/user/login"] == 2  # the challenge, then the answer


async def test_concurrent_expiry_refreshes_once() -> None:
    # The refresh token appears to be single-use: two connections refreshing
    # at once would invalidate each other.
    account, pool = Account(), SaasSessionPool()
    backends = [_pooled(pool, account, sid=f"bf{n}") for n in (1, 2)]
    await asyncio.gather(*(b.evaluate("1") for b in backends))
    account.refreshed = True  # the server has expired ACCESS-1
    results = await asyncio.gather(*(b.evaluate("2") for b in backends))
    assert all(r.ok for r in results), [r.error for r in results]
    assert account.paths["/auth/v1/token/refresh"] == 1
    assert account.paths["/auth/v1/user/login"] == 1


@pytest.mark.parametrize(
    "other",
    [
        {"email": "someone.else@example.com"},
        {"password": "a different password"},
        {"server": "eulogin.bigfix.com"},
    ],
)
async def test_a_different_account_signs_in_separately(other: dict[str, str]) -> None:
    account, pool = Account(), SaasSessionPool()
    first = _pooled(pool, account)
    second = _pooled(pool, account, **other)
    await asyncio.gather(first.evaluate("1"), second.evaluate("1"))
    assert account.paths["/auth/v1/user/login"] == 2


async def test_backend_outside_a_pool_keeps_its_own_session() -> None:
    account = Account()
    backends = [
        SaasBackend(
            "login.bigfix.com",
            username="u@example.com",
            password="pw",
            transport=account.transport(),
        )
        for _ in range(2)
    ]
    await asyncio.gather(*(b.evaluate("1") for b in backends))
    assert account.paths["/auth/v1/user/login"] == 2


async def test_servers_from_login_skip_ids_that_are_not_plain_names(
    recording_transport: type,
) -> None:
    # A sid is printed by --setup and becomes part of a connection name.
    body = LOGIN_OK_BODY.replace('"160001489":', '"160001489":{},"\\u001b]0;x\\u0007":')
    login = _login_ok()
    rec = recording_transport(
        [httpx.Response(200, text=body, headers=login.headers), _captured("singular_integer")]
    )
    async with _backend(rec) as backend:
        await backend.evaluate("1")
        assert backend.servers == ("bf160001489",)
