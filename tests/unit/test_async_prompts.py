"""Async password and TOTP prompts (#31): a GUI on the event loop awaits a dialog.

A prompt may return the answer or an awaitable of it; None or an empty answer
declines, and then nothing is sent. A TOTP code is sent at most once: 100
failed logins lock a BigFix SaaS account for good.
"""

from __future__ import annotations

import asyncio
import base64
import json
import warnings
from collections import Counter
from pathlib import Path
from typing import Any

import httpx
import pytest

from bigfix_remote_session_relevance import Prompt, abackend_from_config, ask
from bigfix_remote_session_relevance.backends.registry import backend_from_config
from bigfix_remote_session_relevance.backends.saas import SaasBackend
from bigfix_remote_session_relevance.client import AsyncSessionRelevanceClient
from bigfix_remote_session_relevance.config import Config, ConnectionConfig
from bigfix_remote_session_relevance.saas_account import saas_sign_in
from bigfix_remote_session_relevance.sync import SessionRelevanceClient

FIXTURES = Path(__file__).parent.parent / "fixtures"
LOGIN_OK_BODY = (FIXTURES / "saas" / "shape_login_ok.json").read_text()
D1 = "1" * 64
D2 = "2" * 64


def _login_ok() -> httpx.Response:
    return httpx.Response(
        200,
        text=LOGIN_OK_BODY,
        headers=[
            ("content-type", "application/json; charset=utf-8"),
            ("set-cookie", "accessToken=ACCESS-1; Path=/; HttpOnly; Secure"),
            ("set-cookie", "refreshToken=REFRESH-1; Path=/; HttpOnly; Secure"),
        ],
    )


def _signal(signal: str) -> httpx.Response:
    return httpx.Response(
        401, json={"status": 401, "message": "Unauthorized", "data": {"errorMessage": signal}}
    )


def _answer() -> httpx.Response:
    data = {"answer": [1], "plural": False, "type": "integer", "evaltime": 1}
    return httpx.Response(200, json={"status": 200, "data": data})


class Saas:
    """A fake BigFix SaaS account: login answers in order (the last repeats)."""

    def __init__(self, *logins: httpx.Response, refresh: httpx.Response | None = None) -> None:
        self.logins = list(logins)
        self.refresh = refresh or _signal("refresh refused")
        self.login_bodies: list[dict[str, Any]] = []
        self.paths: Counter[str] = Counter()

    def transport(self, _conn: Any = None) -> httpx.AsyncBaseTransport:
        return httpx.MockTransport(self._handle)

    async def _handle(self, request: httpx.Request) -> httpx.Response:
        self.paths[request.url.path] += 1
        await asyncio.sleep(0)
        if request.url.path == "/auth/v1/user/login":
            self.login_bodies.append(json.loads(request.content)["data"])
            return self.logins.pop(0) if len(self.logins) > 1 else self.logins[0]
        if request.url.path == "/auth/v1/token/refresh":
            return self.refresh
        return _answer()


def _saas(account: Saas, prompt: Prompt | None) -> SaasBackend:
    return SaasBackend(
        "login.bigfix.com",
        username="operator@example.com",
        password="pw",
        totp_prompt=prompt,
        transport=account.transport(),
    )


class AsyncPrompt:
    """An awaitable dialog: records each question, answers in order."""

    def __init__(self, *answers: str | None) -> None:
        self.answers = list(answers)
        self.asked: list[str] = []
        self.active = 0
        self.overlapped = False

    async def __call__(self, message: str) -> str | None:
        self.asked.append(message)
        self.active += 1
        self.overlapped |= self.active > 1
        try:
            await asyncio.sleep(0.01)  # the dialog is open: the loop keeps running
        finally:
            self.active -= 1
        return self.answers.pop(0) if len(self.answers) > 1 else self.answers[0]


# -- ask() -------------------------------------------------------------------------


async def test_ask_takes_sync_and_async_prompts() -> None:
    assert await ask(None, "q") is None
    assert await ask(lambda message: "sync", "q") == "sync"
    assert await ask(AsyncPrompt("async"), "q") == "async"
    assert await ask(AsyncPrompt(None), "q") is None


# -- TOTP -------------------------------------------------------------------------------


async def test_async_totp_prompt_answers_the_challenge() -> None:
    account = Saas(_signal("totp_required"), _login_ok())
    prompt = AsyncPrompt("123456")
    async with _saas(account, prompt) as backend:
        result = await backend.evaluate("1")
    assert result.ok, result.error
    assert len(prompt.asked) == 1
    assert "operator@example.com" in prompt.asked[0]
    assert account.paths["/auth/v1/user/login"] == 2
    assert account.login_bodies[1]["totp"] == "123456"


@pytest.mark.parametrize("answer", [None, "", "   "])
async def test_declined_totp_prompt_sends_nothing(answer: str | None) -> None:
    # A login with an empty code would be a wrong code: one toward the lockout.
    account = Saas(_signal("totp_required"), _login_ok())
    prompt = AsyncPrompt(answer)
    async with _saas(account, prompt) as backend:
        first = await backend.evaluate("1")
        again = await backend.evaluate("2")
    for result in (first, again):
        assert result.error is not None
        assert (result.error.kind, result.error.code) == ("authentication", "totp_required")
    assert account.paths["/auth/v1/user/login"] == 1
    assert len(prompt.asked) == 1  # one challenge, asked once


async def test_sync_totp_prompt_returning_none_sends_nothing() -> None:
    account = Saas(_signal("totp_required"), _login_ok())
    async with _saas(account, lambda message: None) as backend:
        result = await backend.evaluate("1")
    assert result.error is not None and result.error.code == "totp_required"
    assert account.paths["/auth/v1/user/login"] == 1


async def test_totp_code_is_stripped() -> None:
    account = Saas(_signal("totp_required"), _login_ok())
    async with _saas(account, AsyncPrompt(" 123456\n")) as backend:
        assert (await backend.evaluate("1")).ok
    assert account.login_bodies[1]["totp"] == "123456"


async def test_a_spent_totp_code_is_never_sent_again() -> None:
    # A front end that hands back the code it collected earlier: once used,
    # it is spent, and sending it again would be a wrong code.
    account = Saas(_signal("totp_required"), _login_ok(), _signal("totp_required"))
    prompt = AsyncPrompt("123456")
    async with _saas(account, prompt) as backend:
        assert (await backend.evaluate("1")).ok
        backend._session.until = 0.0  # expired; the refresh is refused: sign in again
        result = await backend.evaluate("2")
    assert result.error is not None
    assert (result.error.kind, result.error.code) == ("authentication", "totp_required")
    assert "already" in result.error.message
    assert [body.get("totp") for body in account.login_bodies] == [None, "123456", None]
    assert len(prompt.asked) == 2


async def test_totp_prompt_that_raises_propagates_and_sends_nothing() -> None:
    account = Saas(_signal("totp_required"), _login_ok())

    async def cancelled(message: str) -> str:
        raise KeyboardInterrupt

    async with _saas(account, cancelled) as backend:
        with pytest.raises(KeyboardInterrupt):
            await backend.evaluate("1")
    assert account.paths["/auth/v1/user/login"] == 1


async def test_saas_sign_in_with_an_async_prompt() -> None:
    account = Saas(_signal("totp_required"), _login_ok())
    prompt = AsyncPrompt("654321")
    signed_in = await saas_sign_in(
        "login.bigfix.com",
        "operator@example.com",
        "pw",
        prompt=prompt,
        transport=account.transport(),
    )
    assert signed_in.error is None
    assert len(prompt.asked) == 1
    assert account.login_bodies[1]["totp"] == "654321"


# -- TOTP through the client ----------------------------------------------------------


def _saas_conn(name: str = "saas", sid: str = "bf1") -> ConnectionConfig:
    return ConnectionConfig(
        name=name,
        backend="saas",
        server="login.bigfix.com",
        username="operator@example.com",
        password="pw",
        sid=sid,
        deployment_id=D1,
        verify=True,
    )


async def test_a_declined_challenge_is_asked_again_on_the_next_run() -> None:
    # One long-lived client (a GUI's): declining once must not lock the
    # account out of the app until it restarts. Within a run it is asked once.
    account = Saas(_signal("totp_required"), _signal("totp_required"), _login_ok())
    prompt = AsyncPrompt(None, "123456")
    conns = (_saas_conn("a", "bf1"), _saas_conn("b", "bf2"))
    async with AsyncSessionRelevanceClient(
        Config(connections=conns),
        mode="all",
        prompt=prompt,
        trust=None,
        transport_factory=account.transport,
    ) as client:
        first = await client.evaluate("1")
        second = await client.evaluate("1")
    assert all(r.error is not None and r.error.code == "totp_required" for r in first)
    assert second.ok, [r.error for r in second]
    assert len(prompt.asked) == 2
    assert [body.get("totp") for body in account.login_bodies] == [None, None, "123456"]


async def test_a_challenge_without_a_prompt_is_not_resent_on_the_next_run() -> None:
    account = Saas(_signal("totp_required"))
    async with AsyncSessionRelevanceClient(
        Config(connections=(_saas_conn(),)), trust=None, transport_factory=account.transport
    ) as client:
        await client.evaluate("1")
        await client.evaluate("2")
    assert account.paths["/auth/v1/user/login"] == 1


async def test_a_rejected_totp_code_is_not_resent_on_the_next_run() -> None:
    # mfa_mismatch counts toward the lockout: cached like any rejection.
    account = Saas(_signal("totp_required"), _signal("mfa_mismatch"))
    prompt = AsyncPrompt("111111", "222222")
    async with AsyncSessionRelevanceClient(
        Config(connections=(_saas_conn(),)),
        prompt=prompt,
        trust=None,
        transport_factory=account.transport,
    ) as client:
        first = await client.evaluate("1")
        second = await client.evaluate("2")
    for results in (first, second):
        assert results[0].error is not None and results[0].error.code == "mfa_mismatch"
    assert account.paths["/auth/v1/user/login"] == 2
    assert len(prompt.asked) == 1


# -- passwords ----------------------------------------------------------------------------


def _rest_conn(name: str, dep: str = D1, **kw: Any) -> ConnectionConfig:
    return ConnectionConfig(
        name=name,
        backend="rest",
        server=f"{name}.example.com",
        username="op",
        deployment_id=dep,
        verify=True,
        **kw,
    )


class Rest:
    def __init__(self) -> None:
        self.auth: list[str | None] = []

    def transport(self, _conn: Any = None) -> httpx.AsyncBaseTransport:
        def handle(request: httpx.Request) -> httpx.Response:
            self.auth.append(request.headers.get("authorization"))
            return httpx.Response(200, json={"result": [1], "plural": False, "type": "integer"})

        return httpx.MockTransport(handle)


def _basic(user: str, password: str) -> str:
    return "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()


async def test_async_password_prompt_is_asked_once() -> None:
    server = Rest()
    prompt = AsyncPrompt("s3cret")
    async with AsyncSessionRelevanceClient(
        [_rest_conn("root")], prompt=prompt, trust=None, transport_factory=server.transport
    ) as client:
        assert (await client.evaluate("1")).ok
        assert (await client.evaluate("2")).ok
    assert prompt.asked == ["Password for op on root: "]
    assert server.auth == [_basic("op", "s3cret")] * 2


async def test_async_password_prompts_never_overlap() -> None:
    # Two dialogs at once (or two questions on one terminal) would interleave.
    server = Rest()
    prompt = AsyncPrompt("pw")
    conns = [_rest_conn("a", D1), _rest_conn("b", D2)]
    async with AsyncSessionRelevanceClient(
        conns, prompt=prompt, trust=None, transport_factory=server.transport
    ) as client:
        # Concurrent runs on one client build each backend once.
        batches = await client.evaluate_many(["1", "2", "3"])
    assert all(batch.ok for batch in batches)
    assert sorted(prompt.asked) == ["Password for op on a: ", "Password for op on b: "]
    assert not prompt.overlapped


async def test_declined_password_prompt_is_an_authentication_result() -> None:
    server = Rest()
    async with AsyncSessionRelevanceClient(
        [_rest_conn("root")],
        prompt=AsyncPrompt(None),
        trust=None,
        transport_factory=server.transport,
    ) as client:
        results = await client.evaluate("1")
    assert results[0].error is not None and results[0].error.kind == "authentication"
    assert server.auth == []


def test_async_password_prompt_through_the_sync_client() -> None:
    # The sync client runs the async one on its own loop thread: an async
    # prompt runs there.
    server = Rest()
    prompt = AsyncPrompt("s3cret")
    with SessionRelevanceClient(
        [_rest_conn("root")], prompt=prompt, trust=None, transport_factory=server.transport
    ) as client:
        assert client.evaluate("1").ok
    assert server.auth == [_basic("op", "s3cret")]


async def test_aresolve_password() -> None:
    conn = _rest_conn("root")
    assert await conn.aresolve_password() is None
    assert await conn.aresolve_password(prompt=lambda message: "sync") == "sync"
    assert await conn.aresolve_password(prompt=AsyncPrompt("async")) == "async"
    inline = _rest_conn("root", password="inline")
    assert await inline.aresolve_password(prompt=AsyncPrompt("unused")) == "inline"


def test_sync_resolve_password_refuses_an_async_prompt() -> None:
    with warnings.catch_warnings():
        warnings.simplefilter("error")  # no "coroutine was never awaited"
        with pytest.raises(TypeError, match="aresolve_password"):
            _rest_conn("root").resolve_password(prompt=AsyncPrompt("async"))


async def test_abackend_from_config_awaits_the_password_prompt() -> None:
    server = Rest()
    backend = await abackend_from_config(
        _rest_conn("root"), prompt=AsyncPrompt("s3cret"), transport=server.transport()
    )
    async with backend:
        assert (await backend.evaluate("1")).ok
    assert server.auth == [_basic("op", "s3cret")]


def test_backend_from_config_refuses_an_async_password_prompt() -> None:
    with pytest.raises(TypeError, match=r"abackend_from_config|afrom_config"):
        backend_from_config(_rest_conn("root"), prompt=AsyncPrompt("s3cret"))


def test_backend_from_config_keeps_an_async_totp_prompt() -> None:
    # SaaS with a password: only the TOTP prompt is left, and it is awaited
    # in the sign-in, so a sync build takes an async prompt.
    backend = backend_from_config(_saas_conn(), prompt=AsyncPrompt("123456"))
    assert isinstance(backend, SaasBackend)


# -- review findings ---------------------------------------------------------------------


async def test_a_challenge_answered_with_a_code_is_never_asked_again() -> None:
    # If the service ever answers a sent code with totp_required again, that
    # code counted toward the lockout: cached for good, like mfa_mismatch.
    account = Saas(_signal("totp_required"))
    prompt = AsyncPrompt("000001", "000002", "000003")
    async with AsyncSessionRelevanceClient(
        Config(connections=(_saas_conn(),)),
        prompt=prompt,
        trust=None,
        transport_factory=account.transport,
    ) as client:
        for _ in range(3):
            await client.evaluate("1")
    assert [body.get("totp") for body in account.login_bodies] == [None, "000001"]
    assert len(prompt.asked) == 1


async def test_sign_in_keeps_a_challenge_answered_with_a_code() -> None:
    account = Saas(_signal("totp_required"))
    prompt = AsyncPrompt("000001", "000002")
    async with _saas(account, prompt) as backend:
        await backend.sign_in()
        await backend.sign_in()
    assert [body.get("totp") for body in account.login_bodies] == [None, "000001"]


async def test_a_prompt_that_raises_is_asked_once_per_run() -> None:
    # A cancelled dialog declines for the run: the other connections of the
    # account (and concurrent runs) must not sign in and ask again.
    account = Saas(_signal("totp_required"), _login_ok())
    asked: list[str] = []

    async def cancelled(message: str) -> str:
        asked.append(message)
        raise RuntimeError("dialog closed")

    conns = (_saas_conn("a", "bf1"), _saas_conn("b", "bf2"), _saas_conn("c", "bf3"))
    async with AsyncSessionRelevanceClient(
        Config(connections=conns),
        mode="all",
        prompt=cancelled,
        trust=None,
        transport_factory=account.transport,
    ) as client:
        with pytest.raises(RuntimeError):
            await client.evaluate_many(["1", "2", "3"])
    assert len(asked) == 1
    assert account.paths["/auth/v1/user/login"] == 1


async def test_a_raised_prompt_is_asked_again_next_run() -> None:
    account = Saas(_signal("totp_required"), _signal("totp_required"), _login_ok())
    answers: list[str | Exception] = [RuntimeError("closed"), "123456"]

    async def prompt(message: str) -> str:
        answer = answers.pop(0)
        if isinstance(answer, Exception):
            raise answer
        return answer

    async with AsyncSessionRelevanceClient(
        Config(connections=(_saas_conn(),)),
        prompt=prompt,
        trust=None,
        transport_factory=account.transport,
    ) as client:
        with pytest.raises(RuntimeError):
            await client.evaluate("1")
        assert (await client.evaluate("2")).ok
    assert [body.get("totp") for body in account.login_bodies] == [None, None, "123456"]
