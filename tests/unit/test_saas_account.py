"""`saas_sign_in`: a non-interactive BigFix SaaS sign-in that lists the servers.

For an app's "Add BigFix SaaS account" screen. Every login POST counts: 100
failed logins lock the account for good, so these tests count them. The
login body is the captured shape (tests/fixtures/saas/shape_login_ok.json).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
import pytest

import bigfix_remote_session_relevance as pkg
from bigfix_remote_session_relevance.backends.saas import (
    LOGIN_PATH,
    RELEVANCE_PATH,
    SaasBackend,
    SaasSessionPool,
)
from bigfix_remote_session_relevance.config import ConnectionConfig
from bigfix_remote_session_relevance.exceptions import ConfigError
from bigfix_remote_session_relevance.saas_account import SaasAccount, saas_sign_in

SAAS_FIXTURES = Path(__file__).parent.parent / "fixtures" / "saas"
EMAIL = "operator@example.com"


def _login_ok(*server_ids: str) -> httpx.Response:
    body = json.loads((SAAS_FIXTURES / "shape_login_ok.json").read_text())
    body["data"]["pids"]["bf"] = {i: {"uid": "00000000", "uname": EMAIL} for i in server_ids}
    return httpx.Response(
        200,
        json=body,
        headers=[("set-cookie", "accessToken=ACCESS-1; Path=/; HttpOnly; Secure")],
    )


def _login_fail(signal: str, status: int = 401) -> httpx.Response:
    return httpx.Response(
        status, json={"status": status, "message": "Unauthorized", "data": {"errorMessage": signal}}
    )


def _captured(name: str) -> httpx.Response:
    return httpx.Response(200, text=(SAAS_FIXTURES / "captured" / f"{name}.json").read_text())


class SaasServer:
    """Answers logins from a list, in order, and relevance with a capture."""

    def __init__(self, *logins: httpx.Response | Exception) -> None:
        self.logins = list(logins)
        self.requests: list[httpx.Request] = []
        self.transport = httpx.MockTransport(self._handle)

    def bodies(self, path: str) -> list[dict[str, Any]]:
        return [json.loads(r.content)["data"] for r in self.requests if r.url.path == path]

    def _handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if request.url.path == LOGIN_PATH:
            item = self.logins.pop(0)
            if isinstance(item, Exception):
                raise item
            return item
        if request.url.path == RELEVANCE_PATH:
            return _captured("singular_integer")
        raise AssertionError(f"unexpected request {request.url.path}")


def _no_prompt(prompt: str) -> str:
    raise AssertionError(f"unexpected prompt {prompt!r}")


# -- signing in -----------------------------------------------------------------------


async def test_one_server() -> None:
    server = SaasServer(_login_ok("160001489"))
    account = await saas_sign_in("login.bigfix.com", EMAIL, "pw", transport=server.transport)
    assert account == SaasAccount("login.bigfix.com", EMAIL, ("bf160001489",))
    assert account.ok
    # Signing in is all it does: one login, no query.
    assert [r.url.path for r in server.requests] == [LOGIN_PATH]
    assert server.bodies(LOGIN_PATH) == [{"email": EMAIL, "password": "pw"}]
    assert server.requests[0].url.host == "api.bigfix.com"


async def test_several_servers_all_listed_in_order() -> None:
    server = SaasServer(_login_ok("160001489", "160002000", "7"))
    account = await saas_sign_in("eulogin.bigfix.com", EMAIL, "pw", transport=server.transport)
    assert account.servers == ("bf160001489", "bf160002000", "bf7")
    assert len(server.requests) == 1
    assert server.requests[0].url.host == "euapi.bigfix.com"


async def test_rejected_password_is_returned_not_retried() -> None:
    server = SaasServer(_login_fail("Incorrect username or password."))
    account = await saas_sign_in("login.bigfix.com", EMAIL, "bad", transport=server.transport)
    assert not account.ok
    assert account.error is not None
    assert (account.error.kind, account.error.code) == ("authentication", "login_failed")
    assert account.error.backend == "saas"
    assert account.servers == ()
    assert len(server.requests) == 1


async def test_totp_required_without_a_code_asks_nothing() -> None:
    server = SaasServer(_login_fail("totp_required"))
    account = await saas_sign_in("login.bigfix.com", EMAIL, "pw", transport=server.transport)
    assert account.error is not None
    assert (account.error.kind, account.error.code) == ("authentication", "totp_required")
    assert len(server.requests) == 1


async def test_totp_answers_the_servers_challenge() -> None:
    server = SaasServer(_login_fail("totp_required"), _login_ok("1"))
    account = await saas_sign_in(
        "login.bigfix.com", EMAIL, "pw", totp="123456", transport=server.transport
    )
    assert account.ok
    assert account.servers == ("bf1",)
    # Two POSTs: the code goes only in answer to the server's own challenge.
    first, second = server.bodies(LOGIN_PATH)
    assert "totp" not in first
    assert second == {"email": EMAIL, "password": "pw", "totp": "123456"}


async def test_totp_unused_when_the_account_has_no_mfa() -> None:
    server = SaasServer(_login_ok("1"))
    account = await saas_sign_in(
        "login.bigfix.com", EMAIL, "pw", totp="123456", transport=server.transport
    )
    assert account.ok
    assert server.bodies(LOGIN_PATH) == [{"email": EMAIL, "password": "pw"}]


async def test_rejected_totp_is_returned_not_retried() -> None:
    server = SaasServer(_login_fail("totp_required"), _login_fail("mfa_mismatch"))
    account = await saas_sign_in(
        "login.bigfix.com", EMAIL, "pw", totp="000000", transport=server.transport
    )
    assert account.error is not None
    assert account.error.code == "mfa_mismatch"
    assert len(server.requests) == 2


async def test_prompt_is_asked_once_on_the_challenge() -> None:
    server = SaasServer(_login_fail("totp_required"), _login_ok("1"))
    prompts: list[str] = []

    def prompt(text: str) -> str:
        prompts.append(text)
        return " 654321 "

    account = await saas_sign_in(
        "login.bigfix.com", EMAIL, "pw", prompt=prompt, transport=server.transport
    )
    assert account.ok
    assert len(prompts) == 1
    assert server.bodies(LOGIN_PATH)[1]["totp"] == "654321"


async def test_prompt_unused_without_a_challenge() -> None:
    server = SaasServer(_login_ok("1"))
    account = await saas_sign_in(
        "login.bigfix.com", EMAIL, "pw", prompt=_no_prompt, transport=server.transport
    )
    assert account.ok


async def test_totp_and_prompt_together_is_a_caller_bug() -> None:
    with pytest.raises(ValueError, match="totp"):
        await saas_sign_in("login.bigfix.com", EMAIL, "pw", totp="1", prompt=_no_prompt)


@pytest.mark.parametrize(("email", "password"), [("", "pw"), ("  ", "pw"), (EMAIL, "")])
async def test_blank_credentials_send_nothing(email: str, password: str) -> None:
    # An empty password would still be a failed login on the account.
    server = SaasServer()
    account = await saas_sign_in("login.bigfix.com", email, password, transport=server.transport)
    assert account.error is not None
    assert account.error.kind == "authentication"
    assert server.requests == []


@pytest.mark.parametrize("host", ["bigfix.example.com", "http://login.bigfix.com"])
async def test_non_saas_host_raises_before_sending(host: str) -> None:
    # The login POST carries the password, so the host is allowlisted.
    server = SaasServer()
    with pytest.raises(ConfigError, match="SaaS"):
        await saas_sign_in(host, EMAIL, "pw", transport=server.transport)
    assert server.requests == []


async def test_service_outage_is_an_error_not_a_rejection() -> None:
    server = SaasServer(httpx.Response(503, text="Service Unavailable"))
    account = await saas_sign_in("login.bigfix.com", EMAIL, "pw", transport=server.transport)
    assert account.error is not None
    assert account.error.kind == "http"
    assert account.error.http_status == 503


async def test_unreachable_is_a_connection_error() -> None:
    server = SaasServer(httpx.ConnectError("no route"))
    account = await saas_sign_in("login.bigfix.com", EMAIL, "pw", transport=server.transport)
    assert account.error is not None
    assert account.error.kind == "connection"


# -- sharing the sign-in through a pool -----------------------------------------------


async def test_pool_lets_later_backends_reuse_the_sign_in() -> None:
    server = SaasServer(_login_ok("1"))
    pool = SaasSessionPool()
    account = await saas_sign_in(
        "login.bigfix.com", EMAIL, "pw", pool=pool, transport=server.transport
    )
    assert account.ok
    backend = SaasBackend(
        "login.bigfix.com", username=EMAIL, password="pw", transport=server.transport
    )
    pool.attach(backend)
    async with backend:
        result = await backend.evaluate("number of bes computers")
    assert result.ok
    assert [r.url.path for r in server.requests] == [LOGIN_PATH, RELEVANCE_PATH]
    assert "accessToken=ACCESS-1" in server.requests[1].headers["cookie"]


async def test_pool_keeps_a_rejected_sign_in_from_being_sent_again() -> None:
    server = SaasServer(_login_fail("Incorrect username or password."))
    pool = SaasSessionPool()
    for _ in range(3):
        account = await saas_sign_in(
            "login.bigfix.com", EMAIL, "bad", pool=pool, transport=server.transport
        )
        assert account.error is not None
        assert account.error.code == "login_failed"
    assert len(server.requests) == 1


async def test_pool_with_a_live_session_lists_without_a_login() -> None:
    server = SaasServer(_login_ok("1", "2"))
    pool = SaasSessionPool()
    await saas_sign_in("login.bigfix.com", EMAIL, "pw", pool=pool, transport=server.transport)
    again = await saas_sign_in(
        "login.bigfix.com", EMAIL, "pw", pool=pool, transport=server.transport
    )
    assert again.servers == ("bf1", "bf2")
    assert len(server.requests) == 1


# -- connections ----------------------------------------------------------------------


def test_one_server_needs_no_sid() -> None:
    (conn,) = SaasAccount("login.bigfix.com", EMAIL, ("bf1",)).connections()
    assert conn == ConnectionConfig(
        name="bigfix-saas",
        backend="saas",
        server="login.bigfix.com",
        username=EMAIL,
        verify=True,
    )
    assert conn.password is None
    assert conn.password_env is None


def test_one_connection_per_server_named_like_setup() -> None:
    account = SaasAccount("eulogin.bigfix.com", EMAIL, ("bf1", "bf2"))
    conns = account.connections()
    assert [(c.name, c.sid) for c in conns] == [
        ("bigfix-saas-eu-bf1", "bf1"),
        ("bigfix-saas-eu-bf2", "bf2"),
    ]
    assert {(c.backend, c.server, c.username, c.verify) for c in conns} == {
        ("saas", "eulogin.bigfix.com", EMAIL, True)
    }


def test_name_prefix() -> None:
    account = SaasAccount("login.bigfix.com", EMAIL, ("bf1", "bf2"))
    assert [c.name for c in account.connections(name_prefix="acme")] == ["acme-bf1", "acme-bf2"]
    (only,) = SaasAccount("login.bigfix.com", EMAIL, ("bf1",)).connections(name_prefix="acme")
    assert only.name == "acme"


def test_failed_sign_in_has_no_connections() -> None:
    from bigfix_remote_session_relevance.result import ResultError

    error = ResultError(kind="authentication", backend="saas", message="credentials rejected")
    assert SaasAccount("login.bigfix.com", EMAIL, error=error).connections() == ()


async def test_connections_evaluate_once_a_password_is_added() -> None:
    import dataclasses

    from bigfix_remote_session_relevance.backends.registry import backend_from_config

    server = SaasServer(_login_ok("1"), _login_ok("1"))
    account = await saas_sign_in("login.bigfix.com", EMAIL, "pw", transport=server.transport)
    (conn,) = account.connections()
    backend = backend_from_config(
        dataclasses.replace(conn, password="pw"), transport=server.transport
    )
    async with backend:
        result = await backend.evaluate("number of bes computers")
    assert result.ok


def test_exported() -> None:
    assert pkg.saas_sign_in is saas_sign_in
    assert pkg.SaasAccount is SaasAccount
    assert {"saas_sign_in", "SaasAccount"} <= set(pkg.__all__)
