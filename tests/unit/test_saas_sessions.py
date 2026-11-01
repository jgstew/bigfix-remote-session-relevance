"""Saved BigFix SaaS sessions (#29): reused across runs so MFA needs a code weekly.

The fake service below follows the behaviour recorded in the issue: the
access token's lifetime is its ``iat``/``exp``; refresh tokens are single-use
(a spent one gets 401); the refresh expiry is fixed at 7 days from login.
Tokens are unsigned JWTs whose payload claims match a live login (2026-11-01):
the access token carries the email as ``eml``.
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
import stat
import sys
import time
import uuid
from collections import Counter
from pathlib import Path
from typing import Any

import httpx
import pytest

from bigfix_remote_session_relevance import saas_sessions
from bigfix_remote_session_relevance.backends.saas import SaasBackend, SaasSessionPool
from bigfix_remote_session_relevance.config import ConnectionConfig, load_config
from bigfix_remote_session_relevance.saas_account import saas_sign_in
from bigfix_remote_session_relevance.saas_sessions import (
    SaasSessionStore,
    SavedSaasSession,
    default_saas_session_store,
    default_saas_sessions_path,
)
from bigfix_remote_session_relevance.secrets import MemorySecretStore
from bigfix_remote_session_relevance.server_address import ServerAddress

FIXTURES = Path(__file__).parent.parent / "fixtures"
EMAIL = "operator@example.com"
API = ServerAddress(scheme="https", host="api.bigfix.com", port=443)
WEEK = 7 * 24 * 3600
ANSWER = (FIXTURES / "saas" / "captured" / "singular_integer.json").read_text()


def _jwt(payload: dict[str, Any]) -> str:
    def part(obj: dict[str, Any]) -> str:
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()

    return f"{part({'alg': 'HS256', 'typ': 'JWT'})}.{part(payload)}.c2lnbmF0dXJl"


def _claims(token: str) -> dict[str, Any]:
    payload = token.split(".")[1]
    claims: dict[str, Any] = json.loads(
        base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))
    )
    return claims


class FakeSaas:
    """BigFix SaaS auth as observed: rotating single-use refresh tokens, wall-clock exp."""

    def __init__(self, *, mfa: bool = False, access_lifetime: int = 3600) -> None:
        self.mfa = mfa
        self.access_lifetime = access_lifetime
        self.paths: Counter[str] = Counter()
        self.login_bodies: list[dict[str, Any]] = []
        self.live_refresh: dict[str, int] = {}  # unspent refresh token -> its fixed exp
        self.issued_access: set[str] = set()
        self.expired_access_sent = 0
        self.on_refresh: Any = None  # hook(token) before a refresh is answered

    def transport(self) -> httpx.AsyncBaseTransport:
        return httpx.MockTransport(self._handle)

    def issue(
        self, *, refresh_exp: int | None = None, access_exp: int | None = None
    ) -> tuple[str, str]:
        now = int(time.time())
        access = _jwt(
            {
                "uId": "u",
                "eml": EMAIL,
                "iat": now,
                "exp": access_exp if access_exp is not None else now + self.access_lifetime,
                "jti": uuid.uuid4().hex,
            }
        )
        rexp = refresh_exp if refresh_exp is not None else now + WEEK
        refresh = _jwt({"iss": "x", "iat": now, "exp": rexp, "jti": uuid.uuid4().hex})
        self.issued_access.add(access)
        self.live_refresh[refresh] = rexp
        return access, refresh

    def _session_response(self, access: str, refresh: str) -> httpx.Response:
        claims = _claims(access)
        body = {
            "status": 200,
            "message": "Ok",
            "data": {
                "iat": claims["iat"],
                "exp": claims["exp"],
                "pids": {"bf": {"160001489": {"uid": "0", "uname": EMAIL}}},
            },
        }
        return httpx.Response(
            200,
            json=body,
            headers=[
                ("set-cookie", f"accessToken={access}; Path=/; HttpOnly; Secure"),
                ("set-cookie", f"refreshToken={refresh}; Path=/; HttpOnly; Secure"),
            ],
        )

    async def _handle(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        self.paths[path] += 1
        await asyncio.sleep(0.01)  # let concurrent callers overlap
        cookies = _cookies(request)
        if path == "/auth/v1/user/login":
            data = json.loads(request.content)["data"]
            self.login_bodies.append(data)
            if data.get("password") != "pw":
                return _fail("Incorrect username or password.")
            if self.mfa and "totp" not in data:
                return _fail("totp_required")
            return self._session_response(*self.issue())
        if path == "/auth/v1/token/refresh":
            token = cookies.get("refreshToken", "")
            if self.on_refresh is not None:
                self.on_refresh(token)
            rexp = self.live_refresh.pop(token, None)  # single-use
            if rexp is None or rexp <= time.time():
                return _fail("invalid refresh token")
            return self._session_response(*self.issue(refresh_exp=rexp))
        access = cookies.get("accessToken", "")
        if access not in self.issued_access:
            return _fail("unauthorized")
        if _claims(access)["exp"] <= time.time():
            # Observed: this can spend the refresh token without a
            # replacement, so the client must never send one.
            self.expired_access_sent += 1
            return _fail("expired")
        return httpx.Response(200, text=ANSWER, headers={"content-type": "application/json"})


def _cookies(request: httpx.Request) -> dict[str, str]:
    found: dict[str, str] = {}
    for part in request.headers.get("cookie", "").split(";"):
        name, _, value = part.strip().partition("=")
        if name:
            found[name] = value
    return found


def _fail(message: str) -> httpx.Response:
    return httpx.Response(
        401, json={"status": 401, "message": "Unauthorized", "data": {"errorMessage": message}}
    )


def _backend(fake: FakeSaas, store: Any = None, **kw: Any) -> SaasBackend:
    return SaasBackend(
        "login.bigfix.com",
        username=EMAIL,
        password="pw",
        transport=fake.transport(),
        session_store=store if store is not None else SaasSessionStore(),
        **kw,
    )


def _saved(
    fake: FakeSaas, *, access_in: float = 3000, refresh_in: float = WEEK - 600
) -> SavedSaasSession:
    now = time.time()
    access, refresh = fake.issue(access_exp=int(now + access_in), refresh_exp=int(now + refresh_in))
    return SavedSaasSession(
        access_token=access,
        refresh_token=refresh,
        access_exp=now + access_in,
        refresh_exp=now + refresh_in,
        servers=("bf160001489",),
        stored_at=now,
    )


async def _query(backend: SaasBackend) -> Any:
    async with backend:
        return await backend.evaluate("number of bes computers")


# -- the store ---------------------------------------------------------------------


def test_default_path_follows_the_data_dir(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    assert default_saas_sessions_path().name == ".remote_session_saas_sessions.toml"
    monkeypatch.setenv("BFRSR_HOME", str(tmp_path / "app"))
    assert default_saas_sessions_path() == tmp_path / "app" / ".remote_session_saas_sessions.toml"
    monkeypatch.setenv("BFRSR_SAAS_SESSIONS", str(tmp_path / "s.toml"))
    assert default_saas_sessions_path() == tmp_path / "s.toml"


def test_file_round_trip_is_private(tmp_path: Path) -> None:
    fake = FakeSaas()
    store = SaasSessionStore(tmp_path / "s.toml", secrets=None)
    saved = _saved(fake)
    store.save(API, "Operator@Example.com", saved)
    assert store.load(API, EMAIL) == saved  # the email in any case
    if sys.platform != "win32":
        assert stat.S_IMODE((tmp_path / "s.toml").stat().st_mode) == 0o600
    text = (tmp_path / "s.toml").read_text()
    assert "saas-session:api.bigfix.com:443:operator@example.com" in text
    assert "version = 1" in text
    assert text.startswith("# BigFix SaaS sessions")  # says what it is, and to keep it private
    assert "keep this file private" in text


def test_other_accounts_and_hosts_are_separate(tmp_path: Path) -> None:
    store = SaasSessionStore(tmp_path / "s.toml", secrets=None)
    store.save(API, EMAIL, _saved(FakeSaas()))
    eu = ServerAddress(scheme="https", host="euapi.bigfix.com", port=443)
    assert store.load(eu, EMAIL) is None
    assert store.load(API, "someone@example.com") is None


def test_interrupted_write_keeps_the_old_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = SaasSessionStore(tmp_path / "s.toml", secrets=None)
    first = _saved(FakeSaas())
    store.save(API, EMAIL, first)

    def boom(*_args: Any) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(os, "replace", boom)
    with pytest.raises(OSError, match="disk full"):
        store.save(API, EMAIL, _saved(FakeSaas()))
    monkeypatch.undo()
    assert store.load(API, EMAIL) == first
    assert [p.name for p in tmp_path.iterdir() if p.name.startswith(".s.toml")] == []


@pytest.mark.parametrize(
    "text",
    [
        "not = [valid toml",
        '[sessions."saas-session:api.bigfix.com:443:operator@example.com"]\nversion = 1\n',
        (
            '[sessions."saas-session:api.bigfix.com:443:operator@example.com"]\n'
            'version = 99\naccess_token = "a"\nrefresh_token = "r"\naccess_exp = 1\nrefresh_exp = 1\n'
        ),
        "sessions = 3\n",
    ],
)
def test_a_corrupt_file_is_no_session_and_is_replaced(tmp_path: Path, text: str) -> None:
    path = tmp_path / "s.toml"
    path.write_text(text)
    store = SaasSessionStore(path, secrets=None)
    assert store.load(API, EMAIL) is None
    saved = _saved(FakeSaas())
    store.save(API, EMAIL, saved)
    assert store.load(API, EMAIL) == saved


def test_an_entry_for_another_email_is_ignored(tmp_path: Path) -> None:
    # The access token's own email claim must match the connection's.
    store = SaasSessionStore(tmp_path / "s.toml", secrets=None)
    store.save(API, "someone@example.com", _saved(FakeSaas()))  # eml claim: EMAIL
    assert store.load(API, "someone@example.com") is None


def test_forget_only_drops_the_token_that_failed(tmp_path: Path) -> None:
    store = SaasSessionStore(tmp_path / "s.toml", secrets=None)
    newer = _saved(FakeSaas())
    store.save(API, EMAIL, newer)
    # Another process already wrote a newer pair: a stale failure keeps it.
    assert not store.forget(API, EMAIL, refresh_token="spent")
    assert store.load(API, EMAIL) == newer
    assert store.forget(API, EMAIL, refresh_token=newer.refresh_token)
    assert store.load(API, EMAIL) is None
    assert not store.forget(API, EMAIL)


def test_secret_store_holds_the_entry_when_there_is_one(tmp_path: Path) -> None:
    secrets = MemorySecretStore()
    store = SaasSessionStore(tmp_path / "s.toml", secrets=secrets)
    saved = _saved(FakeSaas())
    store.save(API, EMAIL, saved)
    key = "saas-session:api.bigfix.com:443:operator@example.com"
    assert json.loads(secrets.get(key) or "")["refresh_token"] == saved.refresh_token
    assert not (tmp_path / "s.toml").exists()  # no token text on disk
    assert store.load(API, EMAIL) == saved
    assert store.forget(API, EMAIL)
    assert secrets.get(key) is None


class BrokenSecrets(MemorySecretStore):
    name = "broken"

    def __init__(self, *, get: bool = True, set: bool = True) -> None:
        super().__init__()
        self.fail_get, self.fail_set = get, set

    def get(self, account: str) -> str | None:
        if self.fail_get:
            raise RuntimeError("locked")
        return super().get(account)

    def set(self, account: str, secret: str) -> None:
        if self.fail_set:
            raise RuntimeError("too large")
        super().set(account, secret)


def test_a_failing_secret_store_falls_back_to_the_file(tmp_path: Path) -> None:
    store = SaasSessionStore(tmp_path / "s.toml", secrets=BrokenSecrets())
    saved = _saved(FakeSaas())
    store.save(API, EMAIL, saved)
    assert (tmp_path / "s.toml").exists()
    assert store.load(API, EMAIL) == saved


def test_corrupt_secret_store_entry_is_no_session(tmp_path: Path) -> None:
    key = "saas-session:api.bigfix.com:443:operator@example.com"
    store = SaasSessionStore(tmp_path / "s.toml", secrets=MemorySecretStore({key: "{nope"}))
    assert store.load(API, EMAIL) is None


def test_tokens_are_not_in_repr(tmp_path: Path) -> None:
    saved = _saved(FakeSaas())
    store = SaasSessionStore(tmp_path / "s.toml", secrets=None)
    for text in (repr(saved), str(saved), repr(store)):
        assert saved.access_token not in text
        assert saved.refresh_token not in text


def test_readable_file_is_warned_about(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    if sys.platform == "win32":
        pytest.skip("POSIX modes")
    store = SaasSessionStore(tmp_path / "s.toml", secrets=None)
    store.save(API, EMAIL, _saved(FakeSaas()))
    (tmp_path / "s.toml").chmod(0o644)
    with caplog.at_level(logging.WARNING):
        store.load(API, EMAIL)
    assert "chmod 600" in caplog.text


@pytest.mark.parametrize("value", ["0", "false", "no", "off", " OFF "])
def test_env_turns_the_default_store_off(monkeypatch: pytest.MonkeyPatch, value: str) -> None:
    monkeypatch.setenv("BFRSR_SESSION_CACHE", value)
    assert default_saas_session_store() is None


def test_default_store_is_on() -> None:
    assert isinstance(default_saas_session_store(), SaasSessionStore)


# -- the backend: reuse across runs ------------------------------------------------


async def test_a_saved_session_is_adopted_with_no_login() -> None:
    fake = FakeSaas()
    first = await _query(_backend(fake))
    assert first.ok, first.error
    assert fake.paths["/auth/v1/user/login"] == 1
    # A new process: a new backend, a new store object, the same file.
    second_backend = _backend(fake)
    second = await _query(second_backend)
    assert second.ok, second.error
    assert fake.paths["/auth/v1/user/login"] == 1
    assert fake.paths["/auth/v1/token/refresh"] == 0
    assert second_backend.servers == ("bf160001489",)


async def test_mfa_account_needs_a_code_only_once() -> None:
    fake = FakeSaas(mfa=True)
    prompted = await _query(_backend(fake, totp_prompt=lambda _m: "123456"))
    assert prompted.ok, prompted.error
    # Later, non-interactive runs: no prompt, no login, no code.
    for _ in range(2):
        result = await _query(_backend(fake))
        assert result.ok, result.error
    assert fake.paths["/auth/v1/user/login"] == 2  # the challenge and its answer, once


async def test_expired_access_token_is_refreshed_and_written_back() -> None:
    fake = FakeSaas()
    store = SaasSessionStore()
    old = _saved(fake, access_in=-60)
    store.save(API, EMAIL, old)
    result = await _query(_backend(fake))
    assert result.ok, result.error
    assert fake.paths["/auth/v1/token/refresh"] == 1
    assert fake.paths["/auth/v1/user/login"] == 0
    assert fake.expired_access_sent == 0
    new = store.load(API, EMAIL)
    assert new is not None
    assert new.refresh_token != old.refresh_token
    assert new.access_exp > time.time() + 3000
    # Refreshing never moves the refresh expiry: it is fixed from login.
    assert abs(new.refresh_exp - old.refresh_exp) < 5


async def test_access_token_about_to_expire_is_renewed_first() -> None:
    # Renewal keeps EXPIRY_SLACK_S on the wall-clock expiry, so no request
    # leaves with a token that expires on the way.
    fake = FakeSaas()
    SaasSessionStore().save(API, EMAIL, _saved(fake, access_in=10))
    result = await _query(_backend(fake))
    assert result.ok, result.error
    assert fake.paths["/auth/v1/token/refresh"] == 1


async def test_wall_clock_expiry_renews_before_sending(monkeypatch: pytest.MonkeyPatch) -> None:
    # A device that slept: the monotonic clock may not have moved, the wall
    # clock has. The renewal must come before the request, not after a 401.
    fake = FakeSaas()
    backend = _backend(fake)
    async with backend:
        assert (await backend.evaluate("1")).ok
        real = time.time
        monkeypatch.setattr(time, "time", lambda: real() + 3600)
        result = await backend.evaluate("1")
    assert result.ok, result.error
    assert fake.expired_access_sent == 0
    assert fake.paths["/auth/v1/token/refresh"] == 1


async def test_two_processes_racing_refresh_once() -> None:
    fake = FakeSaas()
    SaasSessionStore().save(API, EMAIL, _saved(fake, access_in=-60))
    # Separate backends, sessions and store objects: as two processes would be.
    backends = [_backend(fake, SaasSessionStore()) for _ in range(2)]
    results = await asyncio.gather(*(_query(b) for b in backends))
    assert all(r.ok for r in results), [r.error for r in results]
    assert fake.paths["/auth/v1/token/refresh"] == 1
    assert fake.paths["/auth/v1/user/login"] == 0
    saved = SaasSessionStore().load(API, EMAIL)
    assert saved is not None
    for b in backends:
        assert b._session.cookies.get("refreshToken") == saved.refresh_token


async def test_a_spent_refresh_token_rereads_the_store() -> None:
    # Another process (one that could not take the lock in time) rotated the
    # pair first: our refresh gets 401, and the newer pair in the store wins
    # over a fresh sign-in, which for an MFA account would need a code.
    fake = FakeSaas(mfa=True)
    store = SaasSessionStore()
    old = _saved(fake, access_in=-60)
    store.save(API, EMAIL, old)

    def other_process_wins(token: str) -> None:
        if token == old.refresh_token and token in fake.live_refresh:
            del fake.live_refresh[token]
            access, refresh = fake.issue(refresh_exp=int(old.refresh_exp))
            store.save(
                API,
                EMAIL,
                SavedSaasSession(
                    access_token=access,
                    refresh_token=refresh,
                    access_exp=time.time() + 3600,
                    refresh_exp=old.refresh_exp,
                    servers=old.servers,
                    stored_at=time.time(),
                ),
            )

    fake.on_refresh = other_process_wins
    result = await _query(_backend(fake))
    assert result.ok, result.error
    assert fake.paths["/auth/v1/user/login"] == 0
    assert fake.paths["/auth/v1/token/refresh"] == 1


async def test_a_spent_refresh_token_with_nothing_newer_drops_the_entry_and_signs_in() -> None:
    fake = FakeSaas()
    store = SaasSessionStore()
    old = _saved(fake, access_in=-60)
    del fake.live_refresh[old.refresh_token]  # spent elsewhere, nothing saved
    store.save(API, EMAIL, old)
    result = await _query(_backend(fake))
    assert result.ok, result.error
    assert fake.paths["/auth/v1/token/refresh"] == 1
    assert fake.paths["/auth/v1/user/login"] == 1
    new = store.load(API, EMAIL)
    assert new is not None and new.refresh_token != old.refresh_token


async def test_near_the_refresh_expiry_signs_in_instead() -> None:
    fake = FakeSaas()
    SaasSessionStore().save(API, EMAIL, _saved(fake, access_in=-60, refresh_in=1800))
    result = await _query(_backend(fake))
    assert result.ok, result.error
    assert fake.paths["/auth/v1/user/login"] == 1
    assert fake.paths["/auth/v1/token/refresh"] == 0
    new = SaasSessionStore().load(API, EMAIL)
    assert new is not None and new.refresh_exp > time.time() + WEEK - 60  # a new week


async def test_mfa_near_the_refresh_expiry_without_a_prompt_still_refreshes() -> None:
    # The login (password only: totp_required is not counted toward the
    # lockout) asks for a code no one can type; the refresh still works.
    fake = FakeSaas(mfa=True)
    SaasSessionStore().save(API, EMAIL, _saved(fake, access_in=-60, refresh_in=1800))
    result = await _query(_backend(fake))
    assert result.ok, result.error
    assert fake.paths["/auth/v1/user/login"] == 1
    assert fake.paths["/auth/v1/token/refresh"] == 1
    assert all("totp" not in body for body in fake.login_bodies)


async def test_mfa_with_no_usable_session_and_no_prompt() -> None:
    fake = FakeSaas(mfa=True)
    SaasSessionStore().save(API, EMAIL, _saved(fake, access_in=-60, refresh_in=-60))
    result = await _query(_backend(fake))
    assert result.error is not None
    assert (result.error.kind, result.error.code) == ("authentication", "totp_required")
    assert "saved session" in result.error.message
    assert "--setup" in result.error.message
    assert fake.paths["/auth/v1/user/login"] == 1  # password only, never a second POST
    assert all("totp" not in body for body in fake.login_bodies)


async def test_a_rejected_password_with_a_live_session_is_never_sent() -> None:
    # The saved session belongs to the account; using it sends no password.
    fake = FakeSaas()
    SaasSessionStore().save(API, EMAIL, _saved(fake))
    backend = SaasBackend(
        "login.bigfix.com",
        username=EMAIL,
        password="wrong",
        transport=fake.transport(),
        session_store=SaasSessionStore(),
    )
    assert (await _query(backend)).ok
    assert fake.paths["/auth/v1/user/login"] == 0


async def test_pooled_backends_save_once() -> None:
    fake = FakeSaas()
    pool = SaasSessionPool()
    backends = [_backend(fake, sid=f"bf{n}") for n in (1, 2, 3)]
    for b in backends:
        pool.attach(b)
    results = await asyncio.gather(*(b.evaluate("1") for b in backends))
    for b in backends:
        await b.aclose()
    assert all(r.ok for r in results)
    assert fake.paths["/auth/v1/user/login"] == 1
    assert SaasSessionStore().load(API, EMAIL) is not None


# -- opting out --------------------------------------------------------------------


async def test_session_store_none_reads_and_writes_nothing() -> None:
    fake = FakeSaas()
    SaasSessionStore().save(API, EMAIL, _saved(fake))
    before = default_saas_sessions_path().read_bytes()
    backend = SaasBackend(
        "login.bigfix.com",
        username=EMAIL,
        password="pw",
        transport=fake.transport(),
        session_store=None,
    )
    assert (await _query(backend)).ok
    assert fake.paths["/auth/v1/user/login"] == 1
    assert default_saas_sessions_path().read_bytes() == before


async def test_env_opt_out_reads_and_writes_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("BFRSR_SESSION_CACHE", "0")
    fake = FakeSaas()
    backend = SaasBackend(
        "login.bigfix.com", username=EMAIL, password="pw", transport=fake.transport()
    )
    assert (await _query(backend)).ok
    assert not default_saas_sessions_path().exists()


async def test_default_backend_saves_sessions() -> None:
    fake = FakeSaas()
    backend = SaasBackend(
        "login.bigfix.com", username=EMAIL, password="pw", transport=fake.transport()
    )
    assert (await _query(backend)).ok
    assert SaasSessionStore().load(API, EMAIL) is not None


def _conn(**kw: Any) -> ConnectionConfig:
    return ConnectionConfig(
        name="saas", backend="saas", server="login.bigfix.com", username=EMAIL, password="pw", **kw
    )


async def test_config_session_cache_false_reads_and_writes_nothing() -> None:
    fake = FakeSaas()
    backend = SaasBackend.from_config(_conn(session_cache=False), transport=fake.transport())
    assert (await _query(backend)).ok
    assert not default_saas_sessions_path().exists()


async def test_from_config_uses_the_injected_secret_store() -> None:
    fake = FakeSaas()
    secrets = MemorySecretStore()
    backend = SaasBackend.from_config(_conn(), transport=fake.transport(), secrets=secrets)
    assert (await _query(backend)).ok
    assert secrets.get("saas-session:api.bigfix.com:443:operator@example.com")
    assert not default_saas_sessions_path().exists()


def test_session_cache_in_the_config_file(tmp_path: Path) -> None:
    path = tmp_path / "c.toml"
    path.write_text(
        '[[connections]]\nname = "s"\nbackend = "saas"\nserver = "login.bigfix.com"\n'
        f'username = "{EMAIL}"\nsession_cache = false\n'
    )
    assert load_config(path).connections[0].session_cache is False
    path.write_text(path.read_text().replace("false", '"maybe"'))
    with pytest.raises(Exception, match="session_cache"):
        load_config(path)


# -- secrets out of sight ----------------------------------------------------------


async def test_tokens_never_reach_logs_or_results(caplog: pytest.LogCaptureFixture) -> None:
    fake = FakeSaas()
    SaasSessionStore().save(API, EMAIL, _saved(fake, access_in=-60))
    backend = _backend(fake)
    with caplog.at_level(logging.DEBUG):
        result = await _query(backend)
    assert result.ok
    saved = SaasSessionStore().load(API, EMAIL)
    assert saved is not None
    texts = [caplog.text, repr(backend), json.dumps(result.to_dict(), default=str)]
    for token in [*fake.issued_access, *fake.live_refresh]:
        for text in texts:
            assert token not in text


# -- explicit sign-in --------------------------------------------------------------


async def test_saas_sign_in_checks_the_password_and_seeds_the_store() -> None:
    fake = FakeSaas()
    SaasSessionStore().save(API, EMAIL, _saved(fake))
    account = await saas_sign_in("login.bigfix.com", EMAIL, "wrong", transport=fake.transport())
    # A saved session must not make a wrong password look right.
    assert account.error is not None
    assert account.error.code == "login_failed"
    account = await saas_sign_in("login.bigfix.com", EMAIL, "pw", transport=fake.transport())
    assert account.error is None
    assert fake.paths["/auth/v1/user/login"] == 2
    saved = SaasSessionStore().load(API, EMAIL)
    assert saved is not None and saved.access_token in fake.issued_access


def test_module_exports() -> None:
    assert set(saas_sessions.__all__) >= {
        "SaasSessionStore",
        "SavedSaasSession",
        "default_saas_session_store",
        "default_saas_sessions_path",
    }
