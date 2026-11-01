"""``password_store = "system"``: parsing, resolution order and graceful fallback.

Order: ``password_env`` -> inline ``password`` -> the store -> the prompt.
A missing or empty store, or any exception from it, falls through, so one
TOML file works on every OS. No test here reaches a real OS store (conftest
pins `default_secret_store()` to None; stores are injected).
"""

from __future__ import annotations

import logging
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import httpx
import pytest

from bigfix_remote_session_relevance import secrets
from bigfix_remote_session_relevance.backends.registry import backend_from_config
from bigfix_remote_session_relevance.backends.rest import RestBackend
from bigfix_remote_session_relevance.client import AsyncSessionRelevanceClient
from bigfix_remote_session_relevance.config import (
    Config,
    ConnectionConfig,
    load_config,
    redacted_summary,
    save_connection,
)
from bigfix_remote_session_relevance.exceptions import ConfigError
from bigfix_remote_session_relevance.secrets import MemorySecretStore, secret_account
from bigfix_remote_session_relevance.sync import SessionRelevanceClient

SHARED = """\
schema_version = 1

[[connections]]
name = "lab"
backend = "rest"
server = "bf.example.com"
username = "operator"
password_store = "system"
"""


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    os.chmod(path, 0o600)
    return path


def _conn(**kw: Any) -> ConnectionConfig:
    base: dict[str, Any] = {
        "name": "lab",
        "backend": "rest",
        "server": "bf.example.com",
        "username": "operator",
        "password_store": "system",
    }
    return ConnectionConfig(**{**base, **kw})


def _stored(conn: ConnectionConfig, secret: str = "from-store") -> MemorySecretStore:
    return MemorySecretStore({secret_account(conn): secret})


class Prompt:
    def __init__(self, answer: str = "typed") -> None:
        self.answer = answer
        self.asked: list[str] = []

    def __call__(self, text: str) -> str:
        self.asked.append(text)
        return self.answer


class RaisingStore:
    """Like keyring on Windows over SSH: every call raises pywintypes.error 1312."""

    name = "Windows Credential Manager"

    def __init__(self) -> None:
        self.calls = 0

    def _fail(self) -> None:
        self.calls += 1
        raise OSError(1312, "CredRead", "A specified logon session does not exist.")

    def get(self, account: str) -> str | None:
        self._fail()
        return None

    def set(self, account: str, secret: str) -> None:
        self._fail()

    def delete(self, account: str) -> None:
        self._fail()


# -- parsing --------------------------------------------------------------------------


def test_password_store_system_parses(tmp_path: Path) -> None:
    (conn,) = load_config(_write(tmp_path / "c.toml", SHARED)).connections
    assert conn.password_store == "system"
    assert conn.password is None


def test_password_store_is_case_insensitive(tmp_path: Path) -> None:
    text = SHARED.replace('"system"', '" System "')
    (conn,) = load_config(_write(tmp_path / "c.toml", text)).connections
    assert conn.password_store == "system"


@pytest.mark.parametrize("value", ['"keychain"', '""', "true"])
def test_unknown_password_store_is_a_config_error(tmp_path: Path, value: str) -> None:
    text = SHARED.replace('"system"', value)
    with pytest.raises(ConfigError, match="password_store"):
        load_config(_write(tmp_path / "c.toml", text))


def test_password_store_with_a_token_is_a_config_error(tmp_path: Path) -> None:
    text = SHARED.replace('username = "operator"\n', 'token = "t"\n')
    with pytest.raises(ConfigError, match="not both"):
        load_config(_write(tmp_path / "c.toml", text))


def test_password_store_with_local_root_server_is_a_config_error(tmp_path: Path) -> None:
    text = SHARED.replace('server = "bf.example.com"\nusername = "operator"\n', "").replace(
        'password_store = "system"', 'password_store = "system"\ncredentials = "local_root_server"'
    )
    with pytest.raises(ConfigError, match="remove the other credentials"):
        load_config(_write(tmp_path / "c.toml", text))


def test_password_store_counts_as_basic_auth() -> None:
    assert _conn(username=None).auth == "basic"


def test_loading_a_store_config_does_not_touch_the_store(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Only resolution (building a backend) reads the store.
    def boom() -> None:
        raise AssertionError("store read at load time")

    monkeypatch.setattr(secrets, "default_secret_store", boom)
    load_config(_write(tmp_path / "c.toml", SHARED))


def test_loading_a_store_config_does_not_import_keyring(tmp_path: Path) -> None:
    path = _write(tmp_path / "c.toml", SHARED)
    code = (
        "import sys; from bigfix_remote_session_relevance import load_config; "
        f"load_config({str(path)!r}); "
        "assert 'keyring' not in sys.modules"
    )
    env = {**os.environ, "BFRSR_LOCAL_ROOT_SERVER": "0"}
    subprocess.run([sys.executable, "-c", code], check=True, env=env)  # noqa: S603


# -- resolution order -----------------------------------------------------------------


def test_store_is_used_when_nothing_else_is_set() -> None:
    conn = _conn()
    prompt = Prompt()
    assert conn.resolve_password(prompt=prompt, secrets=_stored(conn)) == "from-store"
    assert prompt.asked == []


def test_inline_password_beats_the_store() -> None:
    conn = _conn(password="inline")
    assert conn.resolve_password(secrets=_stored(conn)) == "inline"


def test_password_env_beats_inline_and_store(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TEST_BFRSR_PW", "from-env")
    conn = _conn(password="inline", password_env="TEST_BFRSR_PW")
    assert conn.resolve_password(secrets=_stored(conn)) == "from-env"


def test_unset_password_env_falls_through_to_the_store(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("TEST_BFRSR_PW", raising=False)
    conn = _conn(password_env="TEST_BFRSR_PW")
    assert conn.resolve_password(secrets=_stored(conn)) == "from-store"


def test_empty_store_falls_through_to_the_prompt() -> None:
    prompt = Prompt()
    assert _conn().resolve_password(prompt=prompt, secrets=MemorySecretStore()) == "typed"
    assert prompt.asked == ["Password for operator on lab: "]


def test_no_store_on_this_platform_falls_through_to_the_prompt() -> None:
    # conftest: default_secret_store() is None, as on Linux without keyring.
    assert secrets.default_secret_store() is None
    assert _conn().resolve_password(prompt=Prompt()) == "typed"


def test_explicit_no_store_falls_through_to_the_prompt() -> None:
    assert _conn().resolve_password(prompt=Prompt(), secrets=None) == "typed"


def test_no_store_and_no_prompt_is_none_not_an_error() -> None:
    assert _conn().resolve_password() is None


def test_store_is_not_read_without_password_store() -> None:
    conn = _conn(password_store=None)
    assert conn.resolve_password(prompt=Prompt(), secrets=_stored(conn)) == "typed"


def test_default_store_is_used_when_none_is_given(monkeypatch: pytest.MonkeyPatch) -> None:
    conn = _conn()
    monkeypatch.setattr(secrets, "_default_store", _stored(conn))
    assert conn.resolve_password() == "from-store"


def test_store_errors_fall_through_and_log_at_debug(caplog: pytest.LogCaptureFixture) -> None:
    # Not a KeyringError: Windows over SSH raises pywintypes.error 1312.
    store = RaisingStore()
    with caplog.at_level(logging.DEBUG, logger="bigfix_remote_session_relevance"):
        assert _conn().resolve_password(prompt=Prompt(), secrets=store) == "typed"
    assert store.calls == 1
    (record,) = (r for r in caplog.records if "Windows Credential Manager" in r.getMessage())
    assert record.levelno == logging.DEBUG
    assert "lab" in record.getMessage()


def test_default_store_errors_fall_through(monkeypatch: pytest.MonkeyPatch) -> None:
    def broken() -> None:
        raise RuntimeError("probe blew up")

    monkeypatch.setattr(secrets, "default_secret_store", broken)
    assert _conn().resolve_password(prompt=Prompt()) == "typed"


def test_one_file_works_with_and_without_a_store(tmp_path: Path) -> None:
    # The same TOML on a Mac (store has the entry) and on Linux (no store):
    # the same connections, only where the password comes from differs.
    path = _write(tmp_path / "c.toml", SHARED)
    mac, linux = load_config(path), load_config(path)
    assert mac.connections == linux.connections
    (conn,) = mac.connections
    mac_prompt, linux_prompt = Prompt(), Prompt()
    assert conn.resolve_password(prompt=mac_prompt, secrets=_stored(conn)) == "from-store"
    assert conn.resolve_password(prompt=linux_prompt, secrets=None) == "typed"
    assert (mac_prompt.asked, len(linux_prompt.asked)) == ([], 1)


# -- saving a prompted password ----------------------------------------------------------
# Offered when the backend is built, written only once the server accepts the
# password: a typo saved in the store would otherwise be resent on every run
# (and failed BigFix SaaS logins lock the account).


def _ok(request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, json={"result": [1], "plural": False, "type": "integer"})


def _backend(store: Any, handler: Any, save: Any = lambda _: True, **kw: Any) -> RestBackend:
    return RestBackend.from_config(
        _conn(verify=True, **kw),
        trust=None,
        prompt=Prompt(),
        secrets=store,
        save_prompted=save,
        transport=httpx.MockTransport(handler),
    )


async def test_prompted_password_is_saved_after_the_server_accepts_it() -> None:
    store, offered = MemorySecretStore(), []

    def save(name: str) -> bool:
        offered.append(name)
        return True

    async with _backend(store, _ok, save) as backend:
        assert offered == ["memory"]
        assert store.get(secret_account(_conn())) is None  # not before any request
        assert (await backend.evaluate("1")).ok
    assert store.get(secret_account(_conn())) == "typed"


async def test_session_relevance_error_still_proves_the_password() -> None:
    def error(request: httpx.Request) -> httpx.Response:
        return httpx.Response(400, text='Error: The operator "x" is not defined.')

    store = MemorySecretStore()
    async with _backend(store, error) as backend:
        result = await backend.evaluate("x")
    assert result.error is not None and result.error.kind == "session_relevance"
    assert store.get(secret_account(_conn())) == "typed"


async def test_rejected_password_is_never_saved() -> None:
    calls: list[int] = []

    def reject_once(request: httpx.Request) -> httpx.Response:
        calls.append(1)
        return httpx.Response(401, text="Login failed") if len(calls) == 1 else _ok(request)

    store = MemorySecretStore()
    async with _backend(store, reject_once) as backend:
        first = await backend.evaluate("1")
        assert first.error is not None and first.error.kind == "authentication"
        assert (await backend.evaluate("1")).ok  # even a later success saves nothing
    assert store.get(secret_account(_conn())) is None


async def test_save_waits_out_a_connection_error() -> None:
    calls = []

    def flaky(request: httpx.Request) -> httpx.Response:
        calls.append(1)
        if len(calls) == 1:
            raise httpx.ConnectError("refused")
        return _ok(request)

    store = MemorySecretStore()
    async with _backend(store, flaky) as backend:
        assert (await backend.evaluate("1")).error is not None
        assert store.get(secret_account(_conn())) is None
        assert (await backend.evaluate("1")).ok
    assert store.get(secret_account(_conn())) == "typed"


async def test_prompted_password_is_not_saved_when_declined() -> None:
    store = MemorySecretStore()
    async with _backend(store, _ok, lambda _: False) as backend:
        await backend.evaluate("1")
    assert store.get(secret_account(_conn())) is None


async def test_prompted_password_is_never_saved_implicitly() -> None:
    store = MemorySecretStore()
    async with _backend(store, _ok, None) as backend:
        await backend.evaluate("1")
    assert store.get(secret_account(_conn())) is None


def test_save_is_not_offered_without_password_store_or_a_store() -> None:
    offered: list[str] = []

    def save(name: str) -> bool:
        offered.append(name)
        return True

    _backend(MemorySecretStore(), _ok, save, password_store=None)
    _backend(None, _ok, save)
    assert offered == []


def test_save_is_not_offered_after_the_store_failed_to_read() -> None:
    offered: list[str] = []
    _backend(RaisingStore(), _ok, lambda name: offered.append(name) or True)
    assert offered == []


def test_empty_prompt_answer_is_not_offered() -> None:
    offered: list[str] = []
    RestBackend.from_config(
        _conn(verify=True),
        trust=None,
        prompt=Prompt(""),
        secrets=MemorySecretStore(),
        save_prompted=lambda name: offered.append(name) or True,
    )
    assert offered == []


async def test_failed_save_warns_and_the_query_still_answers(
    caplog: pytest.LogCaptureFixture,
) -> None:
    class ReadOnly(MemorySecretStore):
        def set(self, account: str, secret: str) -> None:
            raise OSError("read-only")

    with caplog.at_level(logging.WARNING):
        async with _backend(ReadOnly(), _ok) as backend:
            assert (await backend.evaluate("1")).ok
    assert any("could not save" in r.getMessage() for r in caplog.records)
    assert all("typed" not in r.getMessage() for r in caplog.records)


# -- writing and showing ------------------------------------------------------------------


def test_save_connection_writes_password_store_and_no_password(tmp_path: Path) -> None:
    path = tmp_path / "c.toml"
    save_connection(path, _conn())
    text = path.read_text()
    assert 'password_store = "system"' in text
    assert "password =" not in text
    (loaded,) = load_config(path).connections
    assert loaded.password_store == "system"


def test_redacted_summary_names_the_store(tmp_path: Path) -> None:
    config = Config(connections=(_conn(),))
    (row,) = redacted_summary(config, secrets=MemorySecretStore({"x": "never-shown"}))
    assert row["password"] == "memory"
    assert "never-shown" not in str(row)


def test_redacted_summary_without_a_store(tmp_path: Path) -> None:
    (row,) = redacted_summary(Config(connections=(_conn(),)))
    assert row["password"] == "system store (none on this machine)"


def test_redacted_summary_inline_and_env_still_win() -> None:
    config = Config(connections=(_conn(password="x"), _conn(name="b", password_env="NOPE_X")))
    rows = redacted_summary(config, secrets=MemorySecretStore())
    assert [r["password"] for r in rows] == ["stored in file", "env var (unset)"]


# -- injection: from_config and the clients ---------------------------------------------


def test_from_config_reads_the_injected_store() -> None:
    conn = _conn(verify=True)
    backend = RestBackend.from_config(conn, trust=None, secrets=_stored(conn))
    assert backend._password == "from-store"


async def test_backend_from_config_passes_secrets_and_save_prompted() -> None:
    conn, store = _conn(verify=True), MemorySecretStore()
    backend = backend_from_config(
        conn,
        trust=None,
        prompt=Prompt(),
        secrets=store,
        save_prompted=lambda _: True,
        transport=httpx.MockTransport(_ok),
    )
    async with backend:
        assert backend._password == "typed"
        await backend.evaluate("1")
    assert store.get(secret_account(conn)) == "typed"


def test_password_store_is_validated_in_code_too() -> None:
    with pytest.raises(ConfigError, match="password_store"):
        _conn(password_store="keychain")


async def test_async_client_takes_secrets() -> None:
    conn = _conn(verify=True)
    seen: list[str | None] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.headers.get("authorization"))
        return _ok(request)

    async with AsyncSessionRelevanceClient(
        [conn],
        trust=None,
        secrets=_stored(conn),
        discover=False,
        transport_factory=lambda c: httpx.MockTransport(handler),
    ) as client:
        (result,) = await client.evaluate("1")
    assert result.ok
    expected = httpx.BasicAuth("operator", "from-store")._auth_header
    assert seen and all(h == expected for h in seen)


def test_sync_client_takes_secrets() -> None:
    conn = _conn(verify=True)
    with SessionRelevanceClient(
        [conn],
        trust=None,
        secrets=_stored(conn),
        discover=False,
        transport_factory=lambda c: httpx.MockTransport(_ok),
    ) as client:
        (result,) = client.evaluate("1")
    assert result.ok
