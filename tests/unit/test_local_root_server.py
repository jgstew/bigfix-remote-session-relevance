"""Reading the local root server's own REST credentials (besapi's root-first login).

Linux runs a real (fake) CryptoUtility through subprocess; Windows logic runs
anywhere with a fake ``winreg`` module and the DPAPI call swapped out, and
the real DPAPI round trip runs only on Windows.
"""

from __future__ import annotations

import base64
import os
import stat
import sys
import types
from pathlib import Path
from typing import Any, Self

import pytest

from bigfix_remote_session_relevance import local_root_server as lrs
from bigfix_remote_session_relevance.backends.registry import (
    backend_from_config,
)
from bigfix_remote_session_relevance.config import (
    ConnectionConfig,
    load_config,
    redacted_summary,
    save_connection,
)
from bigfix_remote_session_relevance.exceptions import ConfigError
from bigfix_remote_session_relevance.local_root_server import (
    LocalRootServerError,
    detect,
    parse_credentials_file,
    read_credentials,
)

SECRET = "s3cr3t-Pa55"
ENCRYPTED = "{aes,1}QUJDREVGR0hJSktMTU5PUA=="

CREDENTIALS = f"""\
RESTUsername=rest_operator
  RESTPassword = {ENCRYPTED}
RESTURL=https://localhost:52311/api

not a key value line
"""

posix_only = pytest.mark.skipif(sys.platform == "win32", reason="runs a POSIX script")


def _fake_crypto_utility(path: Path, *, stdout: str = SECRET, exit_code: int = 0) -> Path:
    """A stand-in CryptoUtility: checks its argv, prints the plaintext."""
    script = f"""#!{sys.executable}
import sys
if sys.argv[1:] != ["-d", "-i", {ENCRYPTED!r}]:
    sys.stderr.write("bad args: %r" % (sys.argv[1:],))
    sys.exit(9)
sys.stdout.write({stdout!r} + "\\n")
sys.exit({exit_code})
"""
    path.write_text(script)
    path.chmod(0o755)
    return path


@pytest.fixture
def linux_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    apps = tmp_path / "Applications"
    apps.mkdir()
    creds = apps / "MasterOperatorCredentials"
    creds.write_text(CREDENTIALS)
    monkeypatch.setattr(lrs, "CREDENTIALS_FILE", creds)
    monkeypatch.setattr(lrs, "CRYPTO_UTILITY", _fake_crypto_utility(apps / "CryptoUtility"))
    return apps


# -- parsing --------------------------------------------------------------------


def test_parse_credentials_file_strips_and_keeps_key_case() -> None:
    assert parse_credentials_file(CREDENTIALS) == {
        "RESTUsername": "rest_operator",
        "RESTPassword": ENCRYPTED,
        "RESTURL": "https://localhost:52311/api",
    }


def test_parse_credentials_file_splits_on_first_equals_only() -> None:
    # Base64 padding and URLs with query strings contain "=" too.
    parsed = parse_credentials_file("RESTPassword={aes,1}AB==\nRESTURL=https://h:1/api?a=b")
    assert parsed == {"RESTPassword": "{aes,1}AB==", "RESTURL": "https://h:1/api?a=b"}


# -- Linux ------------------------------------------------------------------------


@posix_only
def test_linux_reads_and_decrypts(linux_root: Path) -> None:
    creds = read_credentials()
    assert (creds.server, creds.username, creds.password) == (
        "https://localhost:52311",
        "rest_operator",
        SECRET,
    )
    assert SECRET not in repr(creds)


def test_linux_no_credentials_file_is_not_a_root_server() -> None:
    with pytest.raises(LocalRootServerError, match="not a BigFix root server") as info:
        read_credentials()
    assert info.value.code == "local_credentials_absent"
    assert detect() == "absent"


@posix_only
def test_linux_unreadable_file_says_run_as_root(linux_root: Path) -> None:
    if sys.platform != "win32" and os.geteuid() == 0:
        pytest.skip("root can read any file")
    lrs.CREDENTIALS_FILE.chmod(0)
    try:
        assert detect() == "unreadable"
        with pytest.raises(LocalRootServerError, match="run as root") as info:
            read_credentials()
        assert info.value.code == "local_credentials_unreadable"
    finally:
        lrs.CREDENTIALS_FILE.chmod(stat.S_IRUSR | stat.S_IWUSR)


@posix_only
def test_linux_detect_readable(linux_root: Path) -> None:
    assert detect() == "readable"


@posix_only
def test_linux_crypto_utility_failure_never_leaks_output(
    linux_root: Path, caplog: pytest.LogCaptureFixture
) -> None:
    _fake_crypto_utility(lrs.CRYPTO_UTILITY, stdout=SECRET, exit_code=3)
    with pytest.raises(LocalRootServerError, match="CryptoUtility failed") as info:
        read_credentials()
    assert info.value.code == "local_credentials_decrypt_failed"
    assert SECRET not in str(info.value)
    assert SECRET not in caplog.text


def test_linux_missing_crypto_utility(linux_root: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(lrs, "CRYPTO_UTILITY", linux_root / "missing")
    with pytest.raises(LocalRootServerError, match="CryptoUtility") as info:
        read_credentials()
    assert info.value.code == "local_credentials_decrypt_failed"


@posix_only
@pytest.mark.parametrize("plaintext", ["", "abc"])
def test_linux_short_password_is_not_available(linux_root: Path, plaintext: str) -> None:
    _fake_crypto_utility(lrs.CRYPTO_UTILITY, stdout=plaintext)
    with pytest.raises(LocalRootServerError) as info:
        read_credentials()
    assert info.value.code == "local_credentials_decrypt_failed"


@posix_only
def test_linux_crypto_utility_timeout(linux_root: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    lrs.CRYPTO_UTILITY.write_text(f"#!{sys.executable}\nimport time\ntime.sleep(30)\n")
    monkeypatch.setattr(lrs, "CRYPTO_UTILITY_TIMEOUT", 0.5)
    with pytest.raises(LocalRootServerError, match="timed out") as info:
        read_credentials()
    assert info.value.code == "local_credentials_decrypt_failed"
    assert ENCRYPTED not in str(info.value)


@pytest.mark.parametrize("missing", ["RESTUsername", "RESTURL", "RESTPassword"])
def test_linux_incomplete_file(linux_root: Path, missing: str) -> None:
    text = "\n".join(line for line in CREDENTIALS.splitlines() if missing not in line)
    lrs.CREDENTIALS_FILE.write_text(text)
    with pytest.raises(LocalRootServerError, match=missing) as info:
        read_credentials()
    assert info.value.code == "local_credentials_incomplete"


# -- Windows (logic, anywhere) ------------------------------------------------------

REGISTRY_BLOB = b"\x01\x00\x00\x00" + b"dpapi-blob" * 8


def _fake_winreg(values: dict[str, Any] | None, open_error: type[Exception] | None = None) -> Any:
    """The slice of ``winreg`` the reader touches: OpenKey and QueryValueEx."""

    class Key:
        def __enter__(self) -> Self:
            return self

        def __exit__(self, *exc: object) -> None:
            pass

    opened: list[tuple[Any, ...]] = []

    def open_key(hive: Any, subkey: str, reserved: int = 0, access: int = 0) -> Key:
        opened.append((hive, subkey, access))
        if open_error is not None:
            raise open_error(2, "fake")
        if values is None:
            raise FileNotFoundError(2, "The system cannot find the file specified")
        return Key()

    def query_value_ex(key: Key, name: str) -> tuple[Any, int]:
        assert values is not None
        if name not in values:
            raise FileNotFoundError(2, "The system cannot find the file specified")
        return values[name], 1

    return types.SimpleNamespace(
        HKEY_LOCAL_MACHINE="HKLM",
        KEY_READ=0x20019,
        OpenKey=open_key,
        QueryValueEx=query_value_ex,
        opened=opened,
    )


@pytest.fixture
def windows(monkeypatch: pytest.MonkeyPatch) -> Any:
    """Switch to the Windows path; returns a setter for the fake registry."""
    monkeypatch.setattr(lrs, "_IS_WINDOWS", True)
    unprotected: list[bytes] = []

    def unprotect(blob: bytes) -> bytes:
        unprotected.append(blob)
        if blob != REGISTRY_BLOB:
            raise OSError(13, "The data is invalid")
        return (SECRET + "\r\n").encode()

    monkeypatch.setattr(lrs, "_dpapi_unprotect", unprotect)

    def install(values: dict[str, Any] | None, open_error: type[Exception] | None = None) -> Any:
        fake = _fake_winreg(values, open_error)
        monkeypatch.setitem(sys.modules, "winreg", fake)
        fake.unprotected = unprotected
        return fake

    return install


def _registry(**overrides: Any) -> dict[str, Any]:
    values: dict[str, Any] = {
        "RESTUsername": "rest_operator",
        "RESTURL": "https://bigfix.example.com:52311/api",
        "RESTPassword": "{obf}" + base64.b64encode(REGISTRY_BLOB).decode(),
    }
    values.update(overrides)
    return {k: v for k, v in values.items() if v is not None}


def test_windows_reads_registry_and_decrypts(windows: Any) -> None:
    fake = windows(_registry())
    creds = read_credentials()
    assert (creds.server, creds.username, creds.password) == (
        "https://bigfix.example.com:52311",
        "rest_operator",
        SECRET,
    )
    assert fake.opened == [("HKLM", lrs.REGISTRY_KEY, fake.KEY_READ)]
    assert fake.unprotected == [REGISTRY_BLOB]
    assert detect() == "readable"


def test_windows_password_without_obf_prefix(windows: Any) -> None:
    windows(_registry(RESTPassword=base64.b64encode(REGISTRY_BLOB).decode()))
    assert read_credentials().password == SECRET


def test_windows_no_registry_key_is_not_a_root_server(windows: Any) -> None:
    windows(None)
    assert detect() == "absent"
    with pytest.raises(LocalRootServerError, match="not a BigFix root server") as info:
        read_credentials()
    assert info.value.code == "local_credentials_absent"


def test_windows_access_denied_says_run_as_administrator(windows: Any) -> None:
    windows(_registry(), open_error=PermissionError)
    assert detect() == "unreadable"
    with pytest.raises(LocalRootServerError, match="administrator") as info:
        read_credentials()
    assert info.value.code == "local_credentials_unreadable"


@pytest.mark.parametrize(
    "password", ["{obf}not base64!", "{obf}" + base64.b64encode(b"x").decode()]
)
def test_windows_undecryptable_password(windows: Any, password: str) -> None:
    windows(_registry(RESTPassword=password))
    with pytest.raises(LocalRootServerError) as info:
        read_credentials()
    assert info.value.code == "local_credentials_decrypt_failed"


def test_windows_short_password_is_not_available(
    windows: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    windows(_registry())
    monkeypatch.setattr(lrs, "_dpapi_unprotect", lambda blob: b"abc")
    with pytest.raises(LocalRootServerError) as info:
        read_credentials()
    assert info.value.code == "local_credentials_decrypt_failed"


def test_windows_missing_value(windows: Any) -> None:
    windows(_registry(RESTUsername=None))
    with pytest.raises(LocalRootServerError, match="RESTUsername") as info:
        read_credentials()
    assert info.value.code == "local_credentials_incomplete"


def test_dpapi_is_windows_only() -> None:
    if sys.platform == "win32":
        pytest.skip("covered by the real round trip below")
    with pytest.raises(OSError, match="Windows"):
        lrs._dpapi_unprotect(REGISTRY_BLOB)


# -- Windows (real DPAPI) ------------------------------------------------------------


def _dpapi_protect_machine(plaintext: bytes) -> bytes:
    """CryptProtectData with machine scope, as the BigFix server stores RESTPassword."""
    if sys.platform != "win32":
        pytest.skip("DPAPI is Windows only")
    import ctypes
    from ctypes import wintypes

    class Blob(ctypes.Structure):
        _fields_ = (("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char)))

    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p
    buffer = ctypes.create_string_buffer(plaintext, len(plaintext))
    source = Blob(len(plaintext), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_char)))
    out = Blob()
    ok = crypt32.CryptProtectData(
        ctypes.byref(source), None, None, None, None, 4, ctypes.byref(out)
    )
    if not ok:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return ctypes.string_at(out.pbData, out.cbData)
    finally:
        kernel32.LocalFree(out.pbData)


@pytest.mark.skipif(sys.platform != "win32", reason="DPAPI is Windows only")
def test_real_dpapi_round_trip(monkeypatch: pytest.MonkeyPatch) -> None:
    blob = _dpapi_protect_machine(SECRET.encode())
    assert lrs._dpapi_unprotect(blob) == SECRET.encode()

    monkeypatch.setattr(lrs, "_IS_WINDOWS", True)
    fake = _fake_winreg(_registry(RESTPassword="{obf}" + base64.b64encode(blob).decode()))
    monkeypatch.setitem(sys.modules, "winreg", fake)
    assert read_credentials().password == SECRET


@pytest.mark.skipif(sys.platform != "win32", reason="DPAPI is Windows only")
def test_real_dpapi_rejects_garbage() -> None:
    with pytest.raises(OSError):
        lrs._dpapi_unprotect(b"not a dpapi blob")


# -- as a connection ------------------------------------------------------------------

OTHER = """\
schema_version = 1

[defaults]
read_timeout = 42
verify = false

[[connections]]
name = "remote-wr"
backend = "webreports"
server = "wr.example.com"
username = "wr"
password = "pw"
"""


@pytest.fixture
def root_server(monkeypatch: pytest.MonkeyPatch) -> Any:
    """Pretend this machine is a root server whose credentials are in the given state."""

    def set_state(state: str) -> None:
        monkeypatch.setattr(lrs, "detect", lambda: state)

    set_state("readable")
    return set_state


def _local(config: Any) -> list[ConnectionConfig]:
    return [c for c in config.connections if c.credentials == "local_root_server"]


def test_no_config_on_a_root_server_uses_its_credentials(root_server: Any) -> None:
    config = load_config()
    (conn,) = config.connections
    assert (conn.name, conn.backend, conn.auth, conn.auto_detected) == (
        "local-root-server",
        "rest",
        "local_root_server",
        True,
    )
    assert conn.username is None and conn.password is None
    assert conn.address.base_url == "https://localhost:52311"


def test_added_next_to_configured_connections_with_defaults(
    root_server: Any, tmp_path: Path
) -> None:
    path = tmp_path / "c.toml"
    path.write_text(OTHER)
    config = load_config(path)
    assert [c.name for c in config.connections] == ["remote-wr", "local-root-server"]
    (local,) = _local(config)
    assert (local.read_timeout, local.verify) == (42.0, False)


def test_not_a_root_server_adds_nothing(tmp_path: Path) -> None:
    assert load_config(tmp_path / "missing.toml").connections == ()


def test_unreadable_credentials_skipped_when_other_connections_exist(
    root_server: Any, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    # A normal user on a root server: don't fail every run on credentials
    # only root can read, when there is something else to query.
    root_server("unreadable")
    path = tmp_path / "c.toml"
    path.write_text(OTHER)
    caplog.set_level("INFO", logger="bigfix_remote_session_relevance.config")
    assert _local(load_config(path)) == []
    assert "root server" in caplog.text


def test_unreadable_credentials_kept_when_nothing_else_is_configured(root_server: Any) -> None:
    # Otherwise "no connections" would hide the real fix: run as root.
    root_server("unreadable")
    assert len(_local(load_config())) == 1


@pytest.mark.parametrize("value", ["0", "false", "no", "off"])
def test_env_var_opts_out(root_server: Any, monkeypatch: pytest.MonkeyPatch, value: str) -> None:
    monkeypatch.setenv("BFRSR_LOCAL_ROOT_SERVER", value)
    assert load_config().connections == ()


def test_defaults_key_opts_out(root_server: Any, tmp_path: Path) -> None:
    path = tmp_path / "c.toml"
    path.write_text(OTHER.replace("[defaults]", "[defaults]\nlocal_root_server = false"))
    assert _local(load_config(path)) == []


def test_defaults_key_must_be_bool(tmp_path: Path) -> None:
    path = tmp_path / "c.toml"
    path.write_text(OTHER.replace("[defaults]", '[defaults]\nlocal_root_server = "no"'))
    with pytest.raises(ConfigError, match="local_root_server"):
        load_config(path)


EXPLICIT = """\
schema_version = 1

[[connections]]
name = "this-root"
backend = "rest"
credentials = "local_root_server"
read_timeout = 7
"""


def test_explicit_connection_replaces_the_automatic_one(root_server: Any, tmp_path: Path) -> None:
    path = tmp_path / "c.toml"
    path.write_text(EXPLICIT)
    (conn,) = load_config(path).connections
    assert (conn.name, conn.server, conn.read_timeout, conn.auto_detected) == (
        "this-root",
        "localhost",
        7.0,
        False,
    )


def test_explicit_connection_rejects_server(tmp_path: Path) -> None:
    # RESTURL decides where the credentials go; a server here would be ignored.
    path = tmp_path / "c.toml"
    path.write_text(EXPLICIT + 'server = "bigfix01.example.com"\n')
    with pytest.raises(ConfigError, match="server"):
        load_config(path)


@pytest.mark.parametrize(
    ("extra", "match"),
    [
        ('username = "op"', "local_root_server"),
        ('password_env = "X"', "local_root_server"),
        ('token = "t"', "local_root_server"),
        ('client_cert = "c.pem"', "local_root_server"),
    ],
)
def test_explicit_connection_rejects_other_credentials(
    tmp_path: Path, extra: str, match: str
) -> None:
    path = tmp_path / "c.toml"
    path.write_text(EXPLICIT + extra + "\n")
    with pytest.raises(ConfigError, match=match):
        load_config(path)


@pytest.mark.parametrize(
    ("change", "match"),
    [
        (('backend = "rest"', 'backend = "explorer"'), "rest"),
        (("local_root_server", "somewhere_else"), "credentials"),
    ],
)
def test_explicit_connection_validation(
    tmp_path: Path, change: tuple[str, str], match: str
) -> None:
    path = tmp_path / "c.toml"
    path.write_text(EXPLICIT.replace(*change))
    with pytest.raises(ConfigError, match=match):
        load_config(path)


def test_save_round_trips_explicit_connection(tmp_path: Path) -> None:
    path = tmp_path / "c.toml"
    conn = ConnectionConfig(
        name="this-root", backend="rest", server="localhost", credentials="local_root_server"
    )
    save_connection(path, conn)
    text = path.read_text()
    assert 'credentials = "local_root_server"' in text
    assert "auto_detected" not in text
    assert "\nserver =" not in text
    (loaded,) = load_config(path).connections
    assert loaded.credentials == "local_root_server"


def _no_crypto_utility(linux_root: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Loading the config must never decrypt: any CryptoUtility run would fail.
    monkeypatch.setattr(lrs, "CRYPTO_UTILITY", linux_root / "missing")
    lrs.CREDENTIALS_FILE.write_text(
        CREDENTIALS.replace("https://localhost:52311/api", "https://bigfix01.example.com:52311/api")
    )


def test_address_is_rest_url_at_load_time(
    linux_root: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _no_crypto_utility(linux_root, monkeypatch)
    (auto,) = load_config().connections
    assert auto.address.base_url == "https://bigfix01.example.com:52311"
    path = tmp_path / "c.toml"
    path.write_text(EXPLICIT)
    (explicit,) = load_config(path).connections
    assert explicit.address.base_url == "https://bigfix01.example.com:52311"
    (row,) = redacted_summary(load_config(path))
    assert row["server"] == "https://bigfix01.example.com:52311"


def test_rest_url_tolerates_a_byte_order_mark(linux_root: Path) -> None:
    lrs.CREDENTIALS_FILE.write_text("\ufeff" + CREDENTIALS, encoding="utf-8")
    assert lrs.rest_url() == "https://localhost:52311"
    assert (
        parse_credentials_file(lrs.CREDENTIALS_FILE.read_text(encoding="utf-8-sig"))["RESTUsername"]
        == "rest_operator"
    )


def test_rest_url_is_none_when_unavailable() -> None:
    assert lrs.rest_url() is None


def test_redacted_summary_says_local_root_server(root_server: Any) -> None:
    (row,) = redacted_summary(load_config())
    assert (row["auth"], row["username"], row["password"]) == (
        "local_root_server",
        "local root server",
        "local root server",
    )


# -- building the backend ----------------------------------------------------------------


def _conn() -> ConnectionConfig:
    return ConnectionConfig(
        name="local-root-server",
        backend="rest",
        server="localhost",
        credentials="local_root_server",
        verify=False,
    )


def _fake_read(
    monkeypatch: pytest.MonkeyPatch, server: str = "https://bigfix.example.com:52311"
) -> list[str]:
    """Replace read_credentials; returns the names of the threads that called it."""
    import threading

    threads: list[str] = []

    def read() -> lrs.LocalRootCredentials:
        threads.append(threading.current_thread().name)
        return lrs.LocalRootCredentials(server, "rest_op", SECRET)

    monkeypatch.setattr(lrs, "read_credentials", read)
    return threads


async def test_backend_uses_local_credentials(
    monkeypatch: pytest.MonkeyPatch, recording_transport: type
) -> None:
    import httpx

    _fake_read(monkeypatch)
    rec = recording_transport([httpx.Response(200, json={"result": [1], "plural": False})])
    backend = backend_from_config(_conn(), transport=rec.transport)
    assert SECRET not in repr(backend)
    async with backend:
        result = await backend.evaluate("1")
    assert result.ok, result.error
    (req,) = rec.requests
    assert str(req.url) == "https://bigfix.example.com:52311/api/query"
    expected = base64.b64encode(f"rest_op:{SECRET}".encode()).decode()
    assert req.headers["authorization"] == f"Basic {expected}"
    assert result.server == "https://bigfix.example.com:52311"


async def test_backend_reads_credentials_once_off_the_event_loop(
    monkeypatch: pytest.MonkeyPatch, recording_transport: type
) -> None:
    # CryptoUtility can take seconds: never on the loop, never while building.
    import asyncio
    import threading

    import httpx

    threads = _fake_read(monkeypatch)
    rec = recording_transport([httpx.Response(200, json={"result": [1], "plural": False})])
    backend = backend_from_config(_conn(), transport=rec.transport)
    assert threads == []
    async with backend:
        results = await asyncio.gather(*(backend.evaluate("1") for _ in range(3)))
    assert all(r.ok for r in results)
    assert len(threads) == 1
    assert threads[0] != threading.current_thread().name


async def test_backend_failure_is_an_authentication_result(
    linux_root: Path, recording_transport: type
) -> None:
    import httpx

    lrs.CREDENTIALS_FILE.unlink()
    rec = recording_transport([httpx.Response(200, json={"result": [1], "plural": False})])
    async with backend_from_config(_conn(), transport=rec.transport) as backend:
        result = await backend.evaluate("1")
    assert rec.requests == []
    assert result.error is not None
    assert (result.error.kind, result.error.code) == ("authentication", "local_credentials_absent")
    assert "not a BigFix root server" in result.error.message
    assert result.connection == "local-root-server"


async def test_backend_bad_rest_url_is_an_authentication_result(
    monkeypatch: pytest.MonkeyPatch, recording_transport: type
) -> None:
    import httpx

    _fake_read(monkeypatch, server="https://:x/")
    rec = recording_transport([httpx.Response(200, json={"result": [1], "plural": False})])
    async with backend_from_config(_conn(), transport=rec.transport) as backend:
        result = await backend.evaluate("1")
    assert rec.requests == []
    assert result.error is not None
    assert (result.error.kind, result.error.code) == (
        "authentication",
        "local_credentials_incomplete",
    )
    assert SECRET not in result.error.message


# -- in the client ---------------------------------------------------------------------------

DEPLOYMENT = "a" * 64
REMOTE = """\
schema_version = 1

[[connections]]
name = "remote-root"
backend = "rest"
server = "remote.example.com"
username = "op"
password = "pw"
deployment_id = "{deployment}"
""".format(deployment="b" * 64)


def _answer(request: Any) -> Any:
    import httpx

    if "/api/query" not in str(request.url):
        return httpx.Response(404)
    return httpx.Response(200, json={"result": [DEPLOYMENT], "plural": False})


def _client(config: Any, **kwargs: Any) -> Any:
    import httpx

    from bigfix_remote_session_relevance.client import AsyncSessionRelevanceClient

    return AsyncSessionRelevanceClient(
        config, trust=None, transport_factory=lambda c: httpx.MockTransport(_answer), **kwargs
    )


def _failing_read(monkeypatch: pytest.MonkeyPatch) -> None:
    def read() -> lrs.LocalRootCredentials:
        raise lrs.LocalRootServerError("local_credentials_decrypt_failed", "CryptoUtility failed")

    monkeypatch.setattr(lrs, "read_credentials", read)


@pytest.mark.parametrize("mode", ["per_deployment", "all"])
async def test_failed_auto_connection_is_dropped_when_others_exist(
    root_server: Any,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    mode: str,
) -> None:
    # An existing setup that runs as root must not turn partial (exit 3)
    # because the automatic extra connection could not decrypt.
    _failing_read(monkeypatch)
    path = tmp_path / "c.toml"
    path.write_text(REMOTE)
    async with _client(load_config(path), mode=mode) as client:
        assert client.result_count() is None  # unknown until the credentials are read
        results = await client.evaluate("1")
        assert client.result_count() == 1
    assert [(r.connection, r.ok) for r in results] == [("remote-root", True)]
    assert "CryptoUtility failed" in caplog.text


async def test_failed_auto_connection_is_reported_when_alone(
    root_server: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    _failing_read(monkeypatch)
    async with _client(load_config()) as client:
        results = await client.evaluate("1")
    ((r,),) = [list(results)]
    assert r.connection == "local-root-server"
    assert r.error is not None and r.error.code == "local_credentials_decrypt_failed"


async def test_failed_explicit_connection_is_always_reported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _failing_read(monkeypatch)
    path = tmp_path / "c.toml"
    path.write_text(REMOTE + "\n" + EXPLICIT.replace("schema_version = 1\n", ""))
    async with _client(load_config(path), mode="all") as client:
        results = await client.evaluate("1")
    assert sorted((r.connection, r.ok) for r in results) == [
        ("remote-root", True),
        ("this-root", False),
    ]


async def test_auto_connection_deployment_id_is_cached_outside_the_config(
    root_server: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _fake_read(monkeypatch, server="https://localhost:52311")
    path = tmp_path / "c.toml"
    path.write_text(REMOTE)
    before = path.read_text()
    async with _client(load_config(path)) as client:
        found = await client.discover_deployments()
    assert found["local-root-server"] == DEPLOYMENT
    assert path.read_text() == before
    (local,) = _local(load_config(path))
    assert local.deployment_id == DEPLOYMENT


async def test_auto_connection_cache_respects_record_flag(
    root_server: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    _fake_read(monkeypatch, server="https://localhost:52311")
    async with _client(load_config(), record_deployment_ids=False) as client:
        await client.discover_deployments()
    (local,) = _local(load_config())
    assert local.deployment_id is None


async def test_auto_connection_cache_ignored_for_another_server(
    root_server: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    _fake_read(monkeypatch, server="https://elsewhere.example.com:52311")
    async with _client(load_config()) as client:
        await client.discover_deployments()
    (local,) = _local(load_config())  # still at https://localhost:52311
    assert local.deployment_id is None
