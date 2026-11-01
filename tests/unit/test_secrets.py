"""`secrets.py`: the SecretStore protocol, its stores and the default store.

Nothing here touches a real OS store: keyring is driven through fake
backends, and conftest pins `default_secret_store()` to "no store". The real
round trips are opt-in (``BFRSR_REAL_SECRET_STORE=1``, the
``real_secret_store`` marker), under a unique
service per run, cleaned up in ``finally``, and never change HOME (on macOS
the Keychain then shows a GUI dialog and the test hangs).
"""

from __future__ import annotations

import os
import sys
import types
import uuid
from typing import Any

import pytest

from bigfix_remote_session_relevance import secrets
from bigfix_remote_session_relevance.config import ConnectionConfig
from bigfix_remote_session_relevance.secrets import (
    SECRET_SERVICE,
    KeychainSecretStore,
    KeyringSecretStore,
    MemorySecretStore,
    SecretStore,
    default_secret_store,
    secret_account,
)

# -- MemorySecretStore ----------------------------------------------------------------


def test_memory_store_round_trip() -> None:
    store = MemorySecretStore()
    assert store.get("a") is None
    store.set("a", "one")
    store.set("a", "two")
    assert store.get("a") == "two"
    store.delete("a")
    assert store.get("a") is None
    store.delete("a")  # missing: a no-op


def test_memory_store_is_a_secret_store() -> None:
    store: SecretStore = MemorySecretStore({"x": "y"})
    assert store.name == "memory"
    assert store.get("x") == "y"


def test_memory_store_repr_hides_secrets() -> None:
    assert "hunter2" not in repr(MemorySecretStore({"acct": "hunter2"}))


# -- secret_account -------------------------------------------------------------------


def _conn(**kw: Any) -> ConnectionConfig:
    base: dict[str, Any] = {
        "name": "lab",
        "backend": "rest",
        "server": "bf.example.com",
        "username": "Admin",
    }
    return ConnectionConfig(**{**base, **kw})


def test_secret_account_is_backend_host_port_username() -> None:
    assert secret_account(_conn()) == "rest:bf.example.com:52311:admin"


def test_secret_account_survives_a_rename() -> None:
    assert secret_account(_conn(name="a")) == secret_account(_conn(name="b"))


def test_secret_account_spellings_of_one_server_agree() -> None:
    assert secret_account(_conn(server="https://BF.example.com:52311/api")) == secret_account(
        _conn()
    )


@pytest.mark.parametrize(
    "other",
    [
        {"backend": "explorer"},
        {"server": "bf2.example.com"},
        {"server": "bf.example.com:52312"},
        {"username": "operator"},
    ],
)
def test_secret_account_differs_by_backend_server_and_user(other: dict[str, Any]) -> None:
    assert secret_account(_conn(**other)) != secret_account(_conn())


def test_secret_account_without_username() -> None:
    assert secret_account(_conn(username=None)) == "rest:bf.example.com:52311:"


# -- KeyringSecretStore over a fake keyring backend ------------------------------------


class PasswordDeleteError(Exception):
    pass


class FakeBackend:
    """The slice of a keyring backend the adapter touches."""

    name = "fake"

    def __init__(self) -> None:
        self.items: dict[tuple[str, str], str] = {}

    def get_password(self, service: str, username: str) -> str | None:
        return self.items.get((service, username))

    def set_password(self, service: str, username: str, password: str) -> None:
        self.items[(service, username)] = password

    def delete_password(self, service: str, username: str) -> None:
        if (service, username) not in self.items:
            raise PasswordDeleteError("not found")
        del self.items[(service, username)]


@pytest.fixture
def fake_keyring(monkeypatch: pytest.MonkeyPatch) -> types.SimpleNamespace:
    """A stand-in ``keyring`` package: errors, and a get_keyring() backend."""
    errors = types.ModuleType("keyring.errors")
    errors.PasswordDeleteError = PasswordDeleteError  # type: ignore[attr-defined]
    module = types.ModuleType("keyring")
    state = types.SimpleNamespace(backend=FakeBackend(), module=module)
    module.get_keyring = lambda: state.backend  # type: ignore[attr-defined]
    module.errors = errors  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "keyring", module)
    monkeypatch.setitem(sys.modules, "keyring.errors", errors)
    return state


def test_keyring_store_round_trip(fake_keyring: types.SimpleNamespace) -> None:
    store = KeyringSecretStore()
    assert store.get("acct") is None
    store.set("acct", "one")
    store.set("acct", "ünïcode-✓ pw")  # update
    assert store.get("acct") == "ünïcode-✓ pw"
    assert fake_keyring.backend.items == {(SECRET_SERVICE, "acct"): "ünïcode-✓ pw"}
    store.delete("acct")
    assert store.get("acct") is None


def test_keyring_store_deleting_a_missing_item_is_a_no_op(
    fake_keyring: types.SimpleNamespace,
) -> None:
    KeyringSecretStore().delete("never-set")


def test_keyring_store_uses_its_service(fake_keyring: types.SimpleNamespace) -> None:
    KeyringSecretStore(service="svc-x").set("a", "b")
    assert fake_keyring.backend.items == {("svc-x", "a"): "b"}


def test_keyring_store_takes_a_backend() -> None:
    backend = FakeBackend()
    store = KeyringSecretStore(backend=backend)
    store.set("a", "b")
    assert backend.items == {(SECRET_SERVICE, "a"): "b"}


def test_keyring_store_lets_other_errors_through(fake_keyring: types.SimpleNamespace) -> None:
    # Only "nothing to delete" is swallowed; resolution decides about the rest.
    class Broken(FakeBackend):
        def get_password(self, service: str, username: str) -> str | None:
            raise OSError(1312, "CredRead")

    fake_keyring.backend = Broken()
    with pytest.raises(OSError):
        KeyringSecretStore().get("a")


@pytest.mark.parametrize(
    ("module", "cls", "expected"),
    [
        ("keyring.backends.macOS", "Keyring", "macOS Keychain"),
        ("keyring.backends.Windows", "WinVaultKeyring", "Windows Credential Manager"),
        ("keyring.backends.SecretService", "Keyring", "Secret Service"),
        ("keyring.backends.libsecret", "Keyring", "Secret Service"),
        ("keyring.backends.kwallet", "DBusKeyring", "KWallet"),
        ("keyrings.alt.file", "PlaintextKeyring", "keyring (fake)"),
    ],
)
def test_keyring_store_name_says_which_store(module: str, cls: str, expected: str) -> None:
    backend_cls = type(cls, (FakeBackend,), {"__module__": module})
    assert KeyringSecretStore(backend=backend_cls()).name == expected


def test_keyring_store_keeps_windows_passwords_on_this_machine() -> None:
    # keyring's default persistence is "enterprise", which roams with a
    # roaming profile; secrets here are per machine. A fresh instance, so the
    # process-wide keyring backend other code uses is left as it was.
    class WinVaultKeyring(FakeBackend):
        persist: object = "enterprise"

    WinVaultKeyring.__module__ = "keyring.backends.Windows"
    shared = WinVaultKeyring()
    store = KeyringSecretStore(backend=shared)
    assert store._backend is not shared
    assert store._backend.persist == "local machine"
    assert shared.persist == "enterprise"


# -- default_secret_store ----------------------------------------------------------------


def test_tests_see_no_default_store() -> None:
    # conftest pins this, so no test reaches the developer's real store.
    assert default_secret_store() is None


def test_default_store_is_probed_once(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[int] = []
    store = MemorySecretStore()

    def probe() -> SecretStore | None:
        calls.append(1)
        return store

    monkeypatch.setattr(secrets, "_default_store", secrets._UNPROBED)
    monkeypatch.setattr(secrets, "_probe_default_store", probe)
    assert default_secret_store() is store
    assert default_secret_store() is store
    assert calls == [1]


def test_a_failed_probe_is_tried_again(monkeypatch: pytest.MonkeyPatch) -> None:
    # A locked keyring at startup must not turn the store off for a
    # long-running app's whole life; "no store here" answers are kept.
    answers: list[Any] = [RuntimeError("locked"), MemorySecretStore()]

    def probe() -> SecretStore | None:
        answer = answers.pop(0)
        if isinstance(answer, Exception):
            raise secrets._ProbeFailedError from answer
        return answer  # type: ignore[no-any-return]

    monkeypatch.setattr(secrets, "_default_store", secrets._UNPROBED)
    monkeypatch.setattr(secrets, "_probe_default_store", probe)
    assert default_secret_store() is None
    first = default_secret_store()
    assert isinstance(first, MemorySecretStore)
    assert default_secret_store() is first


def test_probe_failure_is_reported_as_retryable(
    monkeypatch: pytest.MonkeyPatch, fake_keyring: types.SimpleNamespace
) -> None:
    class Locked(FakeBackend):
        def get_password(self, service: str, username: str) -> str | None:
            raise RuntimeError("KeyringLocked")

    fake_keyring.backend = Locked()
    monkeypatch.setattr(sys, "platform", "linux")
    with pytest.raises(secrets._ProbeFailedError):
        secrets._probe_default_store()


def test_keyring_store_unwraps_the_chainer() -> None:
    # With a second backend installed (keyrings.alt), keyring returns its
    # chainer; writes go to the first backend, so that is the one used.
    win = type("WinVaultKeyring", (FakeBackend,), {"__module__": "keyring.backends.Windows"})
    chainer = type("ChainerBackend", (FakeBackend,), {"__module__": "keyring.backends.chainer"})()
    chainer.backends = [win(), FakeBackend()]  # type: ignore[attr-defined]
    store = KeyringSecretStore(backend=chainer)
    assert store.name == "Windows Credential Manager"
    assert store._backend.persist == "local machine"


def test_keyring_store_delete_with_a_custom_backend_needs_no_keyring(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setitem(sys.modules, "keyring", None)
    monkeypatch.setitem(sys.modules, "keyring.errors", None)
    KeyringSecretStore(backend=FakeBackend()).delete("never-set")


def test_probe_uses_keyring_on_desktop(
    monkeypatch: pytest.MonkeyPatch, fake_keyring: types.SimpleNamespace
) -> None:
    monkeypatch.setattr(sys, "platform", "darwin")
    store = secrets._probe_default_store()
    assert isinstance(store, KeyringSecretStore)


def test_probe_none_without_keyring(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setitem(sys.modules, "keyring", None)  # import keyring -> ImportError
    assert secrets._probe_default_store() is None


@pytest.mark.parametrize("module", ["keyring.backends.fail", "keyring.backends.null"])
def test_probe_none_when_keyring_has_no_usable_backend(
    module: str, monkeypatch: pytest.MonkeyPatch, fake_keyring: types.SimpleNamespace
) -> None:
    # fail: headless Linux, iOS. null: the user turned keyring off
    # (PYTHON_KEYRING_BACKEND=keyring.backends.null.Keyring).
    fake_keyring.backend = type("Keyring", (FakeBackend,), {"__module__": module})()
    monkeypatch.setattr(sys, "platform", "linux")
    assert secrets._probe_default_store() is None


def test_probe_none_when_the_store_fails(
    monkeypatch: pytest.MonkeyPatch, fake_keyring: types.SimpleNamespace
) -> None:
    # Windows over key-auth SSH: every call, reads included, raises
    # pywintypes.error 1312, which is not a KeyringError.
    class Error1312(Exception):
        pass

    class NoLogonSession(FakeBackend):
        def get_password(self, service: str, username: str) -> str | None:
            raise Error1312(1312, "CredRead", "A specified logon session does not exist.")

    fake_keyring.backend = NoLogonSession()
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(secrets, "_default_store", secrets._UNPROBED)
    assert default_secret_store() is None


@pytest.mark.parametrize("platform", ["android"])
def test_probe_none_on_android(platform: str, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "platform", platform)
    assert secrets._probe_default_store() is None


def test_probe_uses_the_keychain_on_ios(monkeypatch: pytest.MonkeyPatch) -> None:
    probed: list[str] = []

    class FakeKeychain(MemorySecretStore):
        def get(self, account: str) -> str | None:
            probed.append(account)
            return None

    monkeypatch.setattr(sys, "platform", "ios")
    monkeypatch.setattr(secrets, "KeychainSecretStore", FakeKeychain)
    assert isinstance(secrets._probe_default_store(), FakeKeychain)
    assert probed  # one lookup, so a missing entitlement shows up here


def test_probe_none_when_the_ios_keychain_is_unusable(monkeypatch: pytest.MonkeyPatch) -> None:
    class NoEntitlement(MemorySecretStore):
        def get(self, account: str) -> str | None:
            raise secrets.KeychainError("read", -34018)  # errSecMissingEntitlement

    monkeypatch.setattr(sys, "platform", "ios")
    monkeypatch.setattr(secrets, "KeychainSecretStore", NoEntitlement)
    monkeypatch.setattr(secrets, "_default_store", secrets._UNPROBED)
    assert default_secret_store() is None


def test_keychain_error_says_the_status() -> None:
    err = secrets.KeychainError("read", -25308)
    assert err.status == -25308
    assert "-25308" in str(err)


def test_import_does_not_load_keyring_or_ctypes() -> None:
    # The default path (no password_store) must not pay for keyring's ~56 ms
    # import or ctypes.
    import subprocess

    # On Windows something below this package (as on main) already loads
    # ctypes, so only keyring is checked there.
    code = (
        "import sys; import bigfix_remote_session_relevance as p; "
        "p.load_config(); "
        "assert 'keyring' not in sys.modules, 'keyring imported eagerly'; "
        "assert sys.platform == 'win32' or 'ctypes' not in sys.modules, "
        "'ctypes imported eagerly'"
    )
    env = {**os.environ, "BFRSR_LOCAL_ROOT_SERVER": "0"}
    subprocess.run([sys.executable, "-c", code], check=True, env=env)  # noqa: S603


# -- real stores (opt-in) ----------------------------------------------------------------


def _real_backend() -> Any:
    # Named, not keyring.get_keyring(): conftest points keyring at its
    # always-failing backend.
    if sys.platform == "win32":
        from keyring.backends import Windows

        return Windows.WinVaultKeyring()
    from keyring.backends import macOS

    return macOS.Keyring()


def _real_round_trip(store: SecretStore) -> None:
    account = f"test-{uuid.uuid4().hex}"
    try:
        assert store.get(account) is None
        store.set(account, "first")
        store.set(account, "ünïcode-✓ pw")  # the duplicate/update path
        assert store.get(account) == "ünïcode-✓ pw"
        store.delete(account)
        assert store.get(account) is None
        store.delete(account)  # missing: a no-op
    finally:
        store.delete(account)


# conftest skips these without BFRSR_REAL_SECRET_STORE=1 and leaves HOME alone.
real_store = pytest.mark.real_secret_store


@real_store
@pytest.mark.skipif(sys.platform != "darwin", reason="macOS Keychain")
def test_real_keychain_round_trip_ctypes() -> None:
    _real_round_trip(KeychainSecretStore(service=f"bfrsr-test-{uuid.uuid4().hex}"))


@real_store
@pytest.mark.skipif(sys.platform not in ("darwin", "win32"), reason="keyring's OS store")
def test_real_keyring_round_trip() -> None:
    if sys.platform == "win32" and os.environ.get("SSH_CONNECTION"):
        pytest.skip("Windows Credential Manager fails over key-auth SSH (error 1312)")
    _real_round_trip(
        KeyringSecretStore(service=f"bfrsr-test-{uuid.uuid4().hex}", backend=_real_backend())
    )


@real_store
@pytest.mark.skipif(sys.platform != "darwin", reason="macOS Keychain")
def test_real_keychain_items_are_shared_with_keyring() -> None:
    service = f"bfrsr-test-{uuid.uuid4().hex}"
    ours = KeychainSecretStore(service=service)
    theirs = KeyringSecretStore(service=service, backend=_real_backend())
    try:
        ours.set("acct", "from-ctypes")
        assert theirs.get("acct") == "from-ctypes"
        theirs.set("acct", "from-keyring")
        assert ours.get("acct") == "from-keyring"
    finally:
        ours.delete("acct")
