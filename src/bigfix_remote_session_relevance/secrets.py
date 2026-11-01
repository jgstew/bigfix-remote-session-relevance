"""Where connection passwords can live instead of the config file.

A connection with ``password_store = "system"`` keeps its password in this
machine's OS secret store, keyed by `secret_account` (backend, server and
username, not the connection name), so one config file works on every OS
and each machine keeps its own secret. `default_secret_store` picks the
store:

* macOS, Windows (and Linux with the ``[keyring]`` extra): `KeyringSecretStore`,
  over `keyring <https://pypi.org/project/keyring/>`_. keyring's own settings
  (``PYTHON_KEYRING_BACKEND``, ``keyringrc.cfg``) can switch or turn it off.
* iOS: `KeychainSecretStore`, ``ctypes`` against Security.framework (keyring
  has no iOS backend). Items are this-device-only and unreadable while locked.
* Anything else: none; resolution falls through to the prompt.

An app passes its own `SecretStore` (an Android Keystore bridge, say) as
``secrets=``. Neither keyring nor ctypes is imported until a store is built.
"""

from __future__ import annotations

import contextlib
import logging
import sys
from typing import TYPE_CHECKING, Any, Final, Protocol

if TYPE_CHECKING:
    import ctypes

    from .config import ConnectionConfig

log = logging.getLogger(__name__)

SECRET_SERVICE: Final = "bigfix-remote-session-relevance"  # noqa: S105 - a name, not a secret

# The ``secrets=`` default everywhere: `default_secret_store()`, looked up only
# when a password_store password is needed. Any-typed so a parameter can be
# ``SecretStore | None`` (None: no store) and still default to it.
DEFAULT_SECRET_STORE: Any = object()


class SecretStore(Protocol):
    """Where connection secrets live. Keys are opaque account strings."""

    name: str  # for people: "macOS Keychain", "Windows Credential Manager"

    def get(self, account: str) -> str | None: ...
    def set(self, account: str, secret: str) -> None: ...
    def delete(self, account: str) -> None:
        """Remove the secret; a missing one is not an error."""
        ...


class MemorySecretStore:
    """A dict: for tests, and for apps that hold secrets themselves."""

    name = "memory"

    def __init__(self, secrets: dict[str, str] | None = None) -> None:
        self._secrets = dict(secrets or {})

    def __repr__(self) -> str:
        return f"MemorySecretStore(<{len(self._secrets)} secrets>)"

    def get(self, account: str) -> str | None:
        return self._secrets.get(account)

    def set(self, account: str, secret: str) -> None:
        self._secrets[account] = secret

    def delete(self, account: str) -> None:
        self._secrets.pop(account, None)


def secret_account(conn: ConnectionConfig) -> str:
    """Stable per-connection key: backend, server and username.

    Not the name, so renaming a connection keeps its secret, and the same
    file lines up with each machine's own store entry.
    """
    return f"{conn.backend}:{conn.address.host_port}:{(conn.username or '').lower()}"


# -- keyring (desktop) ---------------------------------------------------------------

# keyring backends by module, as people know them; others show keyring's own name.
_KEYRING_NAMES = {
    "keyring.backends.macOS": "macOS Keychain",
    "keyring.backends.Windows": "Windows Credential Manager",
    "keyring.backends.SecretService": "Secret Service",
    "keyring.backends.libsecret": "Secret Service",
    "keyring.backends.kwallet": "KWallet",
}
# Backends that hold nothing: fail raises on every call (headless Linux, iOS),
# null returns None (the user turned keyring off).
_UNUSABLE_KEYRING_MODULES = ("keyring.backends.fail", "keyring.backends.null")


class KeyringSecretStore:
    """Generic passwords under one service, through a keyring backend.

    ``backend`` defaults to ``keyring.get_keyring()``. On macOS keyring's
    items are the same Keychain items `KeychainSecretStore` reads and writes.
    """

    def __init__(self, service: str = SECRET_SERVICE, *, backend: Any = None) -> None:
        if backend is None:
            import keyring

            backend = keyring.get_keyring()
        if type(backend).__name__ == "WinVaultKeyring":
            # keyring's default, "enterprise", roams with a roaming profile;
            # these secrets stay on this machine. A new instance, so the
            # process-wide backend other code shares keeps its setting.
            backend = type(backend)()
            backend.persist = "local machine"
        self.service = service
        self._backend = backend
        module = type(backend).__module__
        self.name: str = _KEYRING_NAMES.get(module) or f"keyring ({getattr(backend, 'name', '')})"

    def __repr__(self) -> str:
        return f"KeyringSecretStore(service={self.service!r}, name={self.name!r})"

    def get(self, account: str) -> str | None:
        found: str | None = self._backend.get_password(self.service, account)
        return found

    def set(self, account: str, secret: str) -> None:
        self._backend.set_password(self.service, account, secret)

    def delete(self, account: str) -> None:
        from keyring.errors import PasswordDeleteError

        with contextlib.suppress(PasswordDeleteError):  # nothing to delete
            self._backend.delete_password(self.service, account)


# -- Apple Keychain via ctypes (iOS) -------------------------------------------------


class KeychainError(RuntimeError):
    def __init__(self, op: str, status: int) -> None:
        super().__init__(f"Keychain {op} failed: OSStatus {status}")
        self.status = status


_ERR_ITEM_NOT_FOUND = -25300
_ERR_DUPLICATE_ITEM = -25299
_UTF8 = 0x08000100


class KeychainSecretStore:
    """Generic-password items under one service, keyed by account.

    ``ctypes`` only, so it runs unchanged on macOS and iOS. On iOS items are
    ``kSecAttrAccessibleWhenUnlockedThisDeviceOnly``: not synced to iCloud,
    not readable while the device is locked. On macOS they go to the login
    keychain (the data-protection keychain needs entitlements an unsigned
    Python lacks).
    """

    name = "Keychain"

    def __init__(self, service: str = SECRET_SERVICE) -> None:
        import ctypes

        self.service = service
        self._ctypes = ctypes
        cf = ctypes.CDLL("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation")
        sec = ctypes.CDLL("/System/Library/Frameworks/Security.framework/Security")
        vp = ctypes.c_void_p
        cf.CFStringCreateWithCString.restype = vp
        cf.CFStringCreateWithCString.argtypes = [vp, ctypes.c_char_p, ctypes.c_uint32]
        cf.CFDataCreate.restype = vp
        cf.CFDataCreate.argtypes = [vp, ctypes.c_char_p, ctypes.c_long]
        cf.CFDataGetBytePtr.restype = vp
        cf.CFDataGetBytePtr.argtypes = [vp]
        cf.CFDataGetLength.restype = ctypes.c_long
        cf.CFDataGetLength.argtypes = [vp]
        cf.CFDictionaryCreate.restype = vp
        cf.CFDictionaryCreate.argtypes = [
            vp,
            ctypes.POINTER(vp),
            ctypes.POINTER(vp),
            ctypes.c_long,
            vp,
            vp,
        ]
        cf.CFRelease.argtypes = [vp]
        for fn in ("SecItemAdd", "SecItemCopyMatching"):
            getattr(sec, fn).restype = ctypes.c_int32
            getattr(sec, fn).argtypes = [vp, ctypes.POINTER(vp)]
        sec.SecItemDelete.restype = ctypes.c_int32
        sec.SecItemDelete.argtypes = [vp]
        sec.SecItemUpdate.restype = ctypes.c_int32
        sec.SecItemUpdate.argtypes = [vp, vp]
        self._cf, self._sec = cf, sec

        def const(lib: ctypes.CDLL, name: str) -> int:
            value = vp.in_dll(lib, name).value
            assert value is not None, name  # noqa: S101 - a framework constant
            return value

        self._k = {
            n: const(sec, n)
            for n in (
                "kSecClass",
                "kSecClassGenericPassword",
                "kSecAttrService",
                "kSecAttrAccount",
                "kSecValueData",
                "kSecReturnData",
                "kSecMatchLimit",
                "kSecMatchLimitOne",
                "kSecAttrAccessible",
                "kSecAttrAccessibleWhenUnlockedThisDeviceOnly",
            )
        }
        self._true = const(cf, "kCFBooleanTrue")
        self._key_cb = ctypes.addressof(vp.in_dll(cf, "kCFTypeDictionaryKeyCallBacks"))
        self._val_cb = ctypes.addressof(vp.in_dll(cf, "kCFTypeDictionaryValueCallBacks"))

    def __repr__(self) -> str:
        return f"KeychainSecretStore(service={self.service!r})"

    # -- CoreFoundation helpers -------------------------------------------

    def _str(self, s: str) -> int:
        ref: int = self._cf.CFStringCreateWithCString(None, s.encode(), _UTF8)
        return ref

    def _dict(self, pairs: list[tuple[int, int]]) -> int:
        vp = self._ctypes.c_void_p
        n = len(pairs)
        keys = (vp * n)(*[k for k, _ in pairs])
        vals = (vp * n)(*[v for _, v in pairs])
        ref: int = self._cf.CFDictionaryCreate(None, keys, vals, n, self._key_cb, self._val_cb)
        return ref

    def _query(self, account: str, *extra: tuple[int, int]) -> tuple[int, list[int]]:
        k = self._k
        owned = [self._str(self.service), self._str(account)]
        pairs = [
            (k["kSecClass"], k["kSecClassGenericPassword"]),
            (k["kSecAttrService"], owned[0]),
            (k["kSecAttrAccount"], owned[1]),
            *extra,
        ]
        return self._dict(pairs), owned

    def _release(self, *refs: int | None) -> None:
        for ref in refs:
            if ref:
                self._cf.CFRelease(ref)

    # -- SecretStore -------------------------------------------------------

    def get(self, account: str) -> str | None:
        k = self._k
        query, owned = self._query(
            account,
            (k["kSecReturnData"], self._true),
            (k["kSecMatchLimit"], k["kSecMatchLimitOne"]),
        )
        out = self._ctypes.c_void_p()
        try:
            status = self._sec.SecItemCopyMatching(query, self._ctypes.byref(out))
            if status == _ERR_ITEM_NOT_FOUND:
                return None
            if status != 0:
                raise KeychainError("read", status)
            data = out.value
            length = self._cf.CFDataGetLength(data)
            raw: bytes = self._ctypes.string_at(self._cf.CFDataGetBytePtr(data), length)
            return raw.decode()
        finally:
            self._release(query, out.value, *owned)

    def set(self, account: str, secret: str) -> None:
        k = self._k
        raw = secret.encode()
        data: int = self._cf.CFDataCreate(None, raw, len(raw))
        extra = [(k["kSecValueData"], data)]
        if sys.platform == "ios":
            # Not synced to iCloud, not readable while locked.
            extra.append(
                (k["kSecAttrAccessible"], k["kSecAttrAccessibleWhenUnlockedThisDeviceOnly"])
            )
        query, owned = self._query(account, *extra)
        try:
            status = self._sec.SecItemAdd(query, None)
            if status == _ERR_DUPLICATE_ITEM:
                match, owned2 = self._query(account)
                update = self._dict([(k["kSecValueData"], data)])
                try:
                    status = self._sec.SecItemUpdate(match, update)
                finally:
                    self._release(match, update, *owned2)
            if status != 0:
                raise KeychainError("write", status)
        finally:
            self._release(query, data, *owned)

    def delete(self, account: str) -> None:
        query, owned = self._query(account)
        try:
            status = self._sec.SecItemDelete(query)
            if status not in (0, _ERR_ITEM_NOT_FOUND):
                raise KeychainError("delete", status)
        finally:
            self._release(query, *owned)


# -- the default store -------------------------------------------------------------

# An account no connection can have (no backend is named "probe"), looked up
# once so a store that cannot work here (errSecMissingEntitlement on iOS,
# Windows error 1312 over SSH) is found before anyone relies on it.
_PROBE_ACCOUNT = "probe:bigfix-remote-session-relevance:"
_UNPROBED: Final = object()
_default_store: object = _UNPROBED


def default_secret_store() -> SecretStore | None:
    """This platform's store, or None. Probed once per process."""
    global _default_store
    if _default_store is _UNPROBED:
        _default_store = _probe_default_store()
    found: SecretStore | None = _default_store  # type: ignore[assignment]
    return found


def _probe_default_store() -> SecretStore | None:
    store: SecretStore
    try:
        if sys.platform == "ios":
            store = KeychainSecretStore()
        elif sys.platform == "android":
            return None  # no built-in store: an app passes its own Keystore bridge
        else:
            try:
                import keyring
            except ImportError:
                log.debug("no OS password store: keyring is not installed")
                return None
            backend = keyring.get_keyring()
            if type(backend).__module__ in _UNUSABLE_KEYRING_MODULES:
                log.debug("no OS password store: keyring has no usable backend (%r)", backend)
                return None
            store = KeyringSecretStore(backend=backend)
        store.get(_PROBE_ACCOUNT)
    except Exception as exc:  # noqa: BLE001 - any failure means "no store here"
        log.debug("no OS password store: %s: %s", type(exc).__name__, exc)
        return None
    return store


__all__ = [
    "SECRET_SERVICE",
    "KeychainError",
    "KeychainSecretStore",
    "KeyringSecretStore",
    "MemorySecretStore",
    "SecretStore",
    "default_secret_store",
    "secret_account",
]
