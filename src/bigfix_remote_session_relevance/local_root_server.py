"""The local BigFix root server's own REST API credentials.

A root server keeps the credentials of an operator for its own REST API on
disk, so code running on it can log in without a configured password. This
is a minimal reimplementation of besapi's ``plugin_utilities_linux`` and
``plugin_utilities_win`` (same author, MIT), reading only, with no new
dependency:

* Linux: ``/var/opt/BESServer/Applications/MasterOperatorCredentials``, a
  header-less ``Key=Value`` file (normally readable only by root), whose
  ``RESTPassword`` is decrypted by the ``CryptoUtility`` next to it.
* Windows: ``HKLM\\SOFTWARE\\Wow6432Node\\BigFix\\Enterprise Server\\MFSConfig``,
  whose ``RESTPassword`` is ``{obf}`` + base64 of a machine-scope DPAPI blob,
  decrypted with ``CryptUnprotectData`` through ctypes.

The plaintext password is never logged or put in an exception message.
"""

from __future__ import annotations

import base64
import binascii
import importlib
import logging
import os
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

log = logging.getLogger(__name__)

LOCAL_ROOT_SERVER = "local_root_server"  # the `credentials` value
CONNECTION_NAME = "local-root-server"  # the automatically added connection
ENV_VAR = "BFRSR_LOCAL_ROOT_SERVER"  # "0", "false", "no" or "off" opts out

CREDENTIALS_FILE = Path("/var/opt/BESServer/Applications/MasterOperatorCredentials")
CRYPTO_UTILITY = Path("/var/opt/BESServer/Applications/CryptoUtility")
CRYPTO_UTILITY_TIMEOUT = 30.0
REGISTRY_KEY = r"SOFTWARE\Wow6432Node\BigFix\Enterprise Server\MFSConfig"
_OBFUSCATED_PREFIX = "{obf}"
_CRYPTPROTECT_LOCAL_MACHINE = 4
# besapi treats a decrypted password this short as a failed decryption.
_MIN_PASSWORD_LENGTH = 4
_REQUIRED = ("RESTUsername", "RESTURL", "RESTPassword")

_IS_WINDOWS = sys.platform == "win32"

Availability = Literal["absent", "unreadable", "readable"]


class LocalRootServerError(Exception):
    """The local root server credentials are not available; ``code`` says why."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class LocalRootCredentials:
    server: str  # RESTURL without its trailing /api
    username: str
    password: str = field(repr=False)


def disabled_by_env() -> bool:
    return os.environ.get(ENV_VAR, "").strip().lower() in ("0", "false", "no", "off")


def detect() -> Availability:
    """Whether this machine has root server credentials, without decrypting them."""
    if _IS_WINDOWS:
        try:
            with _open_registry_key():
                return "readable"
        except LocalRootServerError as exc:
            return "absent" if exc.code == "local_credentials_absent" else "unreadable"
    if not CREDENTIALS_FILE.is_file():
        return "absent"
    return "readable" if os.access(CREDENTIALS_FILE, os.R_OK) else "unreadable"


def rest_url() -> str | None:
    """Where the credentials are for (RESTURL without /api), without decrypting.

    None when it cannot be read: the caller falls back to localhost, which is
    what RESTURL normally is.
    """
    try:
        values = _read_values()
    except LocalRootServerError:
        return None
    url = values.get("RESTURL")
    return _server(url) if url else None


def read_credentials() -> LocalRootCredentials:
    """Read and decrypt the credentials, or raise `LocalRootServerError`."""
    values = _read_values()
    missing = [name for name in _REQUIRED if not values.get(name)]
    if missing:
        where = REGISTRY_KEY if _IS_WINDOWS else str(CREDENTIALS_FILE)
        raise LocalRootServerError(
            "local_credentials_incomplete", f"{', '.join(missing)} not set in {where}"
        )
    decrypt = _decrypt_registry_password if _IS_WINDOWS else _crypto_utility_decrypt
    password = decrypt(values["RESTPassword"])
    if len(password) < _MIN_PASSWORD_LENGTH:
        raise LocalRootServerError(
            "local_credentials_decrypt_failed", "RESTPassword decrypted to nothing usable"
        )
    return LocalRootCredentials(_server(values["RESTURL"]), values["RESTUsername"], password)


def _read_values() -> dict[str, str]:
    return _read_registry() if _IS_WINDOWS else _read_credentials_file()


def _server(url: str) -> str:
    return url.rstrip("/").removesuffix("/api")


# -- Linux ------------------------------------------------------------------------------


def parse_credentials_file(text: str) -> dict[str, str]:
    """``Key=Value`` per line; ``=`` is the only delimiter and key case is kept."""
    values: dict[str, str] = {}
    for line in text.splitlines():
        key, sep, value = line.strip().partition("=")
        if sep and key.strip():
            values[key.strip()] = value.strip()
    return values


def _read_credentials_file() -> dict[str, str]:
    try:
        # utf-8-sig: a byte order mark would otherwise become part of the first key.
        text = CREDENTIALS_FILE.read_text(encoding="utf-8-sig")
    except FileNotFoundError as exc:
        raise LocalRootServerError(
            "local_credentials_absent", f"not a BigFix root server: {CREDENTIALS_FILE} not found"
        ) from exc
    except PermissionError as exc:
        raise LocalRootServerError(
            "local_credentials_unreadable", f"cannot read {CREDENTIALS_FILE}: run as root"
        ) from exc
    except (OSError, UnicodeDecodeError) as exc:
        raise LocalRootServerError(
            "local_credentials_unreadable", f"cannot read {CREDENTIALS_FILE}: {exc}"
        ) from exc
    return parse_credentials_file(text)


def _crypto_utility_decrypt(encrypted: str) -> str:
    # argv list without a shell, so the value is never interpreted. Exception
    # text is left out of messages: TimeoutExpired's includes the command.
    try:
        done = subprocess.run(  # noqa: S603
            [str(CRYPTO_UTILITY), "-d", "-i", encrypted],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
            shell=False,
            timeout=CRYPTO_UTILITY_TIMEOUT,
        )
    except FileNotFoundError as exc:
        raise LocalRootServerError(
            "local_credentials_decrypt_failed", f"CryptoUtility not found at {CRYPTO_UTILITY}"
        ) from exc
    except PermissionError as exc:
        raise LocalRootServerError(
            "local_credentials_unreadable", f"cannot run {CRYPTO_UTILITY}: run as root"
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise LocalRootServerError(
            "local_credentials_decrypt_failed",
            f"CryptoUtility timed out after {CRYPTO_UTILITY_TIMEOUT:g} s",
        ) from exc
    except OSError as exc:
        raise LocalRootServerError(
            "local_credentials_decrypt_failed", f"cannot run {CRYPTO_UTILITY}: {exc.strerror}"
        ) from exc
    if done.returncode != 0:
        # stdout is never shown: it may hold the plaintext.
        raise LocalRootServerError(
            "local_credentials_decrypt_failed", f"CryptoUtility failed (exit {done.returncode})"
        )
    return (done.stdout or "").strip()


# -- Windows ------------------------------------------------------------------------------


def _winreg() -> Any:
    # Imported by name so the module (and its tests) load on any platform.
    return importlib.import_module("winreg")


def _open_registry_key() -> Any:
    winreg = _winreg()
    try:
        return winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, REGISTRY_KEY, 0, winreg.KEY_READ)
    except FileNotFoundError as exc:
        raise LocalRootServerError(
            "local_credentials_absent", f"not a BigFix root server: HKLM\\{REGISTRY_KEY} not found"
        ) from exc
    except PermissionError as exc:
        raise LocalRootServerError(
            "local_credentials_unreadable",
            f"cannot read HKLM\\{REGISTRY_KEY}: run as administrator",
        ) from exc
    except OSError as exc:
        raise LocalRootServerError(
            "local_credentials_unreadable", f"cannot read HKLM\\{REGISTRY_KEY}: {exc.strerror}"
        ) from exc


def _read_registry() -> dict[str, str]:
    winreg = _winreg()
    values: dict[str, str] = {}
    with _open_registry_key() as key:
        for name in _REQUIRED:
            try:
                value, _ = winreg.QueryValueEx(key, name)
            except FileNotFoundError:
                continue
            except OSError as exc:
                raise LocalRootServerError(
                    "local_credentials_unreadable",
                    f"cannot read {name} from HKLM\\{REGISTRY_KEY}: run as administrator",
                ) from exc
            if isinstance(value, str):
                values[name] = value.strip()
    return values


def _decrypt_registry_password(value: str) -> str:
    try:
        blob = base64.b64decode(value.removeprefix(_OBFUSCATED_PREFIX), validate=True)
        plaintext = _dpapi_unprotect(blob)
    except (binascii.Error, ValueError, OSError) as exc:
        raise LocalRootServerError(
            "local_credentials_decrypt_failed", "cannot decrypt RESTPassword with DPAPI"
        ) from exc
    return plaintext.decode("utf-8", errors="replace").strip()


if sys.platform == "win32":
    import ctypes
    from ctypes import wintypes

    class _DataBlob(ctypes.Structure):
        _fields_ = (("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char)))

    def _dpapi_unprotect(blob: bytes) -> bytes:
        """``CryptUnprotectData`` (machine scope, as the server stores it)."""
        crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        unprotect = crypt32.CryptUnprotectData
        unprotect.argtypes = [
            ctypes.POINTER(_DataBlob),
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.POINTER(_DataBlob),
        ]
        unprotect.restype = wintypes.BOOL
        kernel32.LocalFree.argtypes = [ctypes.c_void_p]
        kernel32.LocalFree.restype = ctypes.c_void_p

        buffer = ctypes.create_string_buffer(blob, len(blob))
        source = _DataBlob(len(blob), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_char)))
        out = _DataBlob()
        if not unprotect(
            ctypes.byref(source),
            None,
            None,
            None,
            None,
            _CRYPTPROTECT_LOCAL_MACHINE,
            ctypes.byref(out),
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            return ctypes.string_at(out.pbData, out.cbData)
        finally:
            kernel32.LocalFree(out.pbData)

else:

    def _dpapi_unprotect(blob: bytes) -> bytes:
        raise OSError("DPAPI is only available on Windows")


__all__ = [
    "CONNECTION_NAME",
    "ENV_VAR",
    "LOCAL_ROOT_SERVER",
    "LocalRootCredentials",
    "LocalRootServerError",
    "detect",
    "read_credentials",
    "rest_url",
]
