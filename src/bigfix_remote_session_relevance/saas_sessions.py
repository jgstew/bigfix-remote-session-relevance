"""BigFix SaaS sessions saved across runs, so MFA needs a TOTP code only weekly.

BigFix SaaS has no API key or service account and MFA cannot be skipped, so
reusing a signed-in session is the only way to run an MFA account without a
person typing a code. Observed token behaviour (issue #29):

* The access token lasts its own ``exp - iat`` (1 hour by default, set per
  tenant). A request sent with an expired one can spend the refresh token
  without returning a replacement, so a saved session is renewed by the
  wall clock before it expires, never on a 401.
* The refresh token is single-use: a refresh returns a new pair, and a spent
  token gets 401. Its expiry is fixed at 7 days from login; refreshing does
  not move it.

A saved session is keyed by API host and email (any case), like
`secret_account` with a ``saas-session`` prefix. It goes in this machine's
`SecretStore` (`default_secret_store`: Keychain, Credential Manager, Secret
Service) when there is one, otherwise, or if the store refuses it, in
``.remote_session_saas_sessions.toml`` in `data_dir` as plaintext at 0600,
as config passwords already are. Processes coordinate through a file lock
beside that file, whichever holds the tokens, so two of them never spend the
same refresh token.
"""

from __future__ import annotations

import base64
import binascii
import contextlib
import json
import logging
import os
import stat
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final

from .paths import data_dir
from .secrets import DEFAULT_SECRET_STORE

if TYPE_CHECKING:
    import tomlkit
    from filelock import FileLock

    from .config import ConnectionConfig
    from .secrets import SecretStore
    from .server_address import ServerAddress

log = logging.getLogger(__name__)

SESSIONS_PATH_ENV: Final = "BFRSR_SAAS_SESSIONS"
SESSION_CACHE_ENV: Final = "BFRSR_SESSION_CACHE"
ENTRY_VERSION: Final = 1
# The refresh expiry when the refresh token's own exp cannot be read.
REFRESH_LIFETIME_S: Final = 7 * 24 * 3600.0
_ACCOUNT_PREFIX: Final = "saas-session"
_OFF = ("0", "false", "no", "off")
_FIELDS = ("access_token", "refresh_token", "access_exp", "refresh_exp")


def default_saas_sessions_path() -> Path:
    """``$BFRSR_SAAS_SESSIONS``, else ``.remote_session_saas_sessions.toml`` in `data_dir`."""
    env = os.environ.get(SESSIONS_PATH_ENV)
    if env and not env.isspace():
        return Path(env.strip()).expanduser()
    return data_dir() / ".remote_session_saas_sessions.toml"


def default_saas_session_store(
    secrets: SecretStore | None = DEFAULT_SECRET_STORE,
) -> SaasSessionStore | None:
    """The store backends use unless given one; None when ``BFRSR_SESSION_CACHE`` is off."""
    if os.environ.get(SESSION_CACHE_ENV, "").strip().lower() in _OFF:
        return None
    return SaasSessionStore(secrets=secrets)


def session_account(address: ServerAddress, email: str) -> str:
    """``saas-session:<api host:port>:<email, lower-cased>``."""
    return f"{_ACCOUNT_PREFIX}:{address.host_port}:{email.strip().lower()}"


@dataclass(frozen=True)
class SavedSaasSession:
    """One account's tokens; expiries are wall-clock epoch seconds on this machine."""

    access_token: str = field(repr=False)
    refresh_token: str = field(repr=False)
    access_exp: float
    refresh_exp: float
    servers: tuple[str, ...] = ()
    stored_at: float = 0.0

    def access_remaining(self) -> float:
        return self.access_exp - time.time()

    def refresh_remaining(self) -> float:
        return self.refresh_exp - time.time()

    def _to_dict(self) -> dict[str, Any]:
        return {
            "version": ENTRY_VERSION,
            "access_token": self.access_token,
            "refresh_token": self.refresh_token,
            "access_exp": float(self.access_exp),
            "refresh_exp": float(self.refresh_exp),
            "servers": list(self.servers),
            "stored_at": float(self.stored_at),
        }


def _from_dict(data: Any) -> SavedSaasSession | None:
    if not isinstance(data, dict) or data.get("version") != ENTRY_VERSION:
        return None
    if not all(k in data for k in _FIELDS):
        return None
    try:
        servers = data.get("servers", [])
        return SavedSaasSession(
            access_token=_text(data["access_token"]),
            refresh_token=_text(data["refresh_token"]),
            access_exp=float(data["access_exp"]),
            refresh_exp=float(data["refresh_exp"]),
            servers=tuple(str(s) for s in servers) if isinstance(servers, list) else (),
            stored_at=float(data.get("stored_at", 0.0)),
        )
    except (TypeError, ValueError):
        return None


def _text(value: Any) -> str:
    if not isinstance(value, str) or not value:
        raise TypeError("expected a token")
    return value


def jwt_claims(token: str) -> dict[str, Any] | None:
    """A JWT's payload, unverified (only to read ``exp`` and the email), or None."""
    parts = token.split(".")
    if len(parts) != 3:
        return None
    payload = parts[1]
    try:
        claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    except (ValueError, binascii.Error):
        return None
    return claims if isinstance(claims, dict) else None


def _email_matches(saved: SavedSaasSession, email: str) -> bool:
    # (observed) The access token carries the account's email as "eml". The
    # entry is already keyed by email; this catches one copied or edited
    # into the wrong key, which would sign the connection in as someone else.
    claims = jwt_claims(saved.access_token)
    found = claims.get("eml") if claims else None
    return isinstance(found, str) and found.strip().lower() == email.strip().lower()


class SaasSessionStore:
    """Saved sessions, in a `SecretStore` if there is one, else a 0600 TOML file.

    ``secrets`` defaults to `default_secret_store()`, looked up on first use;
    None means the file only. Any store or file failure reads as no saved
    session (logged at DEBUG), so the worst case is a sign-in.
    """

    def __init__(
        self,
        path: str | os.PathLike[str] | None = None,
        *,
        secrets: SecretStore | None = DEFAULT_SECRET_STORE,
    ) -> None:
        self.path = Path(path) if path is not None else default_saas_sessions_path()
        self._secrets_arg = secrets

    def __repr__(self) -> str:
        return f"SaasSessionStore(path={str(self.path)!r})"

    def _secrets(self) -> SecretStore | None:
        if self._secrets_arg is not DEFAULT_SECRET_STORE:
            found: SecretStore | None = self._secrets_arg
            return found
        from . import secrets as secret_stores

        try:
            return secret_stores.default_secret_store()
        except Exception as exc:  # noqa: BLE001 - no store: the file instead
            log.debug("no OS password store for SaaS sessions: %s", type(exc).__name__)
            return None

    def lock(self) -> FileLock:
        """A new lock on ``<path>.lock``: acquire it in a thread, release it there or here.

        A new, non-thread-local instance per use: filelock instances are
        reentrant, so a shared one would let two backends of this process in
        at once, and thread-local ones cannot be released from another thread.
        """
        from filelock import FileLock

        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        return FileLock(str(self.path) + ".lock", thread_local=False)

    # -- entries -------------------------------------------------------------------

    def load(self, address: ServerAddress, email: str) -> SavedSaasSession | None:
        """The account's saved session, or None (also for any unreadable entry)."""
        account = session_account(address, email)
        saved = None
        store = self._secrets()
        if store is not None:
            try:
                text = store.get(account)
            except Exception as exc:  # noqa: BLE001 - fall back to the file
                log.debug("cannot read a SaaS session from %s: %s", store.name, type(exc).__name__)
            else:
                if text:
                    try:
                        saved = _from_dict(json.loads(text))
                    except ValueError:
                        saved = None
                    if saved is None:
                        log.debug("ignoring an unreadable SaaS session in %s", store.name)
        if saved is None:
            entry = self._read().get("sessions", {}).get(account)
            saved = _from_dict(_plain(entry)) if entry is not None else None
        if saved is not None and not _email_matches(saved, email):
            log.debug("ignoring a saved SaaS session whose token is for another account")
            return None
        return saved

    def save(self, address: ServerAddress, email: str, saved: SavedSaasSession) -> None:
        """Write the session; hold `lock` around a read-then-save."""
        account = session_account(address, email)
        store = self._secrets()
        if store is not None:
            try:
                store.set(account, json.dumps(saved._to_dict()))
            except Exception as exc:  # noqa: BLE001 - too large, locked: the file instead
                log.debug("cannot save a SaaS session in %s: %s", store.name, type(exc).__name__)
            else:
                self._drop_from_file(account)  # one copy, in the better place
                return
        doc = self._read()
        sessions = doc.get("sessions")
        if not isinstance(sessions, dict):
            import tomlkit

            doc = tomlkit.document()
            doc.add(
                tomlkit.comment("BigFix SaaS sessions saved by bigfix-remote-session-relevance.")
            )
            doc.add(tomlkit.comment("Plaintext tokens: keep this file private (mode 600)."))
            doc["sessions"] = sessions = tomlkit.table()
        sessions[account] = saved._to_dict()
        self._write(doc)

    def forget(
        self, address: ServerAddress, email: str, *, refresh_token: str | None = None
    ) -> bool:
        """Delete the saved session; True if there was one.

        With ``refresh_token``, only if it still holds that token: a refresh
        that failed must not drop a newer pair another process saved.
        """
        account = session_account(address, email)
        current = self.load(address, email)
        if refresh_token is not None and (
            current is None or current.refresh_token != refresh_token
        ):
            return False
        found = current is not None
        store = self._secrets()
        if store is not None:
            try:
                had = store.get(account) is not None
                store.delete(account)
                found = found or had
            except Exception as exc:  # noqa: BLE001 - the file may still hold it
                log.debug(
                    "cannot delete a SaaS session from %s: %s", store.name, type(exc).__name__
                )
        return self._drop_from_file(account) or found

    # -- the file ------------------------------------------------------------------

    def _read(self) -> tomlkit.TOMLDocument:
        import tomlkit

        try:
            text = self.path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return tomlkit.document()
        except OSError as exc:
            log.debug("cannot read %s: %s", self.path, type(exc).__name__)
            return tomlkit.document()
        self._warn_if_readable()
        try:
            doc = tomlkit.parse(text)
        except Exception as exc:  # noqa: BLE001 - tomlkit's parse errors share no base
            log.warning("%s is not valid TOML (%s); ignoring it", self.path, type(exc).__name__)
            return tomlkit.document()
        if not isinstance(doc.get("sessions", {}), dict):
            log.warning("%s has no sessions table; ignoring it", self.path)
            return tomlkit.document()
        return doc

    def _drop_from_file(self, account: str) -> bool:
        if not self.path.is_file():
            return False
        doc = self._read()
        sessions = doc.get("sessions")
        if not isinstance(sessions, dict) or account not in sessions:
            return False
        del sessions[account]
        self._write(doc)
        return True

    def _write(self, doc: tomlkit.TOMLDocument) -> None:
        import tomlkit

        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=self.path.parent, prefix=f".{self.path.name}.")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(tomlkit.dumps(doc))
            os.chmod(tmp, 0o600)
            os.replace(tmp, self.path)
        except BaseException:
            with contextlib.suppress(OSError):
                os.unlink(tmp)
            raise

    def _warn_if_readable(self) -> None:
        if sys.platform == "win32":
            return  # the file inherits the directory's ACLs
        try:
            mode = stat.S_IMODE(self.path.stat().st_mode)
        except OSError:
            return
        if mode & 0o077:
            log.warning(
                "%s holds BigFix SaaS session tokens and is readable by other users "
                "(mode %o); run: chmod 600 %s",
                self.path,
                mode,
                self.path,
            )


def forget_saas_session(
    conn: ConnectionConfig,
    *,
    secrets: SecretStore | None = DEFAULT_SECRET_STORE,
    path: str | os.PathLike[str] | None = None,
) -> bool:
    """Delete a SaaS connection's saved session; True if there was one.

    The next run signs in again (with a TOTP code, for an MFA account). The
    session is the account's, so this also signs out other connections with
    the same API host and email. Raises `ConfigError` for a non-SaaS connection.
    """
    from .exceptions import ConfigError
    from .server_address import saas_api_address

    if conn.backend != "saas":
        raise ConfigError(f"{conn.name} is not a BigFix SaaS connection")
    store = SaasSessionStore(path, secrets=secrets)
    api = saas_api_address(conn.address)
    with store.lock():
        return store.forget(api, conn.username or "")


def _plain(value: Any) -> Any:
    """tomlkit containers as plain dicts and lists."""
    unwrap = getattr(value, "unwrap", None)
    return unwrap() if callable(unwrap) else value


__all__ = [
    "SESSIONS_PATH_ENV",
    "SESSION_CACHE_ENV",
    "SaasSessionStore",
    "SavedSaasSession",
    "default_saas_session_store",
    "default_saas_sessions_path",
    "forget_saas_session",
    "session_account",
]
