"""Connection configuration: ``~/.bigfix/.remote_session_connections.toml``.

Read and written with tomlkit so a user's comments and layout survive the
setup wizard and deployment-id write-back. Secrets are never put in a repr,
log line or `redacted_summary`.
"""

from __future__ import annotations

import configparser
import contextlib
import logging
import os
import stat
import sys
import tempfile
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Any

import tomlkit
import tomlkit.exceptions
from tomlkit.items import AoT

from .exceptions import ConfigError
from .server_address import DEFAULT_PORTS, ServerAddress, normalize_server

log = logging.getLogger(__name__)

SCHEMA_VERSION = 1
CONFIG_ENV = "BFRSR_CONFIG"
DEFAULT_BACKEND_PREFERENCE = ("explorer", "rest", "webreports", "saas")
DEFAULT_CONNECT_TIMEOUT = 5.0
DEFAULT_READ_TIMEOUT = 120.0
DEFAULT_VERIFY: bool | str = "tofu"

_BACKEND_ALIASES = {
    "rest": "rest",
    "rest_api": "rest",
    "restapi": "rest",
    "root": "rest",
    "besapi": "rest",
    "webreports": "webreports",
    "web_reports": "webreports",
    "web-reports": "webreports",
    "wr": "webreports",
    "soap": "webreports",
    "explorer": "explorer",
    "bes_explorer": "explorer",
    "bes-explorer": "explorer",
    "bigfix_explorer": "explorer",
    "saas": "saas",
}

# Accepted spellings -> canonical key. Lenient on purpose: people write
# these files by hand, often before reading the docs.
_KEY_ALIASES = {
    "name": "name",
    "backend": "backend",
    "type": "backend",
    "server": "server",
    "url": "server",
    "host": "server",
    "username": "username",
    "user": "username",
    "password": "password",
    "password_env": "password_env",
    "token": "token",
    "api_key": "token",
    "api_token": "token",
    "token_env": "token_env",
    "api_key_env": "token_env",
    "api_token_env": "token_env",
    "client_cert": "client_cert",
    "client_key": "client_key",
    "client_key_password_env": "client_key_password_env",
    "deployment_id": "deployment_id",
    "verify": "verify",
    "connect_timeout": "connect_timeout",
    "read_timeout": "read_timeout",
    "timeout": "read_timeout",
    "enabled": "enabled",
}


def default_config_path() -> Path:
    return Path.home() / ".bigfix" / ".remote_session_connections.toml"


def resolve_config_path(explicit: str | os.PathLike[str] | None = None) -> Path:
    if explicit:
        return Path(explicit).expanduser()
    env = os.environ.get(CONFIG_ENV)
    if env:
        return Path(env).expanduser()
    return default_config_path()


@dataclass(frozen=True)
class ConnectionConfig:
    """One configured endpoint. Unset tuning fields inherit ``[defaults]``."""

    name: str
    backend: str
    server: str
    username: str | None = None
    password: str | None = field(default=None, repr=False)
    password_env: str | None = None
    token: str | None = field(default=None, repr=False)
    token_env: str | None = None
    client_cert: str | None = None
    client_key: str | None = None
    client_key_password_env: str | None = None
    deployment_id: str | None = None
    verify: bool | str | None = None
    connect_timeout: float | None = None
    read_timeout: float | None = None
    enabled: bool = True

    @property
    def address(self) -> ServerAddress:
        return normalize_server(self.server, self.backend)

    @property
    def auth(self) -> str:
        """``token`` (bearer), ``basic``, or ``mtls`` (client cert only)."""
        if self.token is not None or self.token_env is not None:
            return "token"
        if self.username is not None:
            return "basic"
        if self.client_cert is not None:
            return "mtls"
        return "basic"

    def resolve_password(self, *, prompt: Callable[[str], str] | None = None) -> str | None:
        """``password_env`` if set, else inline ``password``, else ``prompt``."""
        if self.password_env:
            value = os.environ.get(self.password_env)
            if value:
                return value
        if self.password is not None:
            return self.password
        if prompt is not None and self.username is not None:
            return prompt(f"Password for {self.username} on {self.name}: ")
        return None

    def resolve_token(self) -> str | None:
        if self.token_env:
            value = os.environ.get(self.token_env)
            if value:
                return value
        return self.token

    def resolve_client_key_password(self) -> str | None:
        if self.client_key_password_env:
            return os.environ.get(self.client_key_password_env) or None
        return None


@dataclass(frozen=True)
class Config:
    connections: tuple[ConnectionConfig, ...] = ()
    backend_preference: tuple[str, ...] = DEFAULT_BACKEND_PREFERENCE
    path: Path | None = None
    source: str = "none"  # "file", "besapi-env", "besapi-conf" or "none"

    def enabled_connections(self) -> tuple[ConnectionConfig, ...]:
        return tuple(c for c in self.connections if c.enabled)

    def connection(self, name: str) -> ConnectionConfig:
        for c in self.connections:
            if c.name == name:
                return c
        raise ConfigError(f"no connection named {name!r}")


# -- loading ------------------------------------------------------------------


def load_config(path: str | os.PathLike[str] | None = None) -> Config:
    """Load and validate the config. A missing file is not an error."""
    resolved = resolve_config_path(path)
    if not resolved.is_file():
        return _besapi_compat() or Config(path=resolved)
    try:
        text = resolved.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"cannot read {resolved}: {exc}") from exc
    try:
        data = tomlkit.parse(text).unwrap()
    except tomlkit.exceptions.ParseError as exc:
        raise ConfigError(f"cannot parse {resolved}: {exc}") from exc
    config = _from_mapping(data, resolved)
    _warn_if_secrets_readable(resolved, config)
    return config


def _from_mapping(data: Mapping[str, Any], path: Path | None) -> Config:
    version = data.get("schema_version", SCHEMA_VERSION)
    if version != SCHEMA_VERSION:
        raise ConfigError(f"unsupported schema_version {version!r} (expected {SCHEMA_VERSION})")

    defaults = data.get("defaults", {})
    if not isinstance(defaults, Mapping):
        raise ConfigError("[defaults] must be a table")
    default_verify = _validate_verify(defaults.get("verify", DEFAULT_VERIFY), "[defaults]")
    default_connect = float(defaults.get("connect_timeout", DEFAULT_CONNECT_TIMEOUT))
    default_read = float(defaults.get("read_timeout", DEFAULT_READ_TIMEOUT))
    preference = tuple(
        _canonical_backend(b, "[defaults] backend_preference")
        for b in defaults.get("backend_preference", DEFAULT_BACKEND_PREFERENCE)
    )

    raw_connections = data.get("connections", [])
    if not isinstance(raw_connections, list):
        raise ConfigError("connections must be an array of tables ([[connections]])")

    connections: list[ConnectionConfig] = []
    seen: set[str] = set()
    for index, raw in enumerate(raw_connections):
        conn = _connection_from_mapping(raw, index)
        if conn.name in seen:
            raise ConfigError(f"duplicate connection name {conn.name!r}")
        seen.add(conn.name)
        connections.append(
            _replace(
                conn,
                verify=default_verify if conn.verify is None else conn.verify,
                connect_timeout=default_connect
                if conn.connect_timeout is None
                else conn.connect_timeout,
                read_timeout=default_read if conn.read_timeout is None else conn.read_timeout,
            )
        )
    return Config(
        connections=tuple(connections),
        backend_preference=preference,
        path=path,
        source="file",
    )


def _connection_from_mapping(raw: Any, index: int) -> ConnectionConfig:
    where = f"connections[{index}]"
    if not isinstance(raw, Mapping):
        raise ConfigError(f"{where} must be a table")
    values: dict[str, Any] = {}
    for key, value in raw.items():
        canonical = _KEY_ALIASES.get(str(key).lower())
        if canonical is None:
            log.warning("%s: ignoring unknown key %r", where, key)
            continue
        values[canonical] = value

    name = values.get("name")
    if not isinstance(name, str) or not name.strip():
        raise ConfigError(f"{where}: missing name")
    where = f"{where} ({name})"
    if "backend" not in values:
        raise ConfigError(f"{where}: missing backend")
    backend = _canonical_backend(values["backend"], where)
    server = values.get("server")
    if not isinstance(server, str) or not server.strip():
        raise ConfigError(f"{where}: missing server")

    for key in ("client_cert", "client_key"):
        if isinstance(values.get(key), str):
            values[key] = str(Path(values[key]).expanduser())
    if "verify" in values:
        values["verify"] = _validate_verify(values["verify"], where)
    for key in ("connect_timeout", "read_timeout"):
        if key in values:
            values[key] = float(values[key])

    conn = ConnectionConfig(
        name=name.strip(),
        backend=backend,
        server=server.strip(),
        **{k: v for k, v in values.items() if k not in ("name", "backend", "server")},
    )
    _validate_auth(conn, where)
    return conn


def _validate_auth(conn: ConnectionConfig, where: str) -> None:
    try:
        address = conn.address
    except ConfigError as exc:
        raise ConfigError(f"{where}: {exc}") from exc
    has_token = conn.token is not None or conn.token_env is not None
    has_basic = (
        conn.username is not None or conn.password is not None or conn.password_env is not None
    )
    if has_token and conn.backend == "webreports":
        raise ConfigError(f"{where}: Web Reports SOAP only supports username/password, not token")
    if has_token and has_basic:
        raise ConfigError(f"{where}: set either token or username/password, not both")
    if conn.client_key is not None and conn.client_cert is None:
        raise ConfigError(f"{where}: client_key needs client_cert")
    if conn.client_cert is not None and address.scheme != "https":
        raise ConfigError(f"{where}: client certificates (mTLS) need https")


def _canonical_backend(value: Any, where: str) -> str:
    canonical = _BACKEND_ALIASES.get(str(value).strip().lower())
    if canonical is None:
        raise ConfigError(
            f"{where}: unknown backend {value!r}; expected one of {sorted(DEFAULT_PORTS)}"
        )
    return canonical


def _validate_verify(value: Any, where: str) -> bool | str:
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.strip():
        text = value.strip()
        return "tofu" if text.lower() == "tofu" else str(Path(text).expanduser())
    raise ConfigError(f'{where}: verify must be true, false, "tofu" or a CA bundle path')


def _replace(conn: ConnectionConfig, **changes: Any) -> ConnectionConfig:
    current = {f.name: getattr(conn, f.name) for f in fields(conn)}
    current.update(changes)
    return ConnectionConfig(**current)


def _warn_if_secrets_readable(path: Path, config: Config) -> None:
    if sys.platform == "win32":
        return
    if not any(c.password is not None or c.token is not None for c in config.connections):
        return
    try:
        mode = stat.S_IMODE(path.stat().st_mode)
    except OSError:
        return
    if mode & 0o077:
        log.warning(
            "%s stores a password or token and is readable by other users (mode %o); "
            "run: chmod 600 %s",
            path,
            mode,
            path,
        )


def _besapi_compat() -> Config | None:
    """Fall back to besapi's env vars or ~/.besapi.conf as one REST connection."""
    server = os.environ.get("BES_ROOT_SERVER")
    user = os.environ.get("BES_USER_NAME")
    password = os.environ.get("BES_PASSWORD")
    if server and user and password:
        conn = ConnectionConfig(
            name="besapi-env",
            backend="rest",
            server=server,
            username=user,
            password=password,
            verify=DEFAULT_VERIFY,
            connect_timeout=DEFAULT_CONNECT_TIMEOUT,
            read_timeout=DEFAULT_READ_TIMEOUT,
        )
        return Config(connections=(conn,), source="besapi-env")

    conf_path = Path.home() / ".besapi.conf"
    if conf_path.is_file():
        parser = configparser.ConfigParser()
        try:
            parser.read(conf_path)
            server = parser.get("besapi", "BES_ROOT_SERVER")
            user = parser.get("besapi", "BES_USER_NAME")
            password = parser.get("besapi", "BES_PASSWORD")
        except (configparser.Error, OSError):
            return None
        conn = ConnectionConfig(
            name="besapi-conf",
            backend="rest",
            server=server,
            username=user,
            password=password,
            verify=DEFAULT_VERIFY,
            connect_timeout=DEFAULT_CONNECT_TIMEOUT,
            read_timeout=DEFAULT_READ_TIMEOUT,
        )
        return Config(connections=(conn,), path=conf_path, source="besapi-conf")
    return None


# -- writing ------------------------------------------------------------------

_SAVE_ORDER = [f.name for f in fields(ConnectionConfig)]


def save_connection(
    path: str | os.PathLike[str], conn: ConnectionConfig, *, replace: bool = False
) -> None:
    """Add (or with ``replace``, overwrite) one connection, keeping comments."""
    target = Path(path)
    doc = _load_document(target)
    connections = _connections_aot(doc)
    table = tomlkit.table()
    for key in _SAVE_ORDER:
        value = getattr(conn, key)
        if value is None or (key == "enabled" and value is True):
            continue
        table.add(key, value)

    for index, existing in enumerate(connections):
        if existing.get("name") == conn.name:
            if not replace:
                raise ConfigError(f"connection {conn.name!r} already exists in {target}")
            connections[index] = table
            break
    else:
        connections.append(table)
    _validate_document(doc, target)
    _atomic_write(target, tomlkit.dumps(doc))


def set_deployment_id(path: str | os.PathLike[str], name: str, deployment_id: str) -> None:
    """Record a discovered deployment id on connection ``name``."""
    target = Path(path)
    doc = _load_document(target)
    for table in _connections_aot(doc):
        if table.get("name") == name:
            table["deployment_id"] = deployment_id
            break
    else:
        raise ConfigError(f"no connection named {name!r} in {target}")
    _validate_document(doc, target)
    _atomic_write(target, tomlkit.dumps(doc))


def _load_document(path: Path) -> tomlkit.TOMLDocument:
    if not path.is_file():
        doc = tomlkit.document()
        doc.add(tomlkit.comment("bigfix-remote-session-relevance connections"))
        doc.add(tomlkit.comment("Docs: https://github.com/jgstew/bigfix-remote-session-relevance"))
        doc.add("schema_version", SCHEMA_VERSION)
        return doc
    try:
        return tomlkit.parse(path.read_text(encoding="utf-8"))
    except tomlkit.exceptions.ParseError as exc:
        raise ConfigError(f"cannot parse {path}: {exc}") from exc


def _connections_aot(doc: tomlkit.TOMLDocument) -> AoT:
    existing = doc.get("connections")
    if existing is None:
        aot = tomlkit.aot()
        doc.append("connections", aot)
        return aot
    if not isinstance(existing, AoT):
        raise ConfigError("connections must be an array of tables ([[connections]])")
    return existing


def _validate_document(doc: tomlkit.TOMLDocument, path: Path) -> None:
    # Re-parse what we are about to write, so a bad edit never replaces a
    # working file.
    _from_mapping(tomlkit.parse(tomlkit.dumps(doc)).unwrap(), path)


def _atomic_write(path: Path, text: str) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
        os.chmod(tmp_name, 0o600)
        os.replace(tmp_name, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp_name)
        raise


# -- display ------------------------------------------------------------------


def redacted_summary(config: Config) -> list[dict[str, Any]]:
    """Rows for ``--show-config``: what is configured, never the secrets."""
    rows: list[dict[str, Any]] = []
    for c in config.connections:
        try:
            server = c.address.base_url
        except ConfigError as exc:
            server = f"<invalid: {exc}>"
        rows.append(
            {
                "name": c.name,
                "backend": c.backend,
                "server": server,
                "auth": c.auth,
                "username": "set" if c.username else "unset",
                "password": _secret_state(c.password, c.password_env),
                "token": _secret_state(c.token, c.token_env),
                "client_cert": "set" if c.client_cert else "unset",
                "deployment_id": c.deployment_id,
                "verify": c.verify
                if isinstance(c.verify, bool) or c.verify == "tofu"
                else "ca bundle",
                "enabled": c.enabled,
            }
        )
    return rows


def _secret_state(inline: str | None, env_name: str | None) -> str:
    if env_name:
        return "env var (set)" if os.environ.get(env_name) else "env var (unset)"
    if inline is not None:
        return "stored in file"
    return "none"


__all__ = [
    "CONFIG_ENV",
    "Config",
    "ConnectionConfig",
    "default_config_path",
    "load_config",
    "redacted_summary",
    "resolve_config_path",
    "save_connection",
    "set_deployment_id",
]
