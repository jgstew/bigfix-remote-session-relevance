"""Turn a configured ``server`` into a base URL.

``server`` is normally just a hostname: ``https`` and the backend's default
port are assumed, and only a different scheme or port needs writing out.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .exceptions import ConfigError

DEFAULT_PORTS: dict[str, int] = {
    "rest": 52311,
    "explorer": 9383,
    "webreports": 443,
    "saas": 443,
}

_SCHEME_PORTS = {"https": 443, "http": 80}
_SCHEME_RE = re.compile(r"^([A-Za-z][A-Za-z0-9+.-]*)://")


@dataclass(frozen=True)
class ServerAddress:
    scheme: str
    host: str
    port: int

    @property
    def _host_for_url(self) -> str:
        return f"[{self.host}]" if ":" in self.host else self.host

    @property
    def host_port(self) -> str:
        """``host:port`` with IPv6 bracketed; the key for pinned certificates."""
        return f"{self._host_for_url}:{self.port}"

    @property
    def base_url(self) -> str:
        if _SCHEME_PORTS.get(self.scheme) == self.port:
            return f"{self.scheme}://{self._host_for_url}"
        return f"{self.scheme}://{self.host_port}"


def normalize_server(server: str, backend: str) -> ServerAddress:
    if backend not in DEFAULT_PORTS:
        raise ConfigError(f"unknown backend {backend!r}; expected one of {sorted(DEFAULT_PORTS)}")
    text = (server or "").strip()
    if not text:
        raise ConfigError("server is empty")

    scheme = "https"
    explicit_scheme = False
    match = _SCHEME_RE.match(text)
    if match:
        scheme = match.group(1).lower()
        explicit_scheme = True
        text = text[match.end() :]
        if scheme not in _SCHEME_PORTS:
            raise ConfigError(f"unsupported scheme {scheme!r} in server {server!r}")

    hostport, _, path = text.partition("/")
    path = "/" + path if path else ""
    if path.rstrip("/") not in ("", "/api"):
        raise ConfigError(f"server {server!r} has a path; only a trailing /api is allowed")
    if "@" in hostport:
        # Credentials belong in username/password(_env), never in the URL,
        # where they would end up in logs and result.server.
        raise ConfigError(f"server {server!r} must not contain credentials")

    host, port_text = _split_host_port(hostport, server)
    if not host:
        raise ConfigError(f"server {server!r} has no host")

    if port_text is None:
        # An explicit http:// with no port means the http port, not the
        # backend default, which is an https port.
        port = 80 if (explicit_scheme and scheme == "http") else DEFAULT_PORTS[backend]
    else:
        if not port_text.isdigit() or not 0 < int(port_text) < 65536:
            raise ConfigError(f"invalid port {port_text!r} in server {server!r}")
        port = int(port_text)

    return ServerAddress(scheme=scheme, host=host.lower(), port=port)


def _split_host_port(hostport: str, original: str) -> tuple[str, str | None]:
    if hostport.startswith("["):
        end = hostport.find("]")
        if end == -1:
            raise ConfigError(f"unterminated IPv6 address in server {original!r}")
        host = hostport[1:end]
        rest = hostport[end + 1 :]
        if not rest:
            return host, None
        if not rest.startswith(":"):
            raise ConfigError(f"invalid server {original!r}")
        return host, rest[1:]
    if hostport.count(":") > 1:
        # Bare IPv6 without brackets: no port can be expressed.
        return hostport, None
    host, sep, port = hostport.partition(":")
    return host, (port if sep else None)


# The password is POSTed to the SaaS API host, so it is held to these
# prefixes instead of trusting whatever host a config names (the same rule
# the bigfix-saas MCP server enforces).
_SAAS_LOGIN_TO_API = {"login.": "api.", "eulogin.": "euapi."}
_SAAS_API_PREFIXES = ("api.", "euapi.")


def saas_api_address(address: ServerAddress) -> ServerAddress:
    """``login.bigfix.com`` -> ``api.bigfix.com`` (``eulogin.`` -> ``euapi.``).

    The web UI lives on ``login.*`` hosts and the API gateway on ``api.*``
    hosts. An API host passes through unchanged; anything else, or http, is
    refused.
    """
    host = address.host
    if address.scheme == "https":
        for login, api in _SAAS_LOGIN_TO_API.items():
            if host.startswith(login):
                return ServerAddress("https", api + host[len(login) :], address.port)
        if host.startswith(_SAAS_API_PREFIXES):
            return address
    raise ConfigError(
        f"BigFix SaaS server {address.base_url!r} is not allowed: use https with a "
        "login., eulogin., api. or euapi. host (e.g. login.bigfix.com)"
    )
