"""The `Backend` base class and the error mapping every backend shares.

Each backend only knows how to build its request and parse its response.
Everything that must behave identically across backends lives here: auth
headers, TLS (including trust-on-first-use), timeouts, retries, mapping
transport failures to `ResultError`, and stamping result metadata.
"""

from __future__ import annotations

import asyncio
import dataclasses
import json
import logging
import re
import ssl
import time
from abc import ABC, abstractmethod
from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING, Any, ClassVar, Protocol, Self, TypeVar

import certifi
import httpx

from .. import local_root_server
from ..exceptions import ConfigError
from ..result import ResultError, SessionRelevanceResult
from ..server_address import ServerAddress, normalize_server

if TYPE_CHECKING:
    from types import TracebackType

    from ..config import ConnectionConfig

log = logging.getLogger(__name__)

_DETAIL_LIMIT = 500


class TrustPolicy(Protocol):
    """What a backend needs from the TOFU trust store (see ``trust.py``)."""

    def is_pinned(self, address: ServerAddress) -> bool: ...

    def ssl_context(self, address: ServerAddress) -> ssl.SSLContext: ...

    async def on_untrusted(self, address: ServerAddress) -> bool: ...

    async def mismatch_error(self, address: ServerAddress, backend: str) -> ResultError: ...


# -- shared error mapping -------------------------------------------------------


def _exception_chain(exc: BaseException) -> list[BaseException]:
    chain: list[BaseException] = []
    current: BaseException | None = exc
    while current is not None and current not in chain:
        chain.append(current)
        current = current.__cause__ or current.__context__
    return chain


def error_from_exception(exc: Exception, backend: str) -> ResultError:
    """Map an httpx failure to a `ResultError`, the same way for every backend."""
    text = str(exc) or type(exc).__name__
    if isinstance(exc, httpx.TimeoutException):
        return ResultError(kind="timeout", message=f"timed out: {text}", backend=backend)
    chain = _exception_chain(exc)
    if any(isinstance(e, ssl.SSLCertVerificationError) for e in chain) or (
        "CERTIFICATE_VERIFY_FAILED" in text
    ):
        return ResultError(
            kind="tls",
            code="cert_verify_failed",
            backend=backend,
            message=f"certificate verification failed: {text}",
        )
    if any(isinstance(e, ssl.SSLError) for e in chain) or "[SSL" in text:
        return ResultError(
            kind="tls",
            code="tls_handshake",
            backend=backend,
            message=f"TLS handshake failed: {text}",
        )
    if isinstance(exc, httpx.TransportError):
        return ResultError(kind="connection", message=f"cannot connect: {text}", backend=backend)
    return ResultError(kind="http", message=text, backend=backend)


_UNAVAILABLE_RE = re.compile(
    r"temporarily unavailable|no reachable|not available|re-?established|try again later",
    re.IGNORECASE,
)
# Accepted credentials, missing privilege, e.g. Explorer's
# 401 {"error": "Explorer login permission required"}.
_PERMISSION_RE = re.compile(r"permission|privilege", re.IGNORECASE)


def server_message(response: httpx.Response) -> str | None:
    """The server's own explanation: a JSON ``error`` field or a short text body."""
    text = response.text.strip()
    if not text:
        return None
    if text.startswith("{"):
        try:
            data = json.loads(text)
        except ValueError:
            return None
        if isinstance(data, dict):
            for key in ("error", "Error", "message", "Message"):
                if isinstance(data.get(key), str) and data[key].strip():
                    return " ".join(str(data[key]).split())
        return None
    if text.startswith("<") or len(text) > _DETAIL_LIMIT:
        return None
    return " ".join(text.split())


def error_from_status(response: httpx.Response, backend: str) -> ResultError:
    status = response.status_code
    detail = response.text[:_DETAIL_LIMIT]
    said = server_message(response)
    # Explorer answers 401 (and REST 503) when it has lost its root server
    # connection. That is an outage, not bad credentials, and must say so.
    if said and (status == 503 or _UNAVAILABLE_RE.search(said)):
        return ResultError(
            kind="http",
            code="service_unavailable",
            backend=backend,
            http_status=status,
            message=said,
            detail=detail,
        )
    if status in (401, 403) and said and _PERMISSION_RE.search(said):
        return ResultError(
            kind="authentication",
            code="permission_denied",
            backend=backend,
            http_status=status,
            detail=detail,
            message=f"operator lacks a required permission: {said}",
        )
    if status in (401, 403):
        return ResultError(
            kind="authentication",
            backend=backend,
            http_status=status,
            detail=detail,
            message="credentials rejected",
        )
    return ResultError(
        kind="http",
        backend=backend,
        http_status=status,
        detail=detail,
        message=f"unexpected HTTP {status} {response.reason_phrase}".rstrip(),
    )


_ERROR_PREFIX_RE = re.compile(r"^\s*(?:relevance\s+error|error)\s*:\s*", re.IGNORECASE)


# (observed) An evaluation exception is named "class TooLargeForStandardNotation"
# by the on-prem servers and "27TooLargeForStandardNotation" by BigFix SaaS: a
# mangled C++ type name, its length then the name. Only that whole message, with
# the number equal to the name's length, is rewritten: never text inside a
# user's `error "..."`.
_MANGLED_RE = re.compile(r"^(The expression could not be evaluated: )(\d+)([A-Za-z_]\w*)$")


def _unmangle(match: re.Match[str]) -> str:
    prefix, length, name = match.groups()
    return f"{prefix}class {name}" if int(length) == len(name) else match.group(0)


def normalize_relevance_error(text: str | None) -> str:
    """Strip backend-specific prefixes so one bad query reads the same everywhere."""
    message = " ".join((text or "").split())
    while True:
        stripped = _ERROR_PREFIX_RE.sub("", message, count=1)
        if stripped == message:
            break
        message = stripped
    return _MANGLED_RE.sub(_unmangle, message) or "unknown error"


# -- TLS contexts -----------------------------------------------------------------


def ca_context(cafile: str | None = None) -> ssl.SSLContext:
    """Normal CA validation: the system store plus certifi, or one CA bundle."""
    if cafile:
        return ssl.create_default_context(cafile=cafile)
    ctx = ssl.create_default_context()
    ctx.load_verify_locations(cafile=certifi.where())
    return ctx


def insecure_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


class _ClientCertError(Exception):
    pass


# -- the base class -----------------------------------------------------------------

Operation = Callable[[httpx.AsyncClient], Awaitable[SessionRelevanceResult]]
# No PEP 695 type parameters: the package still supports Python 3.11.
T = TypeVar("T")


class Backend(ABC):
    """One connection to one BigFix interface. Use as an async context manager."""

    name: ClassVar[str]
    supports_token: ClassVar[bool] = True

    def __init__(
        self,
        server: str | ServerAddress,
        *,
        username: str | None = None,
        password: str | None = None,
        token: str | None = None,
        client_cert: str | None = None,
        client_key: str | None = None,
        client_key_password: str | None = None,
        connection: str | None = None,
        deployment_id: str | None = None,
        verify: bool | str = True,
        trust: TrustPolicy | None = None,
        connect_timeout: float = 5.0,
        read_timeout: float = 120.0,
        retries: int = 1,
        transport: httpx.AsyncBaseTransport | None = None,
        local_root_server: bool = False,
    ) -> None:
        self.address = (
            server if isinstance(server, ServerAddress) else normalize_server(server, self.name)
        )
        self.username = username
        self._password = password
        self._token = token
        self.client_cert = client_cert
        self.client_key = client_key
        self._client_key_password = client_key_password
        self.connection = connection
        self.deployment_id = deployment_id
        self.verify = verify
        self.trust = trust
        self.timeout = httpx.Timeout(read_timeout, connect=connect_timeout)
        self.retries = retries
        self._transport = transport
        self._client: httpx.AsyncClient | None = None
        # The local root server's own credentials replace address, username
        # and password on first use (see resolve_credentials).
        self._credentials_resolved = not local_root_server
        self._credentials_problem: ResultError | None = None
        self._credentials_lock: asyncio.Lock | None = None
        if self.address.scheme == "http":
            log.warning(
                "%s (%s): http:// sends credentials in cleartext; prefer https",
                connection or self.name,
                self.address.base_url,
            )
        if verify is False and self.address.scheme == "https":
            log.warning(
                "%s (%s): TLS certificate verification is disabled",
                connection or self.name,
                self.address.base_url,
            )

    @classmethod
    def from_config(
        cls,
        conn: ConnectionConfig,
        *,
        trust: TrustPolicy | None = None,
        prompt: Callable[[str], str] | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> Self:
        return cls(
            conn.address,
            username=conn.username,
            password=conn.resolve_password(prompt=prompt) if conn.auth == "basic" else None,
            token=conn.resolve_token(),
            client_cert=conn.client_cert,
            client_key=conn.client_key,
            client_key_password=conn.resolve_client_key_password(),
            connection=conn.name,
            deployment_id=conn.deployment_id,
            verify=conn.verify if conn.verify is not None else "tofu",
            trust=trust,
            connect_timeout=conn.connect_timeout or 5.0,
            read_timeout=conn.read_timeout or 120.0,
            transport=transport,
            local_root_server=conn.credentials == local_root_server.LOCAL_ROOT_SERVER,
            **cls._config_kwargs(conn, prompt),
        )

    @classmethod
    def _config_kwargs(
        cls, conn: ConnectionConfig, prompt: Callable[[str], str] | None
    ) -> dict[str, Any]:
        """Backend-specific constructor arguments taken from the config."""
        return {}

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}(connection={self.connection!r}, "
            f"server={self.address.base_url!r}, auth={self.auth!r})"
        )

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    @property
    def auth(self) -> str:
        if self._token is not None:
            return "token"
        if self.username is not None:
            return "basic"
        if self.client_cert is not None:
            return "mtls"
        return "none"

    # -- public API -----------------------------------------------------------------

    async def evaluate(self, session_relevance: str) -> SessionRelevanceResult:
        """Evaluate plain session relevance. Never raises for per-query failures."""
        return await self._run(
            session_relevance, lambda client: self._evaluate(client, session_relevance)
        )

    @abstractmethod
    async def _evaluate(
        self, client: httpx.AsyncClient, session_relevance: str
    ) -> SessionRelevanceResult: ...

    async def resolve_credentials(self) -> ResultError | None:
        """Read the local root server credentials, once; the error if they failed.

        Done on first use rather than when built, and in a thread: decrypting
        runs CryptoUtility (Linux) and must not block the event loop.
        """
        if self._credentials_resolved:
            return self._credentials_problem
        if self._credentials_lock is None:
            self._credentials_lock = asyncio.Lock()
        async with self._credentials_lock:
            if not self._credentials_resolved:
                self._credentials_problem = await asyncio.to_thread(self._apply_local_credentials)
                self._credentials_resolved = True
        return self._credentials_problem

    def _apply_local_credentials(self) -> ResultError | None:
        try:
            creds = local_root_server.read_credentials()
            address = normalize_server(creds.server, self.name)
        except local_root_server.LocalRootServerError as exc:
            return self._local_credentials_error(exc.code, str(exc))
        except ConfigError as exc:
            return self._local_credentials_error(
                "local_credentials_incomplete", f"RESTURL is not usable: {exc}"
            )
        self.address, self.username, self._password = address, creds.username, creds.password
        return None

    def _local_credentials_error(self, code: str, message: str) -> ResultError:
        return ResultError(
            kind="authentication",
            code=code,
            backend=self.name,
            message=f"local root server credentials: {message}",
        )

    # -- machinery shared by every backend -------------------------------------------

    def _auth_problem(self) -> ResultError | None:
        if self.auth == "basic" and self._password is None:
            return ResultError(
                kind="authentication",
                backend=self.name,
                message=(
                    f"no password available for {self.username!r} "
                    "(set password_env, password, or run interactively)"
                ),
            )
        return None

    def _request_headers(self) -> dict[str, str]:
        if self._token is not None:
            return {"Authorization": f"Bearer {self._token}"}
        return {}

    def _basic_auth(self) -> httpx.BasicAuth | None:
        if self.auth == "basic" and self._password is not None:
            return httpx.BasicAuth(self.username or "", self._password)
        return None

    def _tofu_active(self) -> bool:
        return (
            self.verify == "tofu"
            and self.trust is not None
            and self.address.scheme == "https"
            and self._transport is None
        )

    def _ssl_context(self) -> ssl.SSLContext:
        if self.verify is False:
            ctx = insecure_context()
        elif self.verify is True:
            ctx = ca_context()
        elif self.verify == "tofu":
            ctx = self.trust.ssl_context(self.address) if self.trust is not None else ca_context()
        else:
            ctx = ca_context(str(self.verify))
        if self.client_cert:
            try:
                ctx.load_cert_chain(
                    self.client_cert, self.client_key, password=self._client_key_password
                )
            except (OSError, ssl.SSLError) as exc:
                raise _ClientCertError(str(exc)) from exc
        return ctx

    def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            if self._transport is not None:
                transport = self._transport
            elif self.address.scheme == "https":
                transport = httpx.AsyncHTTPTransport(
                    verify=self._ssl_context(), retries=self.retries
                )
            else:
                transport = httpx.AsyncHTTPTransport(retries=self.retries)
            self._client = httpx.AsyncClient(
                base_url=self.address.base_url,
                transport=transport,
                timeout=self.timeout,
                auth=self._basic_auth(),
                headers=self._request_headers(),
                follow_redirects=False,
            )
        return self._client

    async def _run(self, session_relevance: str, operation: Operation) -> SessionRelevanceResult:
        start = time.perf_counter()
        result = await self._run_with_trust(session_relevance, operation)
        return result.replace(
            connection=self.connection,
            deployment_id=self.deployment_id,
            backend=self.name,
            server=self.address.base_url,
            elapsed_ms=round((time.perf_counter() - start) * 1000, 3),
        )

    async def _run_with_trust(
        self, session_relevance: str, operation: Operation
    ) -> SessionRelevanceResult:
        result = await self._with_trust(operation)
        if isinstance(result, ResultError):
            return SessionRelevanceResult.failure(session_relevance, result)
        return result

    async def _with_trust(
        self, operation: Callable[[httpx.AsyncClient], Awaitable[T]]
    ) -> T | ResultError:
        """Run one operation with credentials and TLS trust (TOFU) applied.

        Every call to the server goes through here, so any API a backend
        adds gets the same credential checks, pinning and error mapping as
        ``evaluate()``. Failures come back as the `ResultError`, never raised.
        """
        problem = await self.resolve_credentials() or self._auth_problem()
        if problem is not None:
            return problem
        for attempt in range(2):
            try:
                client = self._get_client()
            except _ClientCertError as exc:
                return ResultError(
                    kind="tls",
                    code="client_cert",
                    backend=self.name,
                    message=f"cannot load client certificate: {exc}",
                )
            try:
                return await operation(client)
            except httpx.HTTPError as exc:
                err = error_from_exception(exc, self.name)
                if (
                    err.kind == "tls"
                    and err.code == "cert_verify_failed"
                    and self._tofu_active()
                    and self.trust is not None
                ):
                    if self.trust.is_pinned(self.address):
                        error = await self.trust.mismatch_error(self.address, self.name)
                        if error.code == "pinned_cert_invalid":
                            # Same cert as pinned, so the cert itself fails
                            # (expired, or a TLS check): say which.
                            error = dataclasses.replace(
                                error, message=f"{error.message}: {err.message}"
                            )
                        return error
                    if attempt == 0 and await self.trust.on_untrusted(self.address):
                        await self.aclose()
                        continue
                    err = self._untrusted_error(err)
                return err
        raise AssertionError("unreachable")  # pragma: no cover

    def _untrusted_error(self, err: ResultError) -> ResultError:
        """``tls/untrusted``, worded for any front end, not just the CLI.

        The fingerprint comes from the store's record of the refused cert
        (`TrustStore.pending`); a custom `TrustPolicy` may keep none.
        """
        host_port = self.address.host_port
        pending = getattr(self.trust, "pending", None)
        info = pending.get(host_port) if isinstance(pending, dict) else None
        fingerprint = getattr(info, "fingerprint", None)
        if isinstance(fingerprint, str):
            message = (
                f"certificate for {host_port} is not trusted yet (SHA-256 {fingerprint}); "
                "confirm it to pin it"
            )
        else:
            message = f"certificate for {host_port} is not trusted and was not pinned"
        return ResultError(
            kind="tls",
            code="untrusted",
            backend=self.name,
            message=message,
            detail=f"{err.message} (CLI: --trust-cert {host_port})",
        )

    def _response_problem(self, response: httpx.Response) -> ResultError | None:
        """Auth failures are decided by status alone, before any body parsing."""
        if response.status_code in (401, 403):
            return error_from_status(response, self.name)
        return None
