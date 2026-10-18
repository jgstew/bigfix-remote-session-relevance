"""Trust on first use (TOFU) for self-signed BigFix certificates.

BigFix root servers, Explorer and often Web Reports present self-signed or
deployment-CA certificates. In ``verify = "tofu"`` mode (the default):

1. Normal CA validation is tried first; a CA-valid cert is never pinned.
2. Otherwise the cert is fetched with a bare handshake (no credentials
   sent), shown to the trust callback (the CLI prompts), and pinned to
   ``~/.bigfix/.remote_session_known_certs.toml``. With no callback it is
   pinned automatically and logged, which is classic TOFU.
3. Afterwards the pinned cert is the *only* trust anchor for that
   ``host:port``, so OpenSSL rejects anything else during the handshake,
   before an Authorization header or SOAP password is sent.
4. A pinned host presenting a different cert is a hard ``tls`` error
   (``pin_mismatch``). It is never re-pinned silently and never failed
   over around, because it is a security signal, not an outage.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import inspect
import logging
import os
import ssl
import tempfile
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import tomlkit
from filelock import FileLock

from .backends.base import ca_context, insecure_context
from .result import ResultError
from .server_address import ServerAddress

log = logging.getLogger(__name__)

TrustCallback = Callable[["CertInfo"], bool | Awaitable[bool]]


def default_known_certs_path() -> Path:
    return Path.home() / ".bigfix" / ".remote_session_known_certs.toml"


@dataclass(frozen=True)
class CertInfo:
    """A certificate a server presented."""

    host_port: str
    sha256: str
    pem: str

    @property
    def fingerprint(self) -> str:
        """``AB:CD:…`` form, as browsers and openssl show it."""
        return ":".join(self.sha256[i : i + 2] for i in range(0, len(self.sha256), 2)).upper()


@dataclass(frozen=True)
class Pin:
    host_port: str
    sha256: str
    pem: str
    first_seen: str
    trusted_by: str


async def fetch_server_cert(host: str, port: int, *, handshake_timeout: float = 10.0) -> CertInfo:
    """Fetch the leaf cert with a bare TLS handshake. No HTTP request is made."""
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(host, port, ssl=insecure_context(), server_hostname=host),
        handshake_timeout,
    )
    try:
        ssl_object = writer.get_extra_info("ssl_object")
        der = ssl_object.getpeercert(binary_form=True) if ssl_object else None
    finally:
        writer.close()
        with contextlib.suppress(OSError, ssl.SSLError):
            await writer.wait_closed()
    del reader
    if not der:
        raise ssl.SSLError(f"{host}:{port} presented no certificate")
    address = ServerAddress(scheme="https", host=host, port=port)
    return CertInfo(
        host_port=address.host_port,
        sha256=hashlib.sha256(der).hexdigest(),
        pem=ssl.DER_cert_to_PEM_cert(der),
    )


def pinned_context(pem: str) -> ssl.SSLContext:
    """A context whose only trust anchor is the pinned certificate.

    PARTIAL_CHAIN lets OpenSSL accept the pinned leaf itself as an anchor, and
    hostname checking is off because BigFix certs rarely match the URL host;
    the pin is the stronger check. X509_STRICT, on by default since Python
    3.13, is off for the same reason: it rejects the self-signed X.509 v1
    cert a real BigFix Explorer serves ("invalid CA certificate") even though
    it is byte-for-byte the cert the user pinned (observed).
    """
    ctx = ssl.create_default_context(cadata=pem)
    ctx.check_hostname = False
    ctx.verify_flags |= ssl.VERIFY_X509_PARTIAL_CHAIN
    ctx.verify_flags &= ~ssl.VERIFY_X509_STRICT
    return ctx


class KnownCerts:
    """The pinned-certificate file. Safe for concurrent processes."""

    def __init__(self, path: str | os.PathLike[str] | None = None) -> None:
        self.path = Path(path) if path is not None else default_known_certs_path()
        self._lock = FileLock(str(self.path) + ".lock")

    def _read(self) -> tomlkit.TOMLDocument:
        if not self.path.is_file():
            doc = tomlkit.document()
            doc.add(tomlkit.comment("Certificates pinned by bigfix-remote-session-relevance"))
            doc.add(tomlkit.comment("(trust on first use). Delete an entry, or run"))
            doc.add(tomlkit.comment("--forget-cert host:port, to be asked again."))
            doc.add("certs", tomlkit.table())
            return doc
        return tomlkit.parse(self.path.read_text(encoding="utf-8"))

    def get(self, host_port: str) -> Pin | None:
        entry = self._read().get("certs", {}).get(host_port)
        return _pin(host_port, entry) if entry else None

    def all(self) -> list[Pin]:
        certs = self._read().get("certs", {})
        return [_pin(key, value) for key, value in certs.items()]

    def pin(self, info: CertInfo, *, trusted_by: str) -> Pin:
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with self._lock:
            doc = self._read()
            certs = doc.setdefault("certs", tomlkit.table())
            entry = tomlkit.table()
            entry.add("sha256", info.sha256)
            entry.add("first_seen", datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"))
            entry.add("trusted_by", trusted_by)
            entry.add("pem", tomlkit.string(info.pem, multiline=True))
            certs[info.host_port] = entry
            self._write(doc)
        pin = self.get(info.host_port)
        if pin is None:  # pragma: no cover - just written under the lock
            raise OSError(f"could not read back the pin for {info.host_port}")
        return pin

    def forget(self, host_port: str) -> bool:
        if not self.path.is_file():
            return False
        with self._lock:
            doc = self._read()
            certs = doc.get("certs", {})
            if host_port not in certs:
                return False
            del certs[host_port]
            self._write(doc)
        return True

    def _write(self, doc: tomlkit.TOMLDocument) -> None:
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


def _pin(host_port: str, data: Mapping[str, Any]) -> Pin:
    return Pin(
        host_port=host_port,
        sha256=str(data.get("sha256", "")),
        pem=str(data.get("pem", "")),
        first_seen=str(data.get("first_seen", "")),
        trusted_by=str(data.get("trusted_by", "")),
    )


class TrustStore:
    """Implements the backends' `TrustPolicy` on top of `KnownCerts`."""

    def __init__(
        self,
        known: KnownCerts | None = None,
        *,
        callback: TrustCallback | None = None,
        trust_on_first_use: bool = True,
    ) -> None:
        self.known = known or KnownCerts()
        self.callback = callback
        self.trust_on_first_use = trust_on_first_use
        self._locks: dict[str, asyncio.Lock] = {}
        # One prompt at a time across hosts, or interactive questions interleave.
        self._prompt_lock: asyncio.Lock | None = None

    def is_pinned(self, address: ServerAddress) -> bool:
        return self.known.get(address.host_port) is not None

    def ssl_context(self, address: ServerAddress) -> ssl.SSLContext:
        pin = self.known.get(address.host_port)
        return pinned_context(pin.pem) if pin else ca_context()

    async def on_untrusted(self, address: ServerAddress) -> bool:
        """First use: fetch, ask (or auto-accept), pin. True when now pinned."""
        lock = self._locks.setdefault(address.host_port, asyncio.Lock())
        async with lock:
            if self.is_pinned(address):
                return True  # another connection pinned it while we waited
            if not self.trust_on_first_use:
                return False
            try:
                info = await fetch_server_cert(address.host, address.port)
            except (OSError, ssl.SSLError, TimeoutError) as exc:
                log.warning("cannot fetch certificate from %s: %s", address.host_port, exc)
                return False
            if self.callback is None:
                log.warning(
                    "trusting certificate for %s on first use (sha256 %s); pinned in %s",
                    info.host_port,
                    info.sha256,
                    self.known.path,
                )
                trusted_by = "auto"
                accepted = True
            else:
                if self._prompt_lock is None:
                    self._prompt_lock = asyncio.Lock()
                async with self._prompt_lock:
                    decision = self.callback(info)
                    accepted = (
                        bool(await decision) if inspect.isawaitable(decision) else bool(decision)
                    )
                trusted_by = "prompt"
            if accepted:
                self.known.pin(info, trusted_by=trusted_by)
            return accepted

    async def mismatch_error(self, address: ServerAddress, backend: str) -> ResultError:
        pin = self.known.get(address.host_port)
        pinned = pin.sha256 if pin else "?"
        try:
            presented = (await fetch_server_cert(address.host, address.port)).sha256
        except (OSError, ssl.SSLError, TimeoutError):
            presented = "unavailable"
        if presented == pinned:
            return ResultError(
                kind="tls",
                code="pinned_cert_invalid",
                backend=backend,
                message=(
                    f"pinned certificate for {address.host_port} no longer validates "
                    f"(sha256 {pinned[:16]}…)"
                ),
            )
        return ResultError(
            kind="tls",
            code="pin_mismatch",
            backend=backend,
            message=(
                f"certificate for {address.host_port} changed (pinned sha256 {pinned[:16]}…, "
                f"presented {presented[:16]}…); possible interception. Verify it out of band, "
                f"then re-trust with --trust-cert {address.host_port}"
            ),
            detail=f"pinned={pinned} presented={presented}",
        )
