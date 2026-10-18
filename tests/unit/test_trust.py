"""Trust on first use, against a real local TLS server."""

from __future__ import annotations

import asyncio
import hashlib
import logging
import ssl
import stat
import sys
from pathlib import Path

import pytest

from bigfix_remote_session_relevance.backends.rest import RestBackend
from bigfix_remote_session_relevance.trust import (
    CertInfo,
    KnownCerts,
    TrustStore,
    default_known_certs_path,
    fetch_server_cert,
    pinned_context,
)

pytestmark = pytest.mark.tls_local


def _fingerprint(pem_path: Path) -> str:
    return hashlib.sha256(ssl.PEM_cert_to_DER_cert(pem_path.read_text())).hexdigest()


def _backend(port: int, store: TrustStore) -> RestBackend:
    return RestBackend(
        f"127.0.0.1:{port}",
        username="op",
        password="pw",
        verify="tofu",
        trust=store,
        connect_timeout=5,
        read_timeout=10,
    )


def test_default_known_certs_path(_isolated_home: Path) -> None:
    assert default_known_certs_path() == (
        _isolated_home / ".bigfix" / ".remote_session_known_certs.toml"
    )


async def test_fetch_server_cert(tls_server, tls_certs) -> None:  # type: ignore[no-untyped-def]
    server = tls_server("self_a")
    info = await fetch_server_cert("127.0.0.1", server.port)
    assert info.sha256 == _fingerprint(tls_certs["self_a_pem"])
    assert info.host_port == f"127.0.0.1:{server.port}"
    assert "BEGIN CERTIFICATE" in info.pem
    assert server.requests == []  # a bare handshake, no HTTP request


async def test_first_use_auto_pins_and_logs(
    tls_server,
    tls_certs,
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,  # type: ignore[no-untyped-def]
) -> None:
    server = tls_server("self_a")
    known = KnownCerts(tmp_path / "known.toml")
    with caplog.at_level(logging.WARNING):
        async with _backend(server.port, TrustStore(known)) as backend:
            result = await backend.evaluate("1")
    assert result.ok, result.error
    pin = known.get(f"127.0.0.1:{server.port}")
    assert pin is not None
    assert pin.sha256 == _fingerprint(tls_certs["self_a_pem"])
    assert pin.trusted_by == "auto"
    assert pin.sha256[:16] in caplog.text
    if sys.platform != "win32":
        assert stat.S_IMODE((tmp_path / "known.toml").stat().st_mode) == 0o600


async def test_prompt_callback_accepts(tls_server, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    server = tls_server("self_a")
    seen: list[CertInfo] = []

    async def callback(info: CertInfo) -> bool:
        seen.append(info)
        return True

    known = KnownCerts(tmp_path / "known.toml")
    async with _backend(server.port, TrustStore(known, callback=callback)) as backend:
        result = await backend.evaluate("1")
    assert result.ok
    assert len(seen) == 1
    pin = known.get(f"127.0.0.1:{server.port}")
    assert pin is not None
    assert pin.trusted_by == "prompt"


async def test_declined_prompt_is_tls_error_and_sends_nothing(
    tls_server,
    tmp_path: Path,  # type: ignore[no-untyped-def]
) -> None:
    server = tls_server("self_a")
    known = KnownCerts(tmp_path / "known.toml")
    store = TrustStore(known, callback=lambda info: False)
    async with _backend(server.port, store) as backend:
        result = await backend.evaluate("1")
    assert result.error is not None
    assert (result.error.kind, result.error.code) == ("tls", "untrusted")
    assert known.get(f"127.0.0.1:{server.port}") is None
    assert server.requests == []


async def test_tofu_disabled(tls_server, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    server = tls_server("self_a")
    store = TrustStore(KnownCerts(tmp_path / "known.toml"), trust_on_first_use=False)
    async with _backend(server.port, store) as backend:
        result = await backend.evaluate("1")
    assert result.error is not None
    assert result.error.code == "untrusted"


async def test_matching_pin_connects_without_asking(
    tls_server,
    tmp_path: Path,  # type: ignore[no-untyped-def]
) -> None:
    server = tls_server("self_a")
    known = KnownCerts(tmp_path / "known.toml")
    known.pin(await fetch_server_cert("127.0.0.1", server.port), trusted_by="wizard")

    def never(info: CertInfo) -> bool:
        raise AssertionError("must not prompt for a pinned cert")

    async with _backend(server.port, TrustStore(known, callback=never)) as backend:
        result = await backend.evaluate("1")
    assert result.ok, result.error
    assert server.requests[0][1] is not None  # credentials sent only after the pin matched


async def test_pinned_bigfix_style_cert_connects(tls_server, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    # BigFix Explorer serves a self-signed cert with no extensions and a
    # negative serial. Python 3.13+ turns on VERIFY_X509_STRICT by default,
    # which rejected it right after the user pinned it ("invalid CA
    # certificate"); the pin, not RFC 5280 conformance, is the trust check.
    server = tls_server("bigfix")
    known = KnownCerts(tmp_path / "known.toml")
    known.pin(await fetch_server_cert("127.0.0.1", server.port), trusted_by="prompt")
    async with _backend(server.port, TrustStore(known)) as backend:
        result = await backend.evaluate("1")
    assert result.ok, result.error


async def test_pinned_cert_that_stops_validating_says_why(tls_server, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    server = tls_server("expired")
    known = KnownCerts(tmp_path / "known.toml")
    known.pin(await fetch_server_cert("127.0.0.1", server.port), trusted_by="prompt")
    async with _backend(server.port, TrustStore(known)) as backend:
        result = await backend.evaluate("1")
    assert result.error is not None
    assert result.error.code == "pinned_cert_invalid"
    # OpenSSL's own reason, not a guess: a guess of "expired?" misled when
    # the real cause was Python 3.13+'s strict checks.
    assert "certificate has expired" in result.error.message
    assert "expired?" not in result.error.message
    assert server.requests == []  # nothing, credentials included, was sent


def test_pinned_context_is_not_strict(tls_certs) -> None:  # type: ignore[no-untyped-def]
    ctx = pinned_context(tls_certs["bigfix_pem"].read_text())
    assert not ctx.verify_flags & ssl.VERIFY_X509_STRICT
    assert ctx.verify_flags & ssl.VERIFY_X509_PARTIAL_CHAIN


async def test_changed_cert_is_hard_error_and_leaks_no_credentials(
    tls_server,
    tls_certs,
    tmp_path: Path,  # type: ignore[no-untyped-def]
) -> None:
    first = tls_server("self_a")
    known = KnownCerts(tmp_path / "known.toml")
    info_a = await fetch_server_cert("127.0.0.1", first.port)
    # Pin cert A for the port the impostor (cert B) listens on.
    impostor = tls_server("self_b")
    known.pin(
        CertInfo(
            host_port=f"127.0.0.1:{impostor.port}",
            sha256=info_a.sha256,
            pem=info_a.pem,
        ),
        trusted_by="prompt",
    )
    before = (tmp_path / "known.toml").read_text()

    def never(info: CertInfo) -> bool:
        raise AssertionError("a changed cert must never prompt")

    async with _backend(impostor.port, TrustStore(known, callback=never)) as backend:
        result = await backend.evaluate("1")
    assert result.error is not None
    assert (result.error.kind, result.error.code) == ("tls", "pin_mismatch")
    assert info_a.sha256[:16] in result.error.message
    assert _fingerprint(tls_certs["self_b_pem"])[:16] in result.error.message
    assert impostor.requests == []
    assert (tmp_path / "known.toml").read_text() == before


async def test_ca_valid_cert_pins_nothing(
    tls_server,
    tls_certs,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,  # type: ignore[no-untyped-def]
) -> None:
    monkeypatch.setenv("SSL_CERT_FILE", str(tls_certs["ca_pem"]))
    server = tls_server("leaf")
    known = KnownCerts(tmp_path / "known.toml")

    def never(info: CertInfo) -> bool:
        raise AssertionError("a CA-valid cert must not prompt")

    async with _backend(server.port, TrustStore(known, callback=never)) as backend:
        result = await backend.evaluate("1")
    assert result.ok, result.error
    assert known.all() == []


async def test_concurrent_first_use_pins_once(tls_server, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    server = tls_server("self_a")
    calls = 0

    async def callback(info: CertInfo) -> bool:
        nonlocal calls
        calls += 1
        await asyncio.sleep(0.05)
        return True

    known = KnownCerts(tmp_path / "known.toml")
    store = TrustStore(known, callback=callback)
    backends = [_backend(server.port, store) for _ in range(5)]
    results = await asyncio.gather(*(b.evaluate("1") for b in backends))
    for b in backends:
        await b.aclose()
    assert all(r.ok for r in results), [r.error for r in results]
    assert calls == 1
    assert len(known.all()) == 1


def test_known_certs_forget_and_all(tmp_path: Path) -> None:
    known = KnownCerts(tmp_path / "known.toml")
    info = CertInfo(host_port="h:1", sha256="ab" * 32, pem="PEM")
    known.pin(info, trusted_by="auto")
    known.pin(CertInfo(host_port="[::1]:2", sha256="cd" * 32, pem="PEM2"), trusted_by="prompt")
    assert {p.host_port for p in known.all()} == {"h:1", "[::1]:2"}
    assert known.forget("h:1") is True
    assert known.forget("h:1") is False
    assert [p.host_port for p in KnownCerts(tmp_path / "known.toml").all()] == ["[::1]:2"]
