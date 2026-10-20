"""Shared test setup.

Two jobs:

* Isolation: every test gets a throwaway HOME, so nothing can read or write
  the developer's real ``~/.bigfix`` (connections, pinned certs).
* Live opt-in: tests marked ``live_*`` talk to real servers, so they run
  only when asked: set ``BFRSR_LIVE_CONFIG=path``, or ``BFRSR_LIVE_TESTS=1``
  to use the real default config path. They are also skipped when that file
  has no enabled connection of the needed backend. The path is resolved at
  import time, before HOME is redirected.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path
from typing import Any

import pytest

_REAL_DEFAULT_CONFIG = Path.home() / ".bigfix" / ".remote_session_connections.toml"
LIVE_CONFIG_PATH = Path(os.environ.get("BFRSR_LIVE_CONFIG", _REAL_DEFAULT_CONFIG)).expanduser()
LIVE_ENABLED = (
    bool(os.environ.get("BFRSR_LIVE_CONFIG")) or os.environ.get("BFRSR_LIVE_TESTS") == "1"
)

_LIVE_MARKERS = {
    "live_rest": "rest",
    "live_webreports": "webreports",
    "live_explorer": "explorer",
    "live_saas": "saas",
}


def _live_backends() -> set[str]:
    """Backends present in the live config, read without exposing values."""
    if not LIVE_ENABLED or not LIVE_CONFIG_PATH.is_file():
        return set()
    try:
        from bigfix_remote_session_relevance.config import load_config

        config = load_config(LIVE_CONFIG_PATH)
    except Exception:  # noqa: BLE001 - a bad live config just skips live tests
        return set()
    return {c.backend for c in config.connections if c.enabled}


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    live_backends: set[str] | None = None
    have_openssl = shutil.which("openssl") is not None
    for item in items:
        if "tls_local" in item.keywords and not have_openssl:
            item.add_marker(pytest.mark.skip(reason="openssl CLI not found"))
        for marker, backend in _LIVE_MARKERS.items():
            if marker in item.keywords:
                if live_backends is None:
                    live_backends = _live_backends()
                if not LIVE_ENABLED:
                    item.add_marker(
                        pytest.mark.skip(reason="live test: set BFRSR_LIVE_TESTS=1 to run")
                    )
                elif backend not in live_backends:
                    item.add_marker(
                        pytest.mark.skip(reason=f"no enabled {backend} connection in live config")
                    )


@pytest.fixture(autouse=True)
def _isolated_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    for var in (
        "BFRSR_CONFIG",
        "BFRSR_LOCAL_ROOT_SERVER",
        "BES_ROOT_SERVER",
        "BES_USER_NAME",
        "BES_PASSWORD",
    ):
        monkeypatch.delenv(var, raising=False)
    # Never pick up the machine's own root server credentials (even on one):
    # point the Linux paths at nothing and take the non-Windows code path.
    from bigfix_remote_session_relevance import local_root_server

    monkeypatch.setattr(local_root_server, "_IS_WINDOWS", False)
    monkeypatch.setattr(
        local_root_server, "CREDENTIALS_FILE", tmp_path / "no-root-server" / "creds"
    )
    monkeypatch.setattr(local_root_server, "CRYPTO_UTILITY", tmp_path / "no-root-server" / "crypto")
    return home


@pytest.fixture
def live_config_path() -> Path:
    return LIVE_CONFIG_PATH


@pytest.fixture
def fixtures_dir() -> Path:
    return Path(__file__).parent / "fixtures"


class RecordingTransport:
    """An httpx.MockTransport that records requests and replays responses.

    ``responses`` is a list of httpx.Response or exceptions (raised), consumed
    in order; the last entry repeats once the list is exhausted.
    """

    def __init__(self, responses: list[object]) -> None:
        import httpx

        self.requests: list[httpx.Request] = []
        self._responses = list(responses)
        self.transport = httpx.MockTransport(self._handle)

    def _handle(self, request: Any) -> Any:
        self.requests.append(request)
        item = self._responses.pop(0) if len(self._responses) > 1 else self._responses[0]
        if isinstance(item, BaseException):
            raise item
        return item


@pytest.fixture
def recording_transport() -> type[RecordingTransport]:
    return RecordingTransport


# -- local TLS server for trust-on-first-use tests ------------------------------


def _openssl(*args: str) -> None:
    import subprocess

    done = subprocess.run(  # noqa: S603
        ["openssl", *args],  # noqa: S607
        check=False,
        capture_output=True,
        text=True,
    )
    if done.returncode:
        # OpenSSL's own message: CI logs otherwise show only the exit status.
        raise RuntimeError(f"openssl {args[0]} failed: {done.stderr.strip()}")


def _der_element(der: bytes, i: int) -> tuple[int, int, int]:
    """(tag, content start, end) of the DER element at ``i``."""
    tag, length, i = der[i], der[i + 1], i + 2
    if length & 0x80:
        size = length & 0x7F
        length, i = int.from_bytes(der[i : i + size], "big"), i + size
    return tag, i, i + length


def _der(tag: int, body: bytes) -> bytes:
    n = len(body)
    if n < 0x80:
        return bytes([tag, n]) + body
    size = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(size)]) + size + body


def _make_v1(pem: Path, key: Path) -> None:
    """Rewrite an extension-less cert as X.509 v1 and re-sign it.

    Newer OpenSSL always writes v3, but real BigFix Explorer certs are v1, and
    Python's strict verification treats the two differently.
    """
    import ssl
    import subprocess

    der = ssl.PEM_cert_to_DER_cert(pem.read_text())
    _, start, _ = _der_element(der, 0)
    _, tbs_start, tbs_end = _der_element(der, start)
    _, _, alg_end = _der_element(der, tbs_end)
    version_tag, _, version_end = _der_element(der, tbs_start)
    if version_tag != 0xA0:  # no [0] EXPLICIT version: already v1 (OpenSSL < 3.2)
        return
    tbs = _der(0x30, der[version_end:tbs_end])
    tbs_path = pem.with_suffix(".tbs")
    tbs_path.write_bytes(tbs)
    signature = subprocess.run(  # noqa: S603
        ["openssl", "dgst", "-sha256", "-sign", str(key), str(tbs_path)],  # noqa: S607
        check=True,
        capture_output=True,
    ).stdout
    cert = _der(0x30, tbs + der[tbs_end:alg_end] + _der(0x03, b"\x00" + signature))
    pem.write_text(ssl.DER_cert_to_PEM_cert(cert))


@pytest.fixture(scope="session")
def tls_certs(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Path]:
    """Throwaway certs minted per test session; no private key is committed.

    ``self_a`` / ``self_b``: two different self-signed certs for 127.0.0.1.
    ``ca`` + ``leaf``: a CA and a leaf it signed, for the CA-valid path.
    ``expired``: self-signed for 127.0.0.1, valid only in early 2020.
    ``bigfix``: the shape of the cert a real BigFix Explorer serves (observed):
    self-signed X.509 *v1*, no extensions, negative serial, CN=BIGFIX.
    """
    if shutil.which("openssl") is None:
        pytest.skip("openssl CLI not found")
    d = tmp_path_factory.mktemp("tls")
    ec = ["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes"]
    for name in ("self_a", "self_b"):
        _openssl(
            "req",
            "-x509",
            *ec,
            "-keyout",
            str(d / f"{name}.key"),
            "-out",
            str(d / f"{name}.pem"),
            "-days",
            "2",
            "-subj",
            f"/CN=bfrsr-{name}",
            "-addext",
            "subjectAltName=IP:127.0.0.1",
        )
    _openssl(
        "req",
        "-x509",
        *ec,
        "-keyout",
        str(d / "ca.key"),
        "-out",
        str(d / "ca.pem"),
        "-days",
        "2",
        "-subj",
        "/CN=bfrsr-test-ca",
        "-addext",
        "basicConstraints=critical,CA:TRUE",
        "-addext",
        "keyUsage=critical,keyCertSign",
    )
    _openssl(
        "req",
        "-new",
        *ec,
        "-keyout",
        str(d / "leaf.key"),
        "-out",
        str(d / "leaf.csr"),
        "-subj",
        "/CN=127.0.0.1",
    )
    # authorityKeyIdentifier, as on any real CA-issued leaf: Python 3.13+
    # verifies strictly and rejects a leaf without one.
    (d / "leaf.ext").write_text(
        "subjectAltName=IP:127.0.0.1\nbasicConstraints=CA:FALSE\nauthorityKeyIdentifier=keyid\n"
    )
    _openssl(
        "x509",
        "-req",
        "-in",
        str(d / "leaf.csr"),
        "-CA",
        str(d / "ca.pem"),
        "-CAkey",
        str(d / "ca.key"),
        "-CAcreateserial",
        "-out",
        str(d / "leaf.pem"),
        "-days",
        "2",
        "-extfile",
        str(d / "leaf.ext"),
    )
    # `openssl ca` rather than `req -not_after`: the latter is OpenSSL 3.4+,
    # and CI's Ubuntu ships 3.0.
    _openssl(
        "req",
        "-new",
        *ec,
        "-keyout",
        str(d / "expired.key"),
        "-out",
        str(d / "expired.csr"),
        "-subj",
        "/CN=bfrsr-expired",
    )
    ca_dir = d / "expired-ca"
    ca_dir.mkdir()
    (ca_dir / "index.txt").write_text("")
    (ca_dir / "serial").write_text("01\n")
    (ca_dir / "ca.cnf").write_text(
        "[ca]\ndefault_ca = expired\n"
        # Forward slashes: OpenSSL's config parser treats a backslash as an escape,
        # which mangles Windows paths; OpenSSL on Windows accepts "/".
        f"[expired]\ndatabase = {(ca_dir / 'index.txt').as_posix()}\n"
        f"serial = {(ca_dir / 'serial').as_posix()}\n"
        f"new_certs_dir = {ca_dir.as_posix()}\ndefault_md = sha256\npolicy = any\n"
        "[any]\ncommonName = supplied\n"
    )
    _openssl(
        "ca",
        "-batch",
        "-selfsign",
        "-config",
        str(ca_dir / "ca.cnf"),
        "-keyfile",
        str(d / "expired.key"),
        "-in",
        str(d / "expired.csr"),
        "-out",
        str(d / "expired.pem"),
        "-startdate",
        "20200101000000Z",
        "-enddate",
        "20200102000000Z",
        "-notext",
    )
    _openssl(
        "req",
        "-new",
        *ec,
        "-keyout",
        str(d / "bigfix.key"),
        "-out",
        str(d / "bigfix.csr"),
        "-subj",
        "/CN=BIGFIX",
    )
    _openssl(
        "x509",
        "-req",
        "-in",
        str(d / "bigfix.csr"),
        "-signkey",
        str(d / "bigfix.key"),
        "-set_serial",
        "-32598752",
        "-out",
        str(d / "bigfix.pem"),
        "-days",
        "2",
    )
    _make_v1(d / "bigfix.pem", d / "bigfix.key")
    return {p.stem + p.suffix.replace(".", "_"): p for p in d.iterdir()}


class TLSServer:
    """A threaded HTTPS server answering like the REST API's /api/query,
    /api/clientquery (query id 7) and /api/clientqueryresults (no rows yet).

    ``requests`` records (path, Authorization header) for every request that
    got past the TLS handshake, so tests can prove credentials never reached
    a server presenting the wrong certificate.
    """

    def __init__(self, certfile: Path, keyfile: Path) -> None:
        import http.server
        import ssl
        import threading

        self.requests: list[tuple[str, str | None]] = []
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                length = int(self.headers.get("content-length", 0))
                self.rfile.read(length)
                if self.path == "/api/clientquery":
                    self._answer(b"<BESAPI><ClientQuery><ID>7</ID></ClientQuery></BESAPI>")
                else:
                    self._answer(b'{"result":[1],"plural":false,"type":"integer","evaltime_ms":0}')

            def do_GET(self) -> None:
                self._answer(b'{"results":[]}')

            def _answer(self, body: bytes) -> None:
                outer.requests.append((self.path, self.headers.get("authorization")))
                self.send_response(200)
                self.send_header("content-length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, format: str, *args: Any) -> None:
                pass

        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile, keyfile)
        self.httpd.socket = ctx.wrap_socket(self.httpd.socket, server_side=True)
        self.port = self.httpd.server_address[1]
        self._thread = threading.Thread(
            target=self.httpd.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True
        )
        self._thread.start()

    def close(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()


@pytest.fixture
def tls_server(tls_certs: dict[str, Path]):  # type: ignore[no-untyped-def]
    """Factory: tls_server("self_a") -> a running TLSServer with that cert."""
    servers: list[TLSServer] = []

    def _start(name: str) -> TLSServer:
        server = TLSServer(tls_certs[f"{name}_pem"], tls_certs[f"{name}_key"])
        servers.append(server)
        return server

    yield _start
    for server in servers:
        server.close()
