from __future__ import annotations

import pytest

from bigfix_remote_session_relevance.exceptions import ConfigError
from bigfix_remote_session_relevance.server_address import DEFAULT_PORTS, normalize_server


def test_default_ports() -> None:
    assert DEFAULT_PORTS == {"rest": 52311, "explorer": 9383, "webreports": 443, "saas": 443}


@pytest.mark.parametrize(
    ("server", "backend", "scheme", "host", "port", "base_url"),
    [
        (
            "bigfix.example.com",
            "rest",
            "https",
            "bigfix.example.com",
            52311,
            "https://bigfix.example.com:52311",
        ),
        (
            "bigfix.example.com",
            "explorer",
            "https",
            "bigfix.example.com",
            9383,
            "https://bigfix.example.com:9383",
        ),
        ("wr.example.com", "webreports", "https", "wr.example.com", 443, "https://wr.example.com"),
        (
            "wr.example.com:8083",
            "webreports",
            "https",
            "wr.example.com",
            8083,
            "https://wr.example.com:8083",
        ),
        (
            "https://bigfix.example.com:52311/api",
            "rest",
            "https",
            "bigfix.example.com",
            52311,
            "https://bigfix.example.com:52311",
        ),
        (
            "https://bigfix.example.com/",
            "rest",
            "https",
            "bigfix.example.com",
            52311,
            "https://bigfix.example.com:52311",
        ),
        ("10.0.0.5", "rest", "https", "10.0.0.5", 52311, "https://10.0.0.5:52311"),
        ("[::1]", "rest", "https", "::1", 52311, "https://[::1]:52311"),
        ("[::1]:8443", "explorer", "https", "::1", 8443, "https://[::1]:8443"),
        (
            "HTTPS://BigFix.Example.com",
            "rest",
            "https",
            "bigfix.example.com",
            52311,
            "https://bigfix.example.com:52311",
        ),
        (
            "  bigfix.example.com  ",
            "rest",
            "https",
            "bigfix.example.com",
            52311,
            "https://bigfix.example.com:52311",
        ),
    ],
)
def test_normalize(
    server: str, backend: str, scheme: str, host: str, port: int, base_url: str
) -> None:
    addr = normalize_server(server, backend)
    assert (addr.scheme, addr.host, addr.port, addr.base_url) == (scheme, host, port, base_url)


def test_host_port_key_brackets_ipv6() -> None:
    assert normalize_server("[::1]", "rest").host_port == "[::1]:52311"
    assert normalize_server("h", "rest").host_port == "h:52311"


def test_explicit_http_is_kept() -> None:
    addr = normalize_server("http://wr.example.com", "webreports")
    assert addr.scheme == "http"
    assert addr.port == 80
    assert addr.base_url == "http://wr.example.com"
    assert normalize_server("http://wr.example.com:888", "webreports").port == 888


@pytest.mark.parametrize(
    "bad",
    [
        "ftp://h",
        "https://h/some/path",
        "",
        "   ",
        "https://",
        "h:notaport",
        "h:0",
        "h:70000",
        "https://user:pw@h",
    ],
)
def test_rejects_bad_servers(bad: str) -> None:
    with pytest.raises(ConfigError):
        normalize_server(bad, "rest")


def test_rejects_unknown_backend() -> None:
    with pytest.raises(ConfigError, match="backend"):
        normalize_server("h", "nope")
