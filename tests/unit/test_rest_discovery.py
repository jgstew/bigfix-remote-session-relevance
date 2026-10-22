"""The root server's lists of registered Explorer and Web Reports servers.

Against ``tests/fixtures/rest/captured/discovery/`` (see tests/fixtures/README.md):
a master operator's 200s, pasted from the lab, and the 403 anyone else gets.
"""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

from bigfix_remote_session_relevance.backends.rest import RestBackend, parse_registered_urls

CAPTURED = Path(__file__).parent.parent / "fixtures" / "rest" / "captured" / "discovery"
# (observed) The lists are the same whether Explorer is reachable or not:
# they are what is registered, not what is up.
STATES = pytest.mark.parametrize("state", ["", "via_explorer__"], ids=["no_explorer", "explorer"])


def _captured(key: str) -> httpx.Response:
    meta = json.loads((CAPTURED / f"{key}.meta.json").read_text())
    headers = {"content-type": meta["content_type"]} if meta["content_type"] else {}
    return httpx.Response(
        meta["status"], text=(CAPTURED / f"{key}.body").read_text(), headers=headers
    )


@STATES
def test_parse_explorers_keeps_order_and_drops_the_repeated_entry(state: str) -> None:
    # (observed) The root server lists its own Explorer twice.
    urls = parse_registered_urls(_captured(f"{state}explorers"), "Explorer", "rest")
    assert urls == ["https://ROOTSERVER:9383", "https://bigfix.example.com:9383"]


@STATES
def test_parse_web_reports_keeps_the_http_scheme_and_port(state: str) -> None:
    urls = parse_registered_urls(_captured(f"{state}webreports"), "WebReports", "rest")
    assert urls == ["http://bigfix.example.com:888"]


def test_the_json_form_lists_the_same_explorers() -> None:
    # The XML is what is requested; this pins that it is not missing anything.
    data = json.loads((CAPTURED / "via_explorer__explorers_json.body").read_text())
    from_json = list(dict.fromkeys(e["url"] for e in data["explorers"]))
    assert from_json == parse_registered_urls(
        _captured("via_explorer__explorers"), "Explorer", "rest"
    )


@STATES
def test_parse_forbidden_is_a_permission_error(state: str) -> None:
    for key in (f"{state}explorers_403", f"{state}webreports_403"):
        error = parse_registered_urls(_captured(key), "Explorer", "rest")
        assert not isinstance(error, list)
        assert (error.kind, error.code, error.http_status) == (
            "authentication",
            "permission_denied",
            403,
        )
        assert "master operator" in error.message


def test_parse_garbled_xml_is_a_format_error() -> None:
    error = parse_registered_urls(
        httpx.Response(200, text="<BESAPI><Explorer>"), "Explorer", "rest"
    )
    assert not isinstance(error, list)
    assert error.kind == "response_format"


def test_parse_skips_entries_without_a_url() -> None:
    body = "<BESAPI><Explorer><URL> </URL></Explorer><Explorer/></BESAPI>"
    assert parse_registered_urls(httpx.Response(200, text=body), "Explorer", "rest") == []


@STATES
async def test_registered_servers_reads_both_lists_as_xml(state: str) -> None:
    seen: list[str] = []
    routes = {
        "/api/explorers": f"{state}explorers",
        "/api/webreports": f"{state}webreports",
    }

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(f"{request.method} {request.url.path}?{request.url.query.decode()}")
        assert request.headers["authorization"].startswith("Basic ")
        return _captured(routes[request.url.path])

    backend = RestBackend(
        "bf", username="op", password="pw", transport=httpx.MockTransport(handler)
    )
    async with backend:
        found = await backend.registered_servers()
    # No ?output=json: its Web Reports entries carry each server's token.
    assert seen == ["GET /api/explorers?", "GET /api/webreports?"]
    assert found == [
        ("explorer", "https://ROOTSERVER:9383"),
        ("explorer", "https://bigfix.example.com:9383"),
        ("webreports", "http://bigfix.example.com:888"),
    ]


@STATES
async def test_registered_servers_forbidden_is_an_error_not_a_raise(state: str) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return _captured(f"{state}explorers_403")

    backend = RestBackend(
        "bf", username="op", password="pw", transport=httpx.MockTransport(handler)
    )
    async with backend:
        found = await backend.registered_servers()
    assert not isinstance(found, list)
    assert found.code == "permission_denied"


async def test_registered_servers_maps_a_connection_failure() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused")

    backend = RestBackend(
        "bf", username="op", password="pw", transport=httpx.MockTransport(handler)
    )
    async with backend:
        found = await backend.registered_servers()
    assert not isinstance(found, list)
    assert found.kind == "connection"


def test_parse_ignores_layout_whitespace() -> None:
    # The 200 captures were pasted from a browser, so their whitespace is not
    # the wire's. This is the root server's usual layout (see clientquery/).
    body = (
        '<?xml version="1.0" encoding="UTF-8"?>\r\n'
        '<BESAPI xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" '
        'xsi:noNamespaceSchemaLocation="BESAPI.xsd">\r\n'
        '\t<Explorer Resource="https://192.0.2.1:52311/api/explorer/localhost">\r\n'
        "\t\t<URL>\r\n\t\t\thttps://ROOTSERVER:9383\r\n\t\t</URL>\r\n"
        "\t</Explorer>\r\n"
        "</BESAPI>\r\n"
    )
    response = httpx.Response(200, text=body, headers={"content-type": "application/xml"})
    assert parse_registered_urls(response, "Explorer", "rest") == ["https://ROOTSERVER:9383"]


async def test_registered_servers_keeps_a_list_when_the_other_fails() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/webreports":
            return httpx.Response(500, text="boom")
        return _captured("explorers")

    backend = RestBackend(
        "bf", username="op", password="pw", transport=httpx.MockTransport(handler)
    )
    async with backend:
        found = await backend.registered_servers()
    assert found == [
        ("explorer", "https://ROOTSERVER:9383"),
        ("explorer", "https://bigfix.example.com:9383"),
    ]
