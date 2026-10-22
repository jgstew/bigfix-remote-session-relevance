"""The root server's lists of registered Explorer and Web Reports servers.

Against ``tests/fixtures/rest/captured/discovery/`` (see tests/fixtures/README.md):
a master operator's 200s, pasted from the lab, and the 403 anyone else gets.
"""

from __future__ import annotations

import json
from pathlib import Path

import httpx

from bigfix_remote_session_relevance.backends.rest import RestBackend, parse_registered_urls

CAPTURED = Path(__file__).parent.parent / "fixtures" / "rest" / "captured" / "discovery"


def _captured(key: str) -> httpx.Response:
    meta = json.loads((CAPTURED / f"{key}.meta.json").read_text())
    headers = {"content-type": meta["content_type"]} if meta["content_type"] else {}
    return httpx.Response(
        meta["status"], text=(CAPTURED / f"{key}.body").read_text(), headers=headers
    )


def test_parse_explorers_keeps_order_and_drops_the_repeated_entry() -> None:
    # (observed) The root server lists its own Explorer twice.
    urls = parse_registered_urls(_captured("via_explorer__explorers"), "Explorer", "rest")
    assert urls == ["https://ROOTSERVER:9383", "https://bigfix.example.com:9383"]


def test_parse_web_reports_keeps_the_http_scheme_and_port() -> None:
    urls = parse_registered_urls(_captured("via_explorer__webreports"), "WebReports", "rest")
    assert urls == ["http://bigfix.example.com:888"]


def test_the_json_form_lists_the_same_explorers() -> None:
    # The XML is what is requested; this pins that it is not missing anything.
    data = json.loads((CAPTURED / "via_explorer__explorers_json.body").read_text())
    from_json = list(dict.fromkeys(e["url"] for e in data["explorers"]))
    assert from_json == parse_registered_urls(
        _captured("via_explorer__explorers"), "Explorer", "rest"
    )


def test_parse_forbidden_is_a_permission_error() -> None:
    for key in ("via_explorer__explorers_403", "via_explorer__webreports_403"):
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


async def test_registered_servers_reads_both_lists_as_xml() -> None:
    seen: list[str] = []
    routes = {
        "/api/explorers": "via_explorer__explorers",
        "/api/webreports": "via_explorer__webreports",
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


async def test_registered_servers_forbidden_is_an_error_not_a_raise() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return _captured("via_explorer__explorers_403")

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
