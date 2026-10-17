from __future__ import annotations

import logging
from pathlib import Path

import defusedxml.ElementTree as SafeET
import httpx
import pytest

from bigfix_remote_session_relevance.backends.webreports import WebReportsBackend

NS = "{http://schemas.bigfix.com/Relevance}"


def _soap(body: str, token: str | None = "TOKEN-1") -> str:
    header = (
        '<soapenv:Header><bf:ResponseHeaderElement xmlns:bf="http://schemas.bigfix.com/Relevance">'
        f"<bf:sessionToken>{token}</bf:sessionToken></bf:ResponseHeaderElement></soapenv:Header>"
        if token
        else ""
    )
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">'
        f"{header}<soapenv:Body>{body}</soapenv:Body></soapenv:Envelope>"
    )


def _structured(
    results: str,
    plural: str = "true",
    type_: str = "string",
    evaltime: str = "3",
    token: str | None = "TOKEN-1",
) -> str:
    return _soap(
        '<GetStructuredRelevanceResultResponse xmlns="http://schemas.bigfix.com/Relevance">'
        f"<StructuredRelevanceResult><results>{results}</results><plural>{plural}</plural>"
        f"<type>{type_}</type><evaltime>{evaltime}</evaltime></StructuredRelevanceResult>"
        "</GetStructuredRelevanceResultResponse>",
        token=token,
    )


def _fault(text: str) -> str:
    return _soap(
        f"<soapenv:Fault><faultcode>soapenv:Server</faultcode><faultstring>{text}</faultstring>"
        "</soapenv:Fault>",
        token=None,
    )


def _xml(text: str, status: int = 200) -> httpx.Response:
    return httpx.Response(status, text=text, headers={"content-type": "text/xml; charset=utf-8"})


def _backend(rec: object, server: str = "wr.example.com") -> WebReportsBackend:
    return WebReportsBackend(server, username="wr<user>", password="p&w", transport=rec.transport)  # type: ignore[attr-defined]


async def test_login_request_shape(recording_transport: type, fixtures_dir: Path) -> None:
    body = (fixtures_dir / "webreports" / "doc_structured_integers.xml").read_text()
    rec = recording_transport([_xml(body)])
    async with _backend(rec) as backend:
        await backend.evaluate('names of bes computers whose (name of it contains "<&>")')
    req = rec.requests[0]
    assert str(req.url) == "https://wr.example.com/webreports/soap"
    assert req.headers["content-type"].startswith("text/xml")
    root = SafeET.fromstring(req.content)
    header = root.find(f".//{NS}RequestHeaderElement")
    assert header is not None
    assert header.get("{http://www.w3.org/2001/XMLSchema-instance}type") == "LoginHeader"
    assert header.findtext(f"{NS}username") == "wr<user>"
    assert header.findtext(f"{NS}password") == "p&w"
    assert root.findtext(f".//{NS}GetStructuredRelevanceResult/{NS}relevanceExpr") == (
        'names of bes computers whose (name of it contains "<&>")'
    )


async def test_doc_structured_integers(recording_transport: type, fixtures_dir: Path) -> None:
    body = (fixtures_dir / "webreports" / "doc_structured_integers.xml").read_text()
    rec = recording_transport([_xml(body)])
    async with _backend(rec) as backend:
        result = await backend.evaluate("ids of bes computers")
    assert result.ok
    assert result.answers == (10697214, 14519782)
    assert result.plural is True
    assert result.type == "integer"
    assert result.evaluation_time_ms == 24
    assert result.backend == "webreports"
    assert result.raw is not None
    assert result.raw.format == "xml"


async def test_session_token_is_reused(recording_transport: type) -> None:
    rec = recording_transport(
        [
            _xml(_structured("<String>a</String>", token="TOKEN-1")),
            _xml(_structured("<String>b</String>", token="TOKEN-1")),
        ]
    )
    async with _backend(rec) as backend:
        await backend.evaluate("1")
        await backend.evaluate("2")
    second = SafeET.fromstring(rec.requests[1].content)
    header = second.find(f".//{NS}RequestHeaderElement")
    assert header is not None
    # The WSDL's type is AuthenticateHeader; developer.bigfix.com says
    # "AuthenticationHeader", which the server rejects ("cannot be resolved").
    assert header.get("{http://www.w3.org/2001/XMLSchema-instance}type") == "AuthenticateHeader"
    assert header.findtext(f"{NS}sessionToken") == "TOKEN-1"
    assert header.find(f"{NS}password") is None


async def test_rejected_token_logs_in_again_once(recording_transport: type) -> None:
    rec = recording_transport(
        [
            _xml(_structured("<String>a</String>", token="TOKEN-1")),
            _xml(_fault("Invalid session token"), status=500),
            _xml(_structured("<String>b</String>", token="TOKEN-2")),
        ]
    )
    async with _backend(rec) as backend:
        await backend.evaluate("1")
        result = await backend.evaluate("2")
    assert result.ok
    assert result.answers == ("b",)
    third = SafeET.fromstring(rec.requests[2].content)
    header = third.find(f".//{NS}RequestHeaderElement")
    assert header is not None
    assert header.get("{http://www.w3.org/2001/XMLSchema-instance}type") == "LoginHeader"


async def test_tuples(recording_transport: type) -> None:
    results = (
        "<Tuple><Integer>1</Integer><String>a</String></Tuple>"
        "<Tuple><Integer>2</Integer><String>b</String></Tuple>"
    )
    rec = recording_transport([_xml(_structured(results, type_="( integer, string )"))])
    async with _backend(rec) as backend:
        result = await backend.evaluate("q")
    assert result.answers == ((1, "a"), (2, "b"))


async def test_empty_and_singular(recording_transport: type) -> None:
    rec = recording_transport(
        [
            _xml(_structured("", plural="true", type_="integer")),
            _xml(_structured("<Boolean>true</Boolean>", plural="false", type_="boolean")),
        ]
    )
    async with _backend(rec) as backend:
        empty = await backend.evaluate("q")
        single = await backend.evaluate("true")
    assert empty.ok
    assert empty.answers == ()
    assert empty.plural is True
    assert single.answers == (True,)
    assert single.plural is False


async def test_relevance_fault(recording_transport: type) -> None:
    rec = recording_transport([_xml(_fault('The operator "foo" is not defined.'), status=500)])
    async with _backend(rec) as backend:
        result = await backend.evaluate("foo")
    assert result.error is not None
    assert result.error.kind == "relevance"
    assert result.error.message == 'The operator "foo" is not defined.'


async def test_login_fault_is_authentication(recording_transport: type) -> None:
    rec = recording_transport(
        [_xml(_fault("Login failed: invalid username or password"), status=500)]
    )
    async with _backend(rec) as backend:
        result = await backend.evaluate("1")
    assert result.error is not None
    assert result.error.kind == "authentication"


PLAIN_RESPONSE = _soap(
    '<GetRelevanceResultResponse xmlns="http://schemas.bigfix.com/Relevance">'
    "<a>alpha</a><a>beta</a></GetRelevanceResultResponse>",
    token=None,
)


async def test_falls_back_to_plain_method_when_structured_unsupported(
    recording_transport: type,
) -> None:
    rec = recording_transport(
        [
            _xml(_fault("No such operation 'GetStructuredRelevanceResult'"), status=500),
            _xml(PLAIN_RESPONSE),
            _xml(PLAIN_RESPONSE),
        ]
    )
    async with _backend(rec) as backend:
        result = await backend.evaluate('("alpha";"beta")')
        await backend.evaluate('("alpha";"beta")')
    assert result.ok
    assert result.answers == ("alpha", "beta")
    assert result.type is None
    assert result.plural is True
    plain = SafeET.fromstring(rec.requests[1].content)
    assert plain.find(f".//{NS}GetRelevanceResult/{NS}username") is not None
    # Remembered: the third request goes straight to the plain method.
    assert SafeET.fromstring(rec.requests[2].content).find(f".//{NS}GetRelevanceResult") is not None


@pytest.mark.parametrize(
    ("answers", "plural"), [("", True), ("<a>x</a>", False), ("<a>x</a><a>y</a>", True)]
)
async def test_plain_method_plurality_rule(
    recording_transport: type, answers: str, plural: bool
) -> None:
    body = _soap(
        '<GetRelevanceResultResponse xmlns="http://schemas.bigfix.com/Relevance">'
        f"{answers}</GetRelevanceResultResponse>",
        token=None,
    )
    rec = recording_transport([_xml(body)])
    async with WebReportsBackend(
        "wr", username="u", password="p", transport=rec.transport, soap_method="plain"
    ) as backend:
        result = await backend.evaluate("q")
    assert result.plural is plural


async def test_non_xml_response_is_response_format(recording_transport: type) -> None:
    rec = recording_transport(
        [httpx.Response(200, text="<html>login</html>", headers={"content-type": "text/html"})]
    )
    async with _backend(rec) as backend:
        result = await backend.evaluate("1")
    assert result.error is not None
    assert result.error.kind == "response_format"


async def test_http_warns_cleartext(
    recording_transport: type, caplog: pytest.LogCaptureFixture
) -> None:
    rec = recording_transport([_xml(_structured("<String>a</String>"))])
    with caplog.at_level(logging.WARNING):
        async with _backend(rec, server="http://wr.example.com:888") as backend:
            result = await backend.evaluate("1")
    assert result.server == "http://wr.example.com:888"
    assert "cleartext" in caplog.text
    assert "p&w" not in caplog.text


async def test_any_fault_on_the_token_path_logs_in_again(recording_transport: type) -> None:
    rec = recording_transport(
        [
            _xml(_structured("<String>a</String>", token="TOKEN-1")),
            _xml(_fault("parsing error: type 'X' specified in 'xsi:type' cannot be resolved")),
            _xml(_structured("<String>b</String>", token="TOKEN-2")),
        ]
    )
    async with _backend(rec) as backend:
        await backend.evaluate("1")
        result = await backend.evaluate("2")
    assert result.answers == ("b",)
    assert len(rec.requests) == 3
