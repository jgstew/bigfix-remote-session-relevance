"""Plain session relevance must normalize identically on every backend.

Each logical case is expressed in each backend's wire format; the
normalized result (answers, strings, type, plurality, error kind/message)
must be the same whichever backend answered.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import httpx
import pytest

from bigfix_remote_session_relevance.backends.explorer import ExplorerBackend
from bigfix_remote_session_relevance.backends.rest import RestBackend
from bigfix_remote_session_relevance.backends.webreports import WebReportsBackend

BF = "http://schemas.bigfix.com/Relevance"


def _wr_structured(results: str, plural: bool, type_: str) -> httpx.Response:
    return httpx.Response(
        200,
        headers={"content-type": "text/xml"},
        text=(
            '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">'
            f'<soapenv:Body><GetStructuredRelevanceResultResponse xmlns="{BF}">'
            f"<StructuredRelevanceResult><results>{results}</results>"
            f"<plural>{str(plural).lower()}</plural><type>{type_}</type>"
            "<evaltime>1</evaltime></StructuredRelevanceResult>"
            "</GetStructuredRelevanceResultResponse></soapenv:Body></soapenv:Envelope>"
        ),
    )


def _wr_fault(text: str) -> httpx.Response:
    return httpx.Response(
        500,
        headers={"content-type": "text/xml"},
        text=(
            '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">'
            "<soapenv:Body><soapenv:Fault><faultcode>soapenv:Server</faultcode>"
            f"<faultstring>{text}</faultstring></soapenv:Fault></soapenv:Body>"
            "</soapenv:Envelope>"
        ),
    )


def _json(values: Any, plural: bool, type_: str) -> httpx.Response:
    return httpx.Response(
        200, json={"result": values, "plural": plural, "type": type_, "evaltime_ms": 1}
    )


HTML = httpx.Response(
    200, text="<html><body>login</body></html>", headers={"content-type": "text/html"}
)
REFUSED = httpx.ConnectError("[Errno 61] Connection refused")

# case -> (json-backend response, web reports response)
CASES: dict[str, tuple[Any, Any]] = {
    "singular_integer": (
        _json([5], False, "integer"),
        _wr_structured("<Integer>5</Integer>", False, "integer"),
    ),
    "plural_strings": (
        _json(["a", "b"], True, "string"),
        _wr_structured("<String>a</String><String>b</String>", True, "string"),
    ),
    "empty_plural": (_json([], True, "integer"), _wr_structured("", True, "integer")),
    "boolean": (
        _json([True], False, "boolean"),
        _wr_structured("<Boolean>true</Boolean>", False, "boolean"),
    ),
    "plural_tuples": (
        _json([[1, "a"], [2, "b"]], True, "( integer, string )"),
        _wr_structured(
            "<Tuple><Integer>1</Integer><String>a</String></Tuple>"
            "<Tuple><Integer>2</Integer><String>b</String></Tuple>",
            True,
            "( integer, string )",
        ),
    ),
    # Web Reports sends qna-style escapes (lowercase hex); REST/Explorer send
    # the text itself. Values observed live on 11.0.7 (issue #5).
    "escaped_strings": (
        _json(["a%b", "a%41", "x\ny", "a\tb", "A\x7fB"], True, "string"),
        _wr_structured(
            "<String>a%25b</String><String>a%2541</String><String>x%0ay</String>"
            "<String>a%09b</String><String>A%7fB</String>",
            True,
            "string",
        ),
    ),
    "escaped_tuple": (
        _json([["a%b", 1]], False, "( string, integer )"),
        _wr_structured(
            "<Tuple><String>a%25b</String><Integer>1</Integer></Tuple>",
            False,
            "( string, integer )",
        ),
    ),
    # Error text is not escaped by Web Reports: it must come through as is.
    "error_with_percent": (
        httpx.Response(200, json={"error": "Error: User-defined error: a%b c"}),
        _wr_fault("User-defined error: a%b c"),
    ),
    "relevance_error": (
        httpx.Response(200, json={"error": 'Error: The operator "foo" is not defined.'}),
        _wr_fault('The operator "foo" is not defined.'),
    ),
    "bad_auth": (httpx.Response(401, text="Unauthorized"), _wr_fault("Login failed for user")),
    "refused": (REFUSED, REFUSED),
    "html_login_page": (HTML, HTML),
}

Factory = Callable[[httpx.AsyncBaseTransport], Any]
BACKENDS: dict[str, Factory] = {
    "rest": lambda t: RestBackend("h", username="u", password="p", transport=t),
    "explorer": lambda t: ExplorerBackend("h", username="u", password="p", transport=t),
    "webreports": lambda t: WebReportsBackend("h", username="u", password="p", transport=t),
}


def _normalized(result: Any) -> tuple[Any, ...]:
    err = result.error
    return (
        result.answers,
        result.answer_strings,
        result.type,
        result.plural,
        result.count,
        err.kind if err else None,
        err.message if err and err.kind in ("session_relevance", "authentication") else None,
    )


@pytest.mark.parametrize("case", sorted(CASES))
async def test_same_normalized_result_on_every_backend(
    case: str, recording_transport: type
) -> None:
    json_response, wr_response = CASES[case]
    seen = {}
    for name, factory in BACKENDS.items():
        response = wr_response if name == "webreports" else json_response
        rec = recording_transport([response])
        async with factory(rec.transport) as backend:
            result = await backend.evaluate("q")
        assert result.backend == name
        seen[name] = _normalized(result)
    assert seen["rest"] == seen["explorer"] == seen["webreports"], seen
