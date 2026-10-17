from __future__ import annotations

import json
import urllib.parse
from pathlib import Path

import httpx
import pytest

from bigfix_remote_session_relevance.backends.rest import RestBackend


def _backend(rec: object) -> RestBackend:
    return RestBackend("bigfix.example.com", username="op", password="pw", transport=rec.transport)  # type: ignore[attr-defined]


REL = 'names of bes computers whose (name of it = "a+b %22")'
NO_EXPLORER = httpx.Response(
    503,
    text=(
        "Cannot perform relevance query evaluation at this time because there is no "
        "reachable BigFix Explorer instance collecting data from this Server."
    ),
    headers={"content-type": "text/plain; charset=UTF-8"},
)


async def test_request_shape_prefers_json_relevance(recording_transport: type) -> None:
    # A JSON body is exact: no URL decoding to get wrong. The root server
    # evaluates it through Explorer when one is reachable.
    rec = recording_transport([httpx.Response(200, json={"result": [], "plural": True})])
    async with _backend(rec) as backend:
        await backend.evaluate(REL)
    (req,) = rec.requests
    assert req.method == "POST"
    assert str(req.url) == "https://bigfix.example.com:52311/api/query"
    assert req.headers["content-type"] == "application/json+relevance"
    assert json.loads(req.content) == {"relevance": REL}


async def test_falls_back_to_double_quoted_form_without_explorer(
    recording_transport: type,
) -> None:
    ok = httpx.Response(200, json={"result": [1], "plural": False, "type": "integer"})
    rec = recording_transport([NO_EXPLORER, ok, ok])
    async with _backend(rec) as backend:
        first = await backend.evaluate(REL)
        await backend.evaluate(REL)
    assert first.ok
    assert first.answers == (1,)
    # Without Explorer the server URL-decodes the form value twice (besapi),
    # so the relevance is percent-quoted before being form-encoded.
    form = urllib.parse.parse_qs(rec.requests[1].content.decode())
    assert form["output"] == ["json"]
    assert form["relevance"] == [urllib.parse.quote(REL, safe=":+")]
    # Remembered: the next query goes straight to the form, no extra 503.
    assert [r.headers["content-type"] for r in rec.requests] == [
        "application/json+relevance",
        "application/x-www-form-urlencoded",
        "application/x-www-form-urlencoded",
    ]


async def test_retries_json_relevance_after_the_fallback_expires(
    recording_transport: type, monkeypatch: pytest.MonkeyPatch
) -> None:
    from bigfix_remote_session_relevance.backends import rest

    now = [1000.0]
    monkeypatch.setattr(rest.time, "monotonic", lambda: now[0])
    ok = httpx.Response(200, json={"result": [1], "plural": False, "type": "integer"})
    rec = recording_transport([NO_EXPLORER, ok, ok])
    async with _backend(rec) as backend:
        await backend.evaluate("1")
        now[0] += rest.EXPLORER_RECHECK_SECONDS + 1
        await backend.evaluate("1")
    assert rec.requests[2].headers["content-type"] == "application/json+relevance"


async def test_other_503_is_not_a_fallback(recording_transport: type) -> None:
    rec = recording_transport([httpx.Response(503, text="maintenance")])
    async with _backend(rec) as backend:
        result = await backend.evaluate("1")
    assert result.error is not None
    assert result.error.http_status == 503
    assert len(rec.requests) == 1


async def test_doc_plural_strings(recording_transport: type, fixtures_dir: Path) -> None:
    body = (fixtures_dir / "rest" / "doc_plural_strings.json").read_text()
    rec = recording_transport(
        [httpx.Response(200, text=body, headers={"content-type": "application/json"})]
    )
    async with _backend(rec) as backend:
        result = await backend.evaluate("names of bes computers")
    assert result.ok
    assert result.answers == ("computerA", "computerB", "computerC")
    assert result.plural is True
    assert result.type == "string"
    assert result.evaluation_time_ms == pytest.approx(1.347)
    assert result.raw is not None
    assert result.raw.format == "json"
    assert result.raw_json()["count"] == 3


async def test_tuples_and_types(recording_transport: type) -> None:
    payload = {
        "result": [[1, "a", True], [2, "b", False]],
        "count": 2,
        "plural": True,
        "type": "( integer, string, boolean )",
        "evaltime_ms": 0.2,
    }
    rec = recording_transport([httpx.Response(200, json=payload)])
    async with _backend(rec) as backend:
        result = await backend.evaluate("q")
    assert result.answers == ((1, "a", True), (2, "b", False))
    assert result.answer_strings == ("1, a, True", "2, b, False")


async def test_singular_scalar_result(recording_transport: type) -> None:
    rec = recording_transport(
        [httpx.Response(200, json={"result": 7, "plural": False, "type": "integer"})]
    )
    async with _backend(rec) as backend:
        result = await backend.evaluate("q")
    assert result.answers == (7,)
    assert result.plural is False


async def test_json_relevance_error(recording_transport: type) -> None:
    # Assumed shape until a real capture replaces it (see tests/fixtures/README.md).
    rec = recording_transport(
        [httpx.Response(200, json={"error": 'Error: The operator "foo" is not defined.'})]
    )
    async with _backend(rec) as backend:
        result = await backend.evaluate("foo")
    assert result.error is not None
    assert result.error.kind == "relevance"
    assert result.error.message == 'The operator "foo" is not defined.'
    assert result.error.detail == 'Error: The operator "foo" is not defined.'
    assert result.answers == ()


BESAPI_XML_OK = """<?xml version="1.0" encoding="UTF-8"?>
<BESAPI xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <Query Resource="q">
    <Result>
      <Tuple><Answer type="integer">1</Answer><Answer type="string">a</Answer></Tuple>
      <Tuple><Answer type="integer">2</Answer><Answer type="string">b</Answer></Tuple>
    </Result>
    <Evaluation><Time>0.31ms</Time><Plurality>Plural</Plurality></Evaluation>
  </Query>
</BESAPI>"""

BESAPI_XML_ERROR = """<?xml version="1.0" encoding="UTF-8"?>
<BESAPI><Query Resource="foo"><Result/><Error>The operator "foo" is not defined.</Error>
</Query></BESAPI>"""


async def test_xml_fallback_when_server_ignores_output_json(recording_transport: type) -> None:
    rec = recording_transport(
        [httpx.Response(200, text=BESAPI_XML_OK, headers={"content-type": "application/xml"})]
    )
    async with _backend(rec) as backend:
        result = await backend.evaluate("q")
    assert result.ok
    assert result.answers == ((1, "a"), (2, "b"))
    assert result.type == "( integer, string )"
    assert result.plural is True
    assert result.evaluation_time_ms == pytest.approx(0.31)
    assert result.raw is not None
    assert result.raw.format == "xml"


async def test_xml_relevance_error(recording_transport: type) -> None:
    rec = recording_transport([httpx.Response(200, text=BESAPI_XML_ERROR)])
    async with _backend(rec) as backend:
        result = await backend.evaluate("foo")
    assert result.error is not None
    assert result.error.kind == "relevance"
    assert result.error.message == 'The operator "foo" is not defined.'


@pytest.mark.parametrize("status", [401, 403])
async def test_auth_failure(recording_transport: type, status: int) -> None:
    rec = recording_transport([httpx.Response(status, text="Login failed")])
    async with _backend(rec) as backend:
        result = await backend.evaluate("1")
    assert result.error is not None
    assert result.error.kind == "authentication"
    assert result.error.http_status == status


async def test_html_login_page_is_response_format(recording_transport: type) -> None:
    rec = recording_transport(
        [
            httpx.Response(
                200,
                text="<html><body>Please log in</body></html>",
                headers={"content-type": "text/html"},
            )
        ]
    )
    async with _backend(rec) as backend:
        result = await backend.evaluate("1")
    assert result.error is not None
    assert result.error.kind == "response_format"


async def test_server_error_is_http(recording_transport: type) -> None:
    rec = recording_transport([httpx.Response(500, text="boom")])
    async with _backend(rec) as backend:
        result = await backend.evaluate("1")
    assert result.error is not None
    assert result.error.kind == "http"
    assert result.error.http_status == 500


async def test_plain_text_error_with_400_is_relevance(recording_transport: type) -> None:
    rec = recording_transport(
        [
            httpx.Response(
                400,
                text='Error: The operator "foo" is not defined.',
                headers={"content-type": "text/plain"},
            )
        ]
    )
    async with _backend(rec) as backend:
        result = await backend.evaluate("foo")
    assert result.error is not None
    assert result.error.kind == "relevance"
    assert result.error.http_status == 400


async def test_unknown_json_shape_is_response_format(recording_transport: type) -> None:
    rec = recording_transport([httpx.Response(200, text=json.dumps({"surprise": 1}))])
    async with _backend(rec) as backend:
        result = await backend.evaluate("1")
    assert result.error is not None
    assert result.error.kind == "response_format"


DISALLOWED = httpx.Response(
    200,
    json={"result": [], "error": "This expression contained a character which is not allowed."},
)


async def test_explorer_returning_during_fallback_is_detected(recording_transport: type) -> None:
    # Fallback active, then Explorer comes back: the double-quoted form now
    # fails every query with "character which is not allowed". One retry over
    # JSON gets the real answer and ends the fallback.
    ok = httpx.Response(200, json={"result": [7], "plural": False, "type": "integer"})
    rec = recording_transport([NO_EXPLORER, ok, DISALLOWED, ok, ok])
    async with _backend(rec) as backend:
        await backend.evaluate("1")  # JSON 503 -> form: fallback starts
        result = await backend.evaluate("7")  # form fails -> JSON retry succeeds
        await backend.evaluate("7")  # back on JSON
    assert result.ok
    assert result.answers == (7,)
    assert [r.headers["content-type"] for r in rec.requests] == [
        "application/json+relevance",
        "application/x-www-form-urlencoded",
        "application/x-www-form-urlencoded",
        "application/json+relevance",
        "application/json+relevance",
    ]


async def test_genuine_disallowed_character_error_is_kept(recording_transport: type) -> None:
    # "1.5" really is "not allowed" in relevance; Explorer still being down
    # (503 on the retry) proves the form answer was genuine.
    ok = httpx.Response(200, json={"result": [1], "plural": False, "type": "integer"})
    rec = recording_transport([NO_EXPLORER, ok, DISALLOWED, NO_EXPLORER, ok])
    async with _backend(rec) as backend:
        await backend.evaluate("1")
        result = await backend.evaluate("1.5")
        await backend.evaluate("1")
    assert result.error is not None
    assert result.error.kind == "relevance"
    assert result.error.message == "This expression contained a character which is not allowed."
    # Fallback still active afterwards: the last query went straight to the form.
    assert rec.requests[-1].headers["content-type"] == "application/x-www-form-urlencoded"
