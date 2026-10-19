"""Parsers against real (redacted) server responses.

Captured from a BigFix 11 deployment with scripts/capture_fixtures.py; see
tests/fixtures/README.md. These, not the docs, are the ground truth.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import httpx
import pytest

from bigfix_remote_session_relevance import escape_result
from bigfix_remote_session_relevance.backends.explorer import ExplorerBackend
from bigfix_remote_session_relevance.backends.rest import RestBackend
from bigfix_remote_session_relevance.backends.webreports import WebReportsBackend

FIXTURES = Path(__file__).parent.parent / "fixtures"
# sha256 of the redacted gather URL http://bigfix.example.com:52311/cgi-bin/bfgather.exe/actionsite
DEPLOYMENT_HASH = "ad1f835d1cc04dd58a71894a39e802e4a08b0f4b141364767acce3d36e1d7291"
BIGFIX_TIME_RE = re.compile(
    r"^[A-Z][a-z]{2}, \d{2} [A-Z][a-z]{2} \d{4} \d{2}:\d{2}:\d{2} [+-]\d{4}$"
)


def _response(backend: str, key: str) -> httpx.Response:
    base = FIXTURES / backend / "captured"
    meta = json.loads((base / f"{key}.meta.json").read_text())
    headers = {"content-type": meta["content_type"]} if meta["content_type"] else {}
    return httpx.Response(meta["status"], text=(base / f"{key}.body").read_text(), headers=headers)


async def _evaluate(backend: str, key: str, recording_transport: type, **kw: Any) -> Any:
    rec = recording_transport([_response(backend, key)])
    cls = {"rest": RestBackend, "webreports": WebReportsBackend, "explorer": ExplorerBackend}[
        backend
    ]
    async with cls("h", username="u", password="p", transport=rec.transport, **kw) as b:
        return await b.evaluate("q")


# (backend, file prefix): the same probe queries captured four ways. REST
# answers differently with and without a reachable Explorer (see rest.py), so
# both REST paths are kept.
SOURCES = [("rest", ""), ("rest", "via_explorer__"), ("webreports", ""), ("explorer", "")]
SOURCE_IDS = ["rest", "rest-via-explorer", "webreports", "explorer"]


async def _from_source(source: tuple[str, str], key: str, recording_transport: type) -> Any:
    backend, prefix = source
    return await _evaluate(backend, prefix + key, recording_transport)


# key -> (answers, type, plural)
SUCCESS = {
    "plural_integers": ((1, 2, 3), "integer", True),
    "plural_strings": (("alpha", "beta"), "string", True),
    "empty_plural": ((), "integer", True),
    "singular_string": (("hello",), "string", False),
    "boolean": ((True,), "boolean", False),
    "tuple": (((1, "a", True),), "( integer, string, boolean )", False),
    "plural_tuples": (((1, "a"), (2, "b")), "( integer, string )", True),
    "nested_tuple": (((1, (2, "x")),), "( integer, ( integer, string ) )", False),
}

# Types beyond integer/string/boolean/time, on all four sources (11.0.7,
# 2026-10-19). Web Reports sends floating points as <FloatingPoint> and every
# other type here as <String>; the REST API (with or without Explorer) and
# Explorer send floating points as JSON numbers whose text is the same as
# Web Reports'. Only integer and boolean become Python numbers.
TYPED = {
    "floating_point": (("1.5",), "floating point", False),
    "floating_point_plural": (("1.5", "-2.25", "3.0"), "floating point", True),
    "floating_point_small": (("0.000001234",), "floating point", False),
    "floating_point_large": (("1.0e+300",), "floating point", False),
    "date": (("Sat, 17 Oct 2026",), "date", False),
    "time_of_day": (("13:45:00",), "time of day", False),
    "time_interval": (("01:30:00",), "time interval", False),
    "version": (("11.0.7",), "version", False),
    "date_parts": (
        (("Saturday", "October", "2026", "17", "October 2026"),),
        "( day of week, month, year, day of month, month and year )",
        False,
    ),
    "big_integer": ((9223372036854775807,), "integer", False),
    "negative_integer": ((-5,), "integer", False),
    "empty_string": (("",), "string", False),
    "tuple_mixed": (
        (("Sat, 17 Oct 2026", "1.5", "1.2"),),
        "( date, floating point, version )",
        False,
    ),
}


@pytest.mark.parametrize("source", SOURCES, ids=SOURCE_IDS)
@pytest.mark.parametrize("key", sorted(TYPED))
async def test_typed_cases(source: tuple[str, str], key: str, recording_transport: type) -> None:
    result = await _from_source(source, key, recording_transport)
    answers, type_, plural = TYPED[key]
    assert result.ok, result.error
    assert (result.answers, result.type, result.plural) == (answers, type_, plural)
    assert result.answer_strings == tuple(
        ", ".join(str(v) for v in a) if isinstance(a, tuple) else str(a) for a in answers
    )


ERRORS = {
    "error_unknown": 'The operator "foo bar baz" is not defined.',
    "error_type": 'The operator "plus" is not defined.',
    "float": "This expression contained a character which is not allowed.",
}


@pytest.mark.parametrize("source", SOURCES, ids=SOURCE_IDS)
@pytest.mark.parametrize("key", sorted(SUCCESS))
async def test_success_cases(source: tuple[str, str], key: str, recording_transport: type) -> None:
    result = await _from_source(source, key, recording_transport)
    answers, type_, plural = SUCCESS[key]
    assert result.ok, result.error
    assert (result.answers, result.type, result.plural) == (answers, type_, plural)


@pytest.mark.parametrize("source", SOURCES, ids=SOURCE_IDS)
@pytest.mark.parametrize("key", sorted(ERRORS))
async def test_relevance_errors(
    source: tuple[str, str], key: str, recording_transport: type
) -> None:
    # The REST API sends {"result": [], "error": "..."} with HTTP 200: the
    # empty result must not be mistaken for an empty success.
    result = await _from_source(source, key, recording_transport)
    assert result.error is not None
    assert result.error.kind == "session_relevance"
    assert result.error.message == ERRORS[key]
    assert result.answers == ()
    assert result.plural is None


@pytest.mark.parametrize("source", SOURCES, ids=SOURCE_IDS)
async def test_time_is_bigfix_format_on_every_backend(
    source: tuple[str, str], recording_transport: type
) -> None:
    # Web Reports structured results send <DateTime>2026-10-17T17:09:32-04:00</DateTime>;
    # it is normalized to the BigFix format the REST API returns.
    result = await _from_source(source, "time", recording_transport)
    assert result.type == "time"
    (value,) = result.answers
    assert BIGFIX_TIME_RE.match(value), value


@pytest.mark.parametrize("source", SOURCES, ids=SOURCE_IDS)
async def test_deployment_id_query(source: tuple[str, str], recording_transport: type) -> None:
    result = await _from_source(source, "deployment_id", recording_transport)
    assert result.answers == (DEPLOYMENT_HASH,)


async def test_singular_integer(recording_transport: type) -> None:
    for source in SOURCES:
        result = await _from_source(source, "singular_integer", recording_transport)
        assert result.type == "integer"
        assert result.plural is False
        assert isinstance(result.answers[0], int)


async def test_rest_xml_output(recording_transport: type) -> None:
    result = await _evaluate("rest", "plural_tuples__xml", recording_transport)
    assert result.answers == ((1, "a"), (2, "b"))
    assert result.type == "( integer, string )"
    assert result.plural is True
    assert result.evaluation_time_ms == pytest.approx(0.46)


async def test_webreports_bad_password(recording_transport: type) -> None:
    result = await _evaluate("webreports", "bad_password", recording_transport)
    assert result.error is not None
    assert result.error.kind == "authentication"
    assert result.error.message == "credentials rejected"


@pytest.mark.parametrize(
    ("key", "answers", "plural"),
    [
        ("plural_strings__plain", ("alpha", "beta"), True),
        ("boolean__plain", ("True",), False),
        ("tuple__plain", ("1, a, True",), False),
    ],
)
async def test_webreports_plain_method(
    key: str, answers: tuple[str, ...], plural: bool, recording_transport: type
) -> None:
    result = await _evaluate("webreports", key, recording_transport, soap_method="plain")
    assert (result.answers, result.plural, result.type) == (answers, plural, None)


async def test_webreports_plain_method_error(recording_transport: type) -> None:
    result = await _evaluate(
        "webreports", "error_unknown__plain", recording_transport, soap_method="plain"
    )
    assert result.error is not None
    assert result.error.kind == "session_relevance"
    assert result.error.message == 'The operator "foo bar baz" is not defined.'


async def test_explorer_unavailable_401_is_not_an_auth_failure(recording_transport: type) -> None:
    # Explorer answers 401 with {"error": "This API is temporarily unavailable
    # while the connection to the Root Server is being re-established."}
    result = await _evaluate("explorer", "unavailable_401", recording_transport)
    assert result.error is not None
    assert result.error.kind == "http"
    assert result.error.code == "service_unavailable"
    assert result.error.http_status == 401
    assert "temporarily unavailable" in result.error.message


async def test_rest_explorer_forwarding_unavailable_503(recording_transport: type) -> None:
    result = await _evaluate("rest", "keys_forwarded", recording_transport)
    assert result.error is not None
    assert result.error.kind == "http"
    assert result.error.code == "service_unavailable"
    assert result.error.http_status == 503
    assert "no reachable BigFix Explorer" in result.error.message


@pytest.mark.parametrize("key", sorted(set(SUCCESS) | set(ERRORS)))
async def test_every_source_agrees(key: str, recording_transport: type) -> None:
    seen = {}
    for source, source_id in zip(SOURCES, SOURCE_IDS, strict=True):
        r = await _from_source(source, key, recording_transport)
        seen[source_id] = (
            r.answers,
            r.answer_strings,
            r.type,
            r.plural,
            r.error and (r.error.kind, r.error.message),
        )
    assert len(set(seen.values())) == 1, seen


async def test_explorer_starting_reports_its_status(recording_transport: type) -> None:
    # While Explorer is starting (here: it cannot reach its root server) it
    # answers POSTs with 405 "Only HTTP GETs are allowed." and reports why on
    # GET /. The error must say so instead of a bare 405.
    rec = recording_transport(
        [_response("explorer", "starting_405"), _response("explorer", "status_starting")]
    )
    async with ExplorerBackend("h", username="u", password="p", transport=rec.transport) as b:
        result = await b.evaluate("q")
    assert result.error is not None
    assert result.error.kind == "http"
    assert result.error.code == "service_unavailable"
    assert result.error.http_status == 405
    assert "Starting" in result.error.message
    assert "Invalid Explorer Certificate" in result.error.message
    assert [r.method for r in rec.requests] == ["POST", "GET"]


async def test_explorer_unavailable_401_includes_status(recording_transport: type) -> None:
    rec = recording_transport(
        [_response("explorer", "unavailable_401"), _response("explorer", "status_starting")]
    )
    async with ExplorerBackend("h", username="u", password="p", transport=rec.transport) as b:
        result = await b.evaluate("q")
    assert result.error is not None
    assert "temporarily unavailable" in result.error.message
    assert "Invalid Explorer Certificate" in result.error.message


async def test_rest_bad_password(recording_transport: type) -> None:
    # Captured with a fresh session: 401 text/plain "HTTP 401: Unauthorized".
    result = await _evaluate("rest", "bad_password", recording_transport)
    assert result.error is not None
    assert (result.error.kind, result.error.code) == ("authentication", None)
    assert result.error.message == "credentials rejected"
    assert result.error.http_status == 401


async def test_explorer_missing_permission_says_so(recording_transport: type) -> None:
    # Valid credentials, but the operator lacks Explorer's login permission:
    # 401 {"error": "Explorer login permission required"}. Still an
    # authentication failure (another connection may work), but the message
    # must name the missing permission rather than claim bad credentials.
    result = await _evaluate("explorer", "permission_401", recording_transport)
    assert result.error is not None
    assert (result.error.kind, result.error.code) == ("authentication", "permission_denied")
    assert result.error.http_status == 401
    assert "Explorer login permission required" in result.error.message
    assert "credentials rejected" not in result.error.message


@pytest.mark.parametrize("source", [("explorer", ""), ("rest", "via_explorer__")])
async def test_bad_password_with_explorer(
    source: tuple[str, str], recording_transport: type
) -> None:
    # Explorer: 401 {"error": "Invalid credentials"}; REST: 401 "HTTP 401: Unauthorized".
    result = await _from_source(source, "bad_password", recording_transport)
    assert result.error is not None
    assert (result.error.kind, result.error.code) == ("authentication", None)
    assert result.error.message == "credentials rejected"


async def _extras(backend: str, key: str, recording_transport: type, **kw: Any) -> Any:
    prefix = "extras_" if backend == "explorer" else "forwarded_"
    rec = recording_transport([_response(backend, prefix + key)])
    cls = ExplorerBackend if backend == "explorer" else RestBackend
    async with cls("h", username="u", password="p", transport=rec.transport) as b:
        return await b.evaluate_explorer("q", **kw)


@pytest.mark.parametrize("backend", ["explorer", "rest"])
async def test_extras_keys_become_nested_dicts(backend: str, recording_transport: type) -> None:
    result = await _extras(backend, "keys", recording_transport, keys="{id name {label flag}}")
    assert result.ok, result.error
    assert result.answers == (
        {"id": 1, "name": {"label": "a", "flag": True}},
        {"id": 2, "name": {"label": "b", "flag": False}},
    )
    assert result.type == "( integer, ( string, boolean ) )"
    assert result.plural is True


@pytest.mark.parametrize("backend", ["explorer", "rest"])
async def test_extras_filter(backend: str, recording_transport: type) -> None:
    result = await _extras(
        backend,
        "filter_computers",
        recording_transport,
        filters={"computers": "set of (bes computers whose (true))"},
    )
    assert result.ok, result.error
    assert result.answers == (35,)


@pytest.mark.parametrize("backend", ["explorer", "rest"])
async def test_extras_filter_that_is_not_a_set(backend: str, recording_transport: type) -> None:
    # A filter must return a set: 400 {"error": "Filter \"computers\": ..."}.
    result = await _extras(
        backend, "filter_bad_type", recording_transport, filters={"computers": "true"}
    )
    assert result.error is not None
    assert result.error.kind == "session_relevance"
    assert result.error.http_status == 400
    assert result.error.message.startswith('Filter "computers":')


# Issue #5: Web Reports keeps qna-style %xx escapes in answer text; REST (with
# and without a reachable Explorer) and Explorer send it decoded.
ESCAPED_STRINGS = ("a%b", "a%41", "x\ny", "a\tb", "a\x01b", "a\x7fb")


@pytest.mark.parametrize("source", SOURCES, ids=SOURCE_IDS)
async def test_escape_probes_decode_on_every_backend(
    source: tuple[str, str], recording_transport: type
) -> None:
    strings = await _from_source(source, "escaped_strings", recording_transport)
    assert strings.answers == strings.answer_strings == ESCAPED_STRINGS
    pair = await _from_source(source, "escaped_tuple", recording_transport)
    assert pair.answers == (("a%b", 1),)
    error = await _from_source(source, "error_escaped", recording_transport)
    assert error.error is not None
    # message is whitespace-normalized; detail keeps the server's text (a tab).
    assert error.error.message == "User-defined error: a%b c"
    assert error.error.detail is not None
    assert "a%b\tc" in error.error.detail


@pytest.mark.parametrize("source", SOURCES, ids=SOURCE_IDS)
async def test_escape_result_gives_web_reports_text_on_every_backend(
    source: tuple[str, str], recording_transport: type
) -> None:
    result = escape_result(await _from_source(source, "escaped_strings", recording_transport))
    # Exactly the <String> leaves of the captured Web Reports response.
    assert result.answers == ("a%25b", "a%2541", "x%0ay", "a%09b", "a%01b", "a%7fb")


async def test_webreports_plain_method_decodes_escapes(recording_transport: type) -> None:
    async def plain(key: str) -> Any:
        return await _evaluate("webreports", key, recording_transport, soap_method="plain")

    assert (await plain("escaped_strings__plain")).answers == ESCAPED_STRINGS
    assert (await plain("escaped_tuple__plain")).answers == ("a%b, 1",)
    error = await plain("error_escaped__plain")
    assert error.error is not None
    # message is whitespace-normalized; detail keeps the server's text (a tab).
    assert error.error.message == "User-defined error: a%b c"
    assert error.error.detail is not None
    assert "a%b\tc" in error.error.detail
