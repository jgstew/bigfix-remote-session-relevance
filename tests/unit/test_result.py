from __future__ import annotations

import dataclasses
import json

import pytest

from bigfix_remote_session_relevance import exceptions
from bigfix_remote_session_relevance.result import (
    ERROR_KINDS,
    RawResponse,
    ResultError,
    SessionRelevanceResult,
)

# The designed public field set. Adding a field is an additive contract change:
# update this list, to_dict's key order, and DESIGN.md together.
DESIGNED_FIELDS = [
    "session_relevance",
    "answers",
    "answer_strings",
    "type",
    "plural",
    "evaluation_time_ms",
    "error",
    "connection",
    "deployment_id",
    "backend",
    "server",
    "elapsed_ms",
    "raw",
]

DESIGNED_DICT_KEYS = [
    "session_relevance",
    "ok",
    "answers",
    "answer_strings",
    "count",
    "type",
    "plural",
    "evaluation_time_ms",
    "error",
    "connection",
    "deployment_id",
    "backend",
    "server",
    "elapsed_ms",
]


def test_result_has_every_designed_field() -> None:
    assert [f.name for f in dataclasses.fields(SessionRelevanceResult)] == DESIGNED_FIELDS


def test_session_relevance_is_named_explicitly() -> None:
    # Session and client relevance are different dialects; the public API
    # never says bare "relevance" (0.5.0 renamed it without an alias).
    result = SessionRelevanceResult.from_values(session_relevance="1", values=["1"])
    assert result.session_relevance == "1"
    assert not hasattr(result, "relevance")
    with pytest.raises(TypeError):
        SessionRelevanceResult(relevance="1")  # type: ignore[call-arg]
    assert exceptions.EXCEPTION_FOR_KIND["session_relevance"] is (
        exceptions.SessionRelevanceEvaluationError
    )
    assert not hasattr(exceptions, "RelevanceError")


def test_from_values_coerces_by_type_and_builds_strings() -> None:
    result = SessionRelevanceResult.from_values(
        "(id of it, name of it) of bes computers",
        [["1", "alpha"], [2, "beta"]],
        type="( integer, string )",
        plural=True,
        evaluation_time_ms=1.5,
        backend="rest",
    )
    assert result.answers == ((1, "alpha"), (2, "beta"))
    assert result.answer_strings == ("1, alpha", "2, beta")
    assert result.count == 2
    assert result.ok
    assert result.error is None


def test_from_values_without_type_keeps_strings() -> None:
    result = SessionRelevanceResult.from_values("names of bes computers", ["5", "a"])
    assert result.answers == ("5", "a")
    assert result.answer_strings == ("5", "a")


def test_failure_has_no_answers() -> None:
    err = ResultError(kind="session_relevance", message='The operator "foo" is not defined.')
    result = SessionRelevanceResult.failure("foo", err, backend="rest")
    assert not result.ok
    assert result.answers == ()
    assert result.count == 0
    assert result.plural is None
    assert result.error is err


def test_result_error_rejects_unknown_kind() -> None:
    with pytest.raises(ValueError, match="kind"):
        ResultError(kind="oops", message="x")


def test_error_kinds_are_the_designed_set() -> None:
    assert ERROR_KINDS == (
        "session_relevance",
        "authentication",
        "connection",
        "timeout",
        "tls",
        "http",
        "response_format",
        "unsupported_feature",
        "not_implemented",
    )


@pytest.mark.parametrize("kind", ERROR_KINDS)
def test_raise_for_error_raises_kind_specific_exception(kind: str) -> None:
    result = SessionRelevanceResult.failure("q", ResultError(kind=kind, message="boom"))
    with pytest.raises(exceptions.SessionRelevanceError) as info:
        result.raise_for_error()
    assert type(info.value) is exceptions.EXCEPTION_FOR_KIND[kind]
    assert info.value.result is result
    assert "boom" in str(info.value)


def test_raise_for_error_returns_self_when_ok() -> None:
    result = SessionRelevanceResult.from_values("1", ["1"], type="integer")
    assert result.raise_for_error() is result


def test_to_dict_key_order_and_json_safety() -> None:
    result = SessionRelevanceResult.from_values(
        "q", [["1", "a"]], type="( integer, string )", plural=True, backend="rest"
    )
    data = result.to_dict()
    assert list(data) == DESIGNED_DICT_KEYS
    assert data["answers"] == [[1, "a"]]
    json.dumps(data)  # must not raise


def test_to_dict_error_shape() -> None:
    err = ResultError(
        kind="tls",
        message="changed",
        backend="rest",
        http_status=None,
        detail="x",
        code="pin_mismatch",
    )
    data = SessionRelevanceResult.failure("q", err).to_dict()
    assert data["error"] == {
        "kind": "tls",
        "code": "pin_mismatch",
        "message": "changed",
        "backend": "rest",
        "http_status": None,
        "detail": "x",
    }


def test_raw_is_hidden_unless_asked_for() -> None:
    raw = RawResponse(status_code=200, content_type="application/json", text='{"result": [1]}')
    result = SessionRelevanceResult.from_values("1", [1], type="integer", raw=raw)
    assert "raw" not in repr(result)
    assert "raw" not in result.to_dict()
    assert result.to_dict(include_raw=True)["raw"] == {
        "status_code": 200,
        "content_type": "application/json",
        "format": "json",
        "text": '{"result": [1]}',
    }


def test_raw_json_and_xml_accessors() -> None:
    as_json = RawResponse(200, "application/json; charset=utf-8", '{"a": 1}')
    assert as_json.format == "json"
    assert as_json.json() == {"a": 1}
    with pytest.raises(ValueError, match="not XML"):
        as_json.xml()

    as_xml = RawResponse(200, "text/xml", "<r><a>1</a></r>")
    assert as_xml.format == "xml"
    assert as_xml.xml().find("a").text == "1"  # type: ignore[union-attr]
    with pytest.raises(ValueError, match="not JSON"):
        as_xml.json()


def test_raw_format_sniffs_body_when_content_type_lies() -> None:
    # BigFix servers are not consistent about Content-Type; an HTML login page
    # served as text/plain must still be identified as not-JSON/not-XML.
    assert RawResponse(200, "text/plain", '{"result": []}').format == "json"
    assert RawResponse(200, None, "<?xml version='1.0'?><a/>").format == "xml"
    assert RawResponse(200, "text/html", "<html><body>login</body></html>").format == "text"


def test_result_raw_accessors_delegate() -> None:
    raw = RawResponse(200, "application/json", '{"result": [1]}')
    result = SessionRelevanceResult.from_values("1", [1], type="integer", raw=raw)
    assert result.raw_json() == {"result": [1]}
    no_raw = SessionRelevanceResult.from_values("1", [1], type="integer")
    with pytest.raises(ValueError, match="no raw"):
        no_raw.raw_json()


def test_raw_xml_is_parsed_safely() -> None:
    bomb = (
        '<?xml version="1.0"?><!DOCTYPE l [<!ENTITY a "aaaa"><!ENTITY b "&a;&a;&a;&a;">]><l>&b;</l>'
    )
    with pytest.raises(Exception, match=r"(?i)entities"):
        RawResponse(200, "text/xml", bomb).xml()


def test_equality_ignores_raw_and_timing_free_fields_compare() -> None:
    a = SessionRelevanceResult.from_values(
        "1", [1], type="integer", raw=RawResponse(200, None, "1")
    )
    b = SessionRelevanceResult.from_values(
        "1", [1], type="integer", raw=RawResponse(200, None, "<a>1</a>")
    )
    assert a == b
