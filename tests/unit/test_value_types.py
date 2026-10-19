from __future__ import annotations

from typing import Any

import pytest

from bigfix_remote_session_relevance.value_types import (
    answer_string,
    coerce,
    parse_type,
)


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("integer", "integer"),
        ("  string ", "string"),
        ("bes computer", "bes computer"),
        ("( integer, string )", ("integer", "string")),
        ("(integer,string)", ("integer", "string")),
        ("( integer, ( string, boolean ) )", ("integer", ("string", "boolean"))),
        ("( ( integer, integer ), time )", (("integer", "integer"), "time")),
        ("", None),
        (None, None),
    ],
)
def test_parse_type(text: str | None, expected: object) -> None:
    assert parse_type(text) == expected


@pytest.mark.parametrize("bad", ["( integer, string", "integer )", "( , )"])
def test_parse_type_malformed_returns_raw_string(bad: str) -> None:
    # A type string we cannot parse must never break result handling; it is
    # kept as an opaque scalar type so values stay strings.
    assert parse_type(bad) == bad.strip()


@pytest.mark.parametrize(
    ("value", "type_node", "expected"),
    [
        ("42", "integer", 42),
        ("-7", "integer", -7),
        (42, "integer", 42),
        ("4x", "integer", "4x"),
        ("True", "boolean", True),
        ("false", "boolean", False),
        (True, "boolean", True),
        ("maybe", "boolean", "maybe"),
        ("hello", "string", "hello"),
        (5, "string", "5"),
        ("Fri, 17 Oct 2026 10:00:00 +0000", "time", "Fri, 17 Oct 2026 10:00:00 +0000"),
        (["1", "abc"], ("integer", "string"), (1, "abc")),
        ([1, ["x", "True"]], ("integer", ("string", "boolean")), (1, ("x", True))),
        # Arity mismatch: keep what we got rather than guess.
        (["1", "2", "3"], ("integer", "integer"), ("1", "2", "3")),
        # A tuple type whose value arrived as one string cannot be split safely.
        ("1, abc", ("integer", "string"), "1, abc"),
        ("anything", None, "anything"),
        ({"id": 1}, None, {"id": 1}),
    ],
)
def test_coerce(value: Any, type_node: Any, expected: Any) -> None:
    assert coerce(value, type_node) == expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("abc", "abc"),
        (42, "42"),
        (True, "True"),
        (False, "False"),
        ((1, "abc"), "1, abc"),
        ((1, ("x", True)), "1, x, True"),
        ({"id": 1, "name": "a"}, '{"id": 1, "name": "a"}'),
        (None, ""),
    ],
)
def test_answer_string(value: object, expected: str) -> None:
    assert answer_string(value) == expected


def test_json_number_keeps_the_server_text_and_stays_a_float() -> None:
    import copy
    import json
    import pickle

    from bigfix_remote_session_relevance.value_types import JsonNumber, loads_json

    small, large, whole = loads_json("[0.000001234, 1.0e+300, 3.0]")
    assert (str(small), str(large), str(whole)) == ("0.000001234", "1.0e+300", "3.0")
    assert small == 0.000001234 and isinstance(small, float)
    assert loads_json("[7]") == [7] and type(loads_json("[7]")[0]) is int
    for clone in (copy.copy(small), copy.deepcopy(small), pickle.loads(pickle.dumps(small))):  # noqa: S301 (own data)
        assert isinstance(clone, JsonNumber) and str(clone) == "0.000001234"
    assert json.loads(json.dumps([small])) == [0.000001234]
    assert coerce(small, "floating point") == "0.000001234"
