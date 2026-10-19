"""qna-style %XX escapes: Web Reports' answer text, and the opt-in inverse."""

from __future__ import annotations

import pytest

from bigfix_remote_session_relevance import (
    ResultError,
    SessionRelevanceResult,
    escape_answer,
    unescape_answer,
)
from bigfix_remote_session_relevance.escapes import escape_result

# (as Web Reports sends it, decoded) -- observed live on 11.0.7 (issue #5).
PAIRS = [
    ("a%25b", "a%b"),
    ("a%2541", "a%41"),
    ("a%09b", "a\tb"),
    ("x%0ay", "x\ny"),
    ("a%0db", "a\rb"),
    ("a%00b", "a\x00b"),
    ("a%01b", "a\x01b"),
    ("a%1fb", "a\x1fb"),
    ("a%7fb", "a\x7fb"),
    ('a b,c;"d" café €', 'a b,c;"d" café €'),
    ("", ""),
]


@pytest.mark.parametrize(("escaped", "decoded"), PAIRS)
def test_unescape(escaped: str, decoded: str) -> None:
    assert unescape_answer(escaped) == decoded


@pytest.mark.parametrize(("escaped", "decoded"), PAIRS)
def test_escape_is_web_reports_form(escaped: str, decoded: str) -> None:
    assert escape_answer(decoded) == escaped


def test_unescape_accepts_uppercase_hex() -> None:
    assert unescape_answer("A%7FB%0A") == "A\x7fB\n"


def test_unescape_leaves_bare_percent() -> None:
    assert unescape_answer("100% %z1 %4") == "100% %z1 %4"


def test_escape_set_is_percent_and_controls_only() -> None:
    escaped = {chr(c) for c in range(0x100) if escape_answer(chr(c)) != chr(c)}
    assert escaped == {"%", *map(chr, range(0x20)), "\x7f"}


def test_round_trip_every_low_character() -> None:
    text = "".join(chr(c) for c in range(0x100))
    assert unescape_answer(escape_answer(text)) == text


def test_escape_result_escapes_every_string_leaf() -> None:
    result = SessionRelevanceResult.from_values(
        "q",
        [["a%b", 1, True], ["x\ny", 2, False]],
        type="( string, integer, boolean )",
        plural=True,
    )
    out = escape_result(result)
    assert out.answers == (("a%25b", 1, True), ("x%0ay", 2, False))
    assert out.answer_strings == ("a%25b, 1, True", "x%0ay, 2, False")
    assert out.type == result.type
    assert out.plural is True


def test_escape_result_escapes_dict_values() -> None:
    # Explorer `keys` output: names are the caller's, values are answer text.
    result = SessionRelevanceResult.from_values("q", [{"name": "a\tb", "n": 1}], type=None)
    assert escape_result(result).answers == ({"name": "a%09b", "n": 1},)


def test_escape_result_leaves_errors_alone() -> None:
    failed = SessionRelevanceResult.failure(
        "q", ResultError(kind="session_relevance", message="User-defined error: a%b c")
    )
    assert escape_result(failed) is failed
