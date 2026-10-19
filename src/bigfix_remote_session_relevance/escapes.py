"""The ``%XX`` escapes Web Reports (like the client's qna) puts in answer text.

Web Reports sends ``%`` as ``%25`` and the control characters 0x00-0x1F and
0x7F as ``%xx`` (lowercase hex); everything else, non-ASCII included, is sent
as is. The REST API and Explorer send the text itself. Observed live on
11.0.7 (issue #5).
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

from .value_types import answer_string

if TYPE_CHECKING:
    from .result import SessionRelevanceResult

_ESCAPE_RE = re.compile(r"%([0-9A-Fa-f]{2})")
_ESCAPES = {c: f"%{c:02x}" for c in (ord("%"), *range(0x20), 0x7F)}  # for str.translate


def unescape_answer(text: str) -> str:
    """Decode the ``%XX`` escapes Web Reports puts in answer text.

    One pass, so ``a%2541`` is ``a%41``, not ``aA``. A ``%`` not followed by
    two hex digits is left as is. Every escaped character is ASCII, so
    ``chr()`` of the byte is the character.
    """
    if "%" not in text:  # most answers: skip the regex
        return text
    return _ESCAPE_RE.sub(lambda m: chr(int(m.group(1), 16)), text)


def escape_answer(text: str) -> str:
    """The inverse of `unescape_answer`: Web Reports' form of answer text.

    ``%`` and 0x00-0x1F/0x7F become ``%xx`` in lowercase hex, exactly as Web
    Reports sends them, so ``escape_answer(unescape_answer(t)) == t`` for its
    text. Makes non-printable characters visible.
    """
    # ASCII controls are never printable, so printable text without "%" has
    # nothing to escape; both checks run in C. (Some non-ASCII characters are
    # not printable either: they take the translate path and come out as is.)
    if "%" not in text and text.isprintable():
        return text
    return text.translate(_ESCAPES)


def escape_result(result: SessionRelevanceResult) -> SessionRelevanceResult:
    """`result` with every string in its answers escaped (`escape_answer`).

    Applied after the backend, so it is the same on every backend. Errors
    (never escaped by any server) and ``raw`` are left as they are.
    """
    if result.error is not None:
        return result
    answers = tuple(_escape_value(a) for a in result.answers)
    if answers == result.answers:
        return result
    return result.replace(answers=answers, answer_strings=tuple(answer_string(a) for a in answers))


def _escape_value(value: Any) -> Any:
    if isinstance(value, str):
        return escape_answer(value)
    if isinstance(value, tuple | list):
        return type(value)(_escape_value(v) for v in value)
    if isinstance(value, dict):
        return {k: _escape_value(v) for k, v in value.items()}
    return value
