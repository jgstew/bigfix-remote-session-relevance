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
# For the terminal: C0 (but tab), DEL and C1. ESC (0x1b) and CSI (0x9b) start
# terminal control sequences; CR, LF, NEL (0x85) and the rest move the cursor
# or start a line, which could fake extra answers.
_CONTROLS = {c: f"%{c:02x}" for c in (*range(0x20), *range(0x7F, 0xA0)) if c != ord("\t")}
_CONTROLS_BUT_LF = {c: e for c, e in _CONTROLS.items() if c != ord("\n")}


def unescape_answer(text: str) -> str:
    """Decode the ``%XX`` escapes Web Reports puts in answer text.

    One pass, so ``a%2541`` is ``a%41``, not ``aA``. A ``%`` not followed by
    two hex digits is left as is. Every escaped character is ASCII, so
    ``chr()`` of the byte is the character. Any ``%XX`` is decoded, not only
    the ones Web Reports produces, so this is for Web Reports' answer text,
    where a literal ``%`` is always ``%25``.
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


def escape_controls(text: str, *, keep_newlines: bool = False) -> str:
    """`text` safe to write to a terminal: control characters shown as ``%xx``.

    For display only. C0 controls but tab, DEL and the C1 controls are
    escaped; ``%`` is not (so ``%SystemRoot%`` stays readable), which makes
    this lossy: ``--keep-escapes`` is the unambiguous form.
    """
    if text.isprintable():  # most text; C0, DEL and C1 are never printable
        return text
    return text.translate(_CONTROLS_BUT_LF if keep_newlines else _CONTROLS)


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
