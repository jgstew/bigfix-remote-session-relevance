"""Session relevance type strings and native value coercion.

Every backend reports a result type as a string such as ``integer`` or
``( integer, ( string, boolean ) )``. That string, not the wire format, is
what decides the Python type of each answer, so the REST API (JSON numbers),
Web Reports (XML text) and Explorer agree on ``answers`` for the same query.
"""

from __future__ import annotations

import json
import re
from typing import Any, Self, TypeAlias

# A parsed type: a scalar type name, or a tuple of parsed types.
TypeNode: TypeAlias = "str | tuple[TypeNode, ...]"

_INT_RE = re.compile(r"^[+-]?\d+$")


class _Malformed(ValueError):
    pass


class JsonNumber(float):
    """A JSON number that remembers the server's text for it.

    The REST API and Explorer send floating points as JSON numbers whose
    text is what Web Reports sends as text (``0.000001234``, ``1.0e+300``);
    ``str(float)`` would give ``1.234e-06`` and ``1e+300``. ``str()`` of this
    is the server's text, so ``answers`` agree across backends; it is still
    a ``float`` for arithmetic, equality and ``json.dumps``.
    """

    text: str

    def __new__(cls, text: str) -> Self:
        number = super().__new__(cls, text)
        number.text = text
        return number

    def __str__(self) -> str:
        return self.text

    def __getnewargs__(self) -> tuple[str]:  # type: ignore[override]  # pickle/copy keep the text
        return (self.text,)


def loads_json(text: str) -> Any:
    """`json.loads`, with non-integer numbers as `JsonNumber`."""
    return json.loads(text, parse_float=JsonNumber)


def parse_type(text: str | None) -> TypeNode | None:
    """Parse a session relevance type string.

    Unparsable input is returned stripped, as an opaque scalar type, so a
    type the server spells in a way we did not anticipate degrades to string
    answers instead of an exception.
    """
    if text is None or not text.strip():
        return None
    stripped = text.strip()
    try:
        node, rest = _parse(stripped, 0)
        if stripped[rest:].strip():
            raise _Malformed(stripped)
    except _Malformed:
        return stripped
    return node


def _parse(text: str, pos: int) -> tuple[TypeNode, int]:
    pos = _skip_ws(text, pos)
    if pos < len(text) and text[pos] == "(":
        items: list[TypeNode] = []
        pos += 1
        while True:
            item, pos = _parse(text, pos)
            items.append(item)
            pos = _skip_ws(text, pos)
            if pos >= len(text):
                raise _Malformed(text)
            if text[pos] == ",":
                pos += 1
                continue
            if text[pos] == ")":
                return tuple(items), pos + 1
            raise _Malformed(text)
    start = pos
    while pos < len(text) and text[pos] not in "(),":
        pos += 1
    name = text[start:pos].strip()
    if not name:
        raise _Malformed(text)
    return name, pos


def _skip_ws(text: str, pos: int) -> int:
    while pos < len(text) and text[pos].isspace():
        pos += 1
    return pos


def coerce(value: Any, type_node: TypeNode | None) -> Any:
    """Convert one answer to its native Python type, per ``type_node``.

    integer -> int, boolean -> bool, tuple types -> tuple; any other type is
    a string. Values that do not fit their declared type are left as they
    arrived rather than guessed at. ``dict`` (Explorer ``keys`` output) and
    untyped values pass through untouched.
    """
    if type_node is None or isinstance(value, dict):
        return value
    if isinstance(type_node, tuple):
        if isinstance(value, list | tuple) and len(value) == len(type_node):
            return tuple(coerce(v, t) for v, t in zip(value, type_node, strict=True))
        if isinstance(value, list | tuple):
            return tuple(value)
        return value
    if type_node == "integer":
        if isinstance(value, bool):
            return value
        if isinstance(value, int):
            return value
        if isinstance(value, str) and _INT_RE.match(value.strip()):
            return int(value.strip())
        return value
    if type_node == "boolean":
        if isinstance(value, bool):
            return value
        if isinstance(value, str) and value.strip().lower() in ("true", "false"):
            return value.strip().lower() == "true"
        return value
    if isinstance(value, bool):
        return "True" if value else "False"
    if isinstance(value, int | float):
        return str(value)
    return value


def answer_string(value: Any) -> str:
    """Render an answer the way BigFix prints it.

    Tuples are flattened and joined with ``", "`` (as the relevance debugger
    and the REST API XML output do), booleans are ``True``/``False``, and
    dicts from Explorer ``keys`` become compact JSON.
    """
    if value is None:
        return ""
    if isinstance(value, bool):
        return "True" if value else "False"
    if isinstance(value, tuple | list):
        return ", ".join(answer_string(v) for v in value)
    if isinstance(value, dict):
        return json.dumps(value, separators=(", ", ": "))
    return str(value)
