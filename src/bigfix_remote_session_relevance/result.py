"""`SessionRelevanceResult`: the one return type of every backend.

Modelled on ``SessionRelevanceResult`` in bigfix-relevance-debugger's
``upstream/besapi.py`` and extended for multiple backends and servers. The
normalized fields are what callers use; ``raw`` keeps the untouched response
for the rare caller that asks for it, and is kept out of ``repr()``,
equality and ``to_dict()`` unless requested.

The field set is a public contract: see ``test_result_has_every_designed_field``.
"""

from __future__ import annotations

import dataclasses
import json
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Literal

import defusedxml.ElementTree as SafeET

from .exceptions import EXCEPTION_FOR_KIND
from .value_types import answer_string, coerce, parse_type

if TYPE_CHECKING:
    from xml.etree.ElementTree import Element

ERROR_KINDS: tuple[str, ...] = (
    "relevance",
    "authentication",
    "connection",
    "timeout",
    "tls",
    "http",
    "response_format",
    "unsupported_feature",
    "not_implemented",
)

RawFormat = Literal["json", "xml", "text"]


@dataclass(frozen=True)
class ResultError:
    """A failure, in the same shape whichever backend produced it.

    ``message`` is normalized (backend prefixes and SOAP wrapping removed) so
    the same bad query reads the same everywhere; ``detail`` keeps the text
    exactly as the server sent it. ``code`` is an optional machine-readable
    sub-kind (e.g. ``pin_mismatch``) for decisions ``kind`` is too coarse for.
    """

    kind: str
    message: str
    backend: str | None = None
    http_status: int | None = None
    detail: str | None = None
    code: str | None = None

    def __post_init__(self) -> None:
        if self.kind not in ERROR_KINDS:
            raise ValueError(f"unknown error kind {self.kind!r}; expected one of {ERROR_KINDS}")

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "code": self.code,
            "message": self.message,
            "backend": self.backend,
            "http_status": self.http_status,
            "detail": self.detail,
        }


@dataclass(frozen=True)
class RawResponse:
    """The response body exactly as received."""

    status_code: int
    content_type: str | None
    text: str

    @property
    def format(self) -> RawFormat:
        # Content-Type first, then sniff: BigFix servers are not consistent
        # about the header, and a login page must not pass for data.
        ctype = (self.content_type or "").lower()
        if "json" in ctype:
            return "json"
        if "xml" in ctype and "html" not in ctype:
            return "xml"
        body = self.text.lstrip()
        if body.startswith(("{", "[")):
            return "json"
        if body.startswith("<") and not body[:15].lower().startswith(("<!doctype html", "<html")):
            return "xml"
        return "text"

    def json(self) -> Any:
        if self.format != "json":
            raise ValueError(f"raw response is not JSON (format={self.format})")
        return json.loads(self.text)

    def xml(self) -> Element:
        if self.format != "xml":
            raise ValueError(f"raw response is not XML (format={self.format})")
        return SafeET.fromstring(self.text)

    def to_dict(self) -> dict[str, Any]:
        return {
            "status_code": self.status_code,
            "content_type": self.content_type,
            "format": self.format,
            "text": self.text,
        }


@dataclass(frozen=True)
class SessionRelevanceResult:
    """The result of one session relevance query against one connection."""

    relevance: str
    answers: tuple[Any, ...] = ()
    answer_strings: tuple[str, ...] = ()
    type: str | None = None
    plural: bool | None = None
    evaluation_time_ms: float | None = None
    error: ResultError | None = None
    connection: str | None = None
    deployment_id: str | None = None
    backend: str | None = None
    server: str | None = None
    elapsed_ms: float | None = field(default=None, compare=False)
    raw: RawResponse | None = field(default=None, repr=False, compare=False)

    # -- construction ---------------------------------------------------------

    @classmethod
    def from_values(
        cls,
        relevance: str,
        values: Iterable[Any],
        *,
        type: str | None = None,
        **kwargs: Any,
    ) -> SessionRelevanceResult:
        """Build a successful result, coercing values by the reported type."""
        node = parse_type(type)
        answers = tuple(coerce(v, node) for v in values)
        return cls(
            relevance=relevance,
            answers=answers,
            answer_strings=tuple(answer_string(a) for a in answers),
            type=type,
            **kwargs,
        )

    @classmethod
    def failure(cls, relevance: str, error: ResultError, **kwargs: Any) -> SessionRelevanceResult:
        return cls(relevance=relevance, error=error, **kwargs)

    def replace(self, **changes: Any) -> SessionRelevanceResult:
        return dataclasses.replace(self, **changes)

    # -- convenience ----------------------------------------------------------

    @property
    def ok(self) -> bool:
        return self.error is None

    @property
    def count(self) -> int:
        return len(self.answers)

    def raise_for_error(self) -> SessionRelevanceResult:
        """Raise the kind-specific exception if this result failed; else return self."""
        if self.error is None:
            return self
        exc_type = EXCEPTION_FOR_KIND[self.error.kind]
        where = f" [{self.connection or self.backend}]" if (self.connection or self.backend) else ""
        raise exc_type(f"{self.error.kind}{where}: {self.error.message}", result=self)

    def raw_json(self) -> Any:
        return self._require_raw().json()

    def raw_xml(self) -> Element:
        return self._require_raw().xml()

    def _require_raw(self) -> RawResponse:
        if self.raw is None:
            raise ValueError("this result has no raw response")
        return self.raw

    def to_dict(self, *, include_raw: bool = False) -> dict[str, Any]:
        data: dict[str, Any] = {
            "relevance": self.relevance,
            "ok": self.ok,
            "answers": [_jsonable(a) for a in self.answers],
            "answer_strings": list(self.answer_strings),
            "count": self.count,
            "type": self.type,
            "plural": self.plural,
            "evaluation_time_ms": self.evaluation_time_ms,
            "error": self.error.to_dict() if self.error else None,
            "connection": self.connection,
            "deployment_id": self.deployment_id,
            "backend": self.backend,
            "server": self.server,
            "elapsed_ms": self.elapsed_ms,
        }
        if include_raw:
            data["raw"] = self.raw.to_dict() if self.raw else None
        return data


def _jsonable(value: Any) -> Any:
    if isinstance(value, tuple | list):
        return [_jsonable(v) for v in value]
    return value
