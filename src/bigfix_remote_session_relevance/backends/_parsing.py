"""Response parsers shared by the JSON-speaking backends (REST, Explorer).

The REST API is asked for JSON, but an older server (or a proxy) may still
answer with the BESAPI XML document, so that is parsed too. Callers never
see which one arrived.
"""

from __future__ import annotations

import json
import re
from typing import TYPE_CHECKING, Any
from xml.etree.ElementTree import ParseError

import defusedxml.ElementTree as SafeET
import httpx
from defusedxml import DefusedXmlException

from ..result import RawResponse, ResultError, SessionRelevanceResult
from .base import error_from_status, normalize_relevance_error

if TYPE_CHECKING:
    from xml.etree.ElementTree import Element

_DETAIL_LIMIT = 500
_TIME_RE = re.compile(r"^\s*([0-9]*\.?[0-9]+)\s*(ms|s)?\s*$", re.IGNORECASE)


def raw_from_response(response: httpx.Response) -> RawResponse:
    return RawResponse(
        status_code=response.status_code,
        content_type=response.headers.get("content-type"),
        text=response.text,
    )


def parse_session_relevance_response(
    session_relevance: str, response: httpx.Response, backend: str
) -> SessionRelevanceResult:
    """Parse a REST ``/api/query`` or Explorer ``/api/relevance`` response."""
    raw = raw_from_response(response)
    if response.status_code in (401, 403):
        return SessionRelevanceResult.failure(
            session_relevance, error_from_status(response, backend), raw=raw
        )
    if raw.format == "json":
        try:
            data = json.loads(raw.text)
        except ValueError as exc:
            return _format_error(session_relevance, raw, backend, f"invalid JSON: {exc}")
        return _from_json(session_relevance, data, response, raw, backend)
    if raw.format == "xml":
        return parse_besapi_xml(session_relevance, raw, backend)
    # Plain text: a session relevance error on some versions, otherwise not ours.
    if response.status_code == 400 and raw.text.strip():
        return _session_relevance_error(session_relevance, raw.text, raw, backend, http_status=400)
    if response.status_code >= 400:
        return SessionRelevanceResult.failure(
            session_relevance, error_from_status(response, backend), raw=raw
        )
    return _format_error(session_relevance, raw, backend, "expected JSON, got non-JSON response")


def _from_json(
    session_relevance: str, data: Any, response: httpx.Response, raw: RawResponse, backend: str
) -> SessionRelevanceResult:
    # The REST API reports relevance errors as {"result": [], "error": "..."}
    # with HTTP 200, so the error must be checked before the result.
    message = _json_error_text(data)
    if (
        message is not None
        and response.status_code < 500
        and response.status_code
        not in (
            401,
            403,
        )
    ):
        status = response.status_code if response.status_code != 200 else None
        return _session_relevance_error(
            session_relevance, message, raw, backend, http_status=status
        )
    if isinstance(data, dict) and "result" in data:
        values = data["result"]
        if not isinstance(values, list):
            values = [values]
        return SessionRelevanceResult.from_values(
            session_relevance,
            values,
            type=data.get("type"),
            plural=data.get("plural") if isinstance(data.get("plural"), bool) else None,
            evaluation_time_ms=_float_or_none(data.get("evaltime_ms")),
            raw=raw,
        )
    if response.status_code >= 400:
        return SessionRelevanceResult.failure(
            session_relevance, error_from_status(response, backend), raw=raw
        )
    return _format_error(session_relevance, raw, backend, "JSON response has no result")


def _json_error_text(data: Any) -> str | None:
    if isinstance(data, dict):
        for key in ("error", "Error", "message", "Message"):
            value = data.get(key)
            if isinstance(value, str) and value.strip():
                return value
            if isinstance(value, dict):
                nested = _json_error_text(value)
                if nested:
                    return nested
    return None


def parse_besapi_xml(
    session_relevance: str, raw: RawResponse, backend: str
) -> SessionRelevanceResult:
    """Parse ``<BESAPI><Query>…`` as in bigfix-relevance-debugger's besapi.py."""
    try:
        root = SafeET.fromstring(raw.text)
    except (ParseError, DefusedXmlException) as exc:
        return _format_error(session_relevance, raw, backend, f"invalid XML: {exc}")
    if _local(root.tag) != "BESAPI":
        return _format_error(session_relevance, raw, backend, f"unexpected XML root <{root.tag}>")
    query = _child(root, "Query")
    if query is None:
        return _format_error(session_relevance, raw, backend, "BESAPI response has no <Query>")
    error = _child(query, "Error")
    if error is not None:
        return _session_relevance_error(session_relevance, error.text or "", raw, backend)

    result_el = _child(query, "Result")
    values: list[Any] = []
    types: list[str] = []
    for node in list(result_el) if result_el is not None else []:
        if _local(node.tag) in ("Answer", "Tuple"):
            value, type_text = _render_besapi(node)
            values.append(value)
            types.append(type_text)
    evaluation = _child(query, "Evaluation")
    plurality = _child_text(evaluation, "Plurality")
    return SessionRelevanceResult.from_values(
        session_relevance,
        values,
        type=types[0] if types else None,
        plural={"Plural": True, "Singular": False}.get(plurality or ""),
        evaluation_time_ms=parse_time_ms(_child_text(evaluation, "Time")),
        raw=raw,
    )


def _render_besapi(node: Element) -> tuple[Any, str]:
    if _local(node.tag) == "Tuple":
        parts = [_render_besapi(child) for child in node]
        return [p[0] for p in parts], "( " + ", ".join(p[1] for p in parts) + " )"
    return node.text or "", node.get("type", "")


def parse_time_ms(text: str | None) -> float | None:
    """``"0.31ms"`` / ``"2s"`` / ``"24"`` (ms assumed) -> milliseconds."""
    if text is None:
        return None
    match = _TIME_RE.match(text)
    if not match:
        return None
    value = float(match.group(1))
    return value * 1000 if (match.group(2) or "ms").lower() == "s" else value


def _float_or_none(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int | float):
        return float(value)
    if isinstance(value, str):
        return parse_time_ms(value)
    return None


def _session_relevance_error(
    session_relevance: str,
    text: str,
    raw: RawResponse,
    backend: str,
    http_status: int | None = None,
) -> SessionRelevanceResult:
    return SessionRelevanceResult.failure(
        session_relevance,
        ResultError(
            kind="session_relevance",
            backend=backend,
            http_status=http_status,
            message=normalize_relevance_error(text),
            detail=text[:_DETAIL_LIMIT],
        ),
        raw=raw,
    )


def _format_error(
    session_relevance: str, raw: RawResponse, backend: str, message: str
) -> SessionRelevanceResult:
    return SessionRelevanceResult.failure(
        session_relevance,
        ResultError(
            kind="response_format",
            backend=backend,
            http_status=raw.status_code,
            message=message,
            detail=raw.text[:_DETAIL_LIMIT],
        ),
        raw=raw,
    )


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _child(parent: Element | None, name: str) -> Element | None:
    if parent is None:
        return None
    for child in parent:
        if _local(child.tag) == name:
            return child
    return None


def _child_text(parent: Element | None, name: str) -> str | None:
    child = _child(parent, name)
    return None if child is None else (child.text or "")
