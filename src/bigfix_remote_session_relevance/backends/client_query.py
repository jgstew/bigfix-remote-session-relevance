"""BigFix Query (ClientQuery): send client relevance to agents through REST.

Strictly additive and opt-in, like ``explorer_extras``. Plain ``evaluate()``
is session relevance and never touches this. Here the expression is client
relevance, evaluated by each targeted agent, so the parameter is named
``client_relevance``.

This is a two-call wire layer: ``POST /api/clientquery`` submits and returns
the query id, ``GET /api/clientqueryresults/{id}`` returns every row so far
(results accumulate as agents answer). Polling is left to the caller.
Only `RestBackend` implements it (observed on 11.0.x).
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import dataclass, replace
from typing import Any, Protocol, runtime_checkable
from xml.etree import ElementTree as ET

import defusedxml.ElementTree as SafeET
import httpx
from defusedxml import DefusedXmlException

from ..result import ResultError
from .base import error_from_status, server_message

_DETAIL_LIMIT = 500
PERMISSION_HINT = 'non-master operators need the "Can Submit Queries" permission'


@dataclass(frozen=True)
class ClientQueryRow:
    """One answer from one computer. A plural answer is one row per value."""

    computer_id: int
    computer_name: str
    is_failure: bool
    result: str  # the answer, or the error text when is_failure

    def to_dict(self) -> dict[str, Any]:
        return {
            "computer_id": self.computer_id,
            "computer_name": self.computer_name,
            "is_failure": self.is_failure,
            "result": self.result,
        }


@dataclass
class ClientQueryResponse:
    """The result of one submit or one results call. Errors are results."""

    query_id: int | None
    rows: list[ClientQueryRow]
    error: ResultError | None
    connection: str | None
    server: str
    backend: str
    elapsed_ms: float

    @property
    def ok(self) -> bool:
        return self.error is None

    def to_dict(self) -> dict[str, Any]:
        return {
            "query_id": self.query_id,
            "ok": self.ok,
            "rows": [row.to_dict() for row in self.rows],
            "error": self.error.to_dict() if self.error else None,
            "connection": self.connection,
            "server": self.server,
            "backend": self.backend,
            "elapsed_ms": self.elapsed_ms,
        }


@runtime_checkable
class ClientQueryExtras(Protocol):
    async def submit_client_query(
        self, client_relevance: str, computer_ids: Sequence[int]
    ) -> ClientQueryResponse: ...

    async def client_query_results(self, query_id: int) -> ClientQueryResponse: ...


def supports_client_query(backend: object) -> bool:
    return isinstance(backend, ClientQueryExtras)


def client_query_body(client_relevance: str, computer_ids: Sequence[int]) -> bytes:
    """Validate the targets and build the XML body. Bad input is a caller bug."""
    ids = list(computer_ids)
    if not ids:
        raise ValueError("computer_ids must name at least one computer")
    for computer_id in ids:
        if isinstance(computer_id, bool) or not isinstance(computer_id, int):
            raise TypeError(f"computer_ids must be integers, got {computer_id!r}")
    # ElementTree escapes the text, so the client relevance can hold < & etc.
    root = ET.Element("BESAPI")
    query = ET.SubElement(root, "ClientQuery")
    ET.SubElement(query, "ApplicabilityRelevance").text = "true"
    ET.SubElement(query, "QueryText").text = client_relevance
    target = ET.SubElement(query, "Target")
    for computer_id in ids:
        ET.SubElement(target, "ComputerID").text = str(computer_id)
    body: bytes = ET.tostring(root, encoding="utf-8", xml_declaration=True)
    return body


def status_problem(response: httpx.Response, backend: str) -> ResultError | None:
    """Any non-200 as a `ResultError`, with the server's own text in the message."""
    if response.status_code == 200:
        return None
    error = error_from_status(response, backend)
    # Bad REST credentials are a 401 (rest/captured/bad_password), so a 403
    # here means a missing permission even when the body does not say so.
    if error.code == "permission_denied" or response.status_code == 403:
        return replace(error, message=f"{error.message} ({PERMISSION_HINT})")
    said = server_message(response)
    if error.kind == "http" and error.code is None and said:
        # (observed) 400 "cannot get results for queries not submitted by the
        # logged user" for another operator's or an unknown query id.
        return replace(error, message=f"{error.message}: {said}")
    return error


def parse_submit(response: httpx.Response, backend: str) -> int | ResultError:
    """The query id from the ``<ID>`` element.

    The ``Resource`` URL is ignored: servers have returned it as ``http://``
    for a request made over https.
    """
    if problem := status_problem(response, backend):
        return problem
    try:
        root = SafeET.fromstring(response.text)
    except (ET.ParseError, DefusedXmlException) as exc:
        return _format_error(response, backend, f"invalid XML: {exc}")
    text = root.findtext("ClientQuery/ID")
    try:
        return int((text or "").strip())
    except ValueError:
        return _format_error(response, backend, "no integer <ClientQuery><ID> in the response")


def parse_results(response: httpx.Response, backend: str) -> list[ClientQueryRow] | ResultError:
    """Every row so far from ``?output=json`` (sent with no Content-Type)."""
    if problem := status_problem(response, backend):
        return problem
    try:
        data = json.loads(response.text)
    except (ValueError, RecursionError) as exc:  # RecursionError: absurdly deep nesting
        return _format_error(response, backend, f"invalid JSON: {exc}")
    results = data.get("results") if isinstance(data, dict) else None
    if not isinstance(results, list):
        return _format_error(response, backend, 'expected a "results" list')
    rows: list[ClientQueryRow] = []
    for item in results:
        row = _row(item)
        if row is None:
            return _format_error(response, backend, f"unexpected result row: {item!r}"[:200])
        rows.append(row)
    return rows


def _row(item: Any) -> ClientQueryRow | None:
    if not isinstance(item, dict):
        return None
    computer_id = item.get("computerID")
    name = item.get("computerName")
    failure = item.get("isFailure")
    result = item.get("result")
    if (
        isinstance(computer_id, bool)
        or not isinstance(computer_id, int)
        or not isinstance(name, str)
        or not isinstance(failure, bool)
        or not isinstance(result, str)
    ):
        return None
    return ClientQueryRow(computer_id, name, is_failure=failure, result=result)


def _format_error(response: httpx.Response, backend: str, message: str) -> ResultError:
    return ResultError(
        kind="response_format",
        backend=backend,
        http_status=response.status_code,
        message=message,
        detail=response.text[:_DETAIL_LIMIT],
    )
