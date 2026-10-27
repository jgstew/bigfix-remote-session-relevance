"""BigFix Query (ClientQuery): send client relevance to agents through REST.

Strictly additive and opt-in, like ``explorer_extras``. Plain ``evaluate()``
is session relevance and never touches this. Here the expression is client
relevance, evaluated by each targeted agent, so the parameter is named
``client_relevance``.

This is a two-call wire layer: ``POST /api/clientquery`` submits and returns
the query id, ``GET /api/clientqueryresults/{id}`` returns every row so far
(results accumulate as agents answer). Polling is left to the caller.
`RestBackend` implements it (observed on 11.0.x), and `SaasBackend` through
the BigFix SaaS fast query API; the validation and the response shape here
are shared, so both behave the same to a caller.
"""

from __future__ import annotations

import json
import time
from collections.abc import Sequence
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable
from xml.etree import ElementTree as ET

import defusedxml.ElementTree as SafeET
import httpx
from defusedxml import DefusedXmlException

from ..result import ResultError
from .base import error_from_status, server_message

if TYPE_CHECKING:
    from .base import Backend

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
    """BigFix Query. A backend may accept fewer targets than REST does:
    `SaasBackend` takes one computer per submit and answers several ids with
    an ``unsupported_feature`` / ``multiple_targets`` error result.
    """

    async def submit_client_query(
        self,
        client_relevance: str,
        computer_ids: Sequence[int],
        *,
        use_client_context: bool | None = None,
    ) -> ClientQueryResponse: ...

    async def client_query_results(self, query_id: int) -> ClientQueryResponse: ...


def supports_client_query(backend: object) -> bool:
    return isinstance(backend, ClientQueryExtras)


# A client query call: (query id, rows so far), or the server's error.
Outcome = tuple[int | None, list[ClientQueryRow]] | ResultError


def check_computer_ids(computer_ids: Sequence[int]) -> list[int]:
    """The ids as a list. No ids, or ids that are not integers, are a caller bug."""
    ids = list(computer_ids)
    if not ids:
        raise ValueError("computer_ids must name at least one computer")
    for computer_id in ids:
        if isinstance(computer_id, bool) or not isinstance(computer_id, int):
            raise TypeError(f"computer_ids must be integers, got {computer_id!r}")
    return ids


def check_use_client_context(use_client_context: bool | None) -> None:
    if use_client_context is not None and not isinstance(use_client_context, bool):
        # A truthy "false" would silently turn client context on.
        raise TypeError(f"use_client_context must be a bool, got {use_client_context!r}")


def check_query_id(query_id: int) -> None:
    if isinstance(query_id, bool) or not isinstance(query_id, int):
        raise TypeError(f"query_id must be an integer, got {query_id!r}")


def response_from(
    backend: Backend, query_id: int | None, outcome: Outcome, start: float
) -> ClientQueryResponse:
    """The `ClientQueryResponse` for an outcome; ``start`` is a perf_counter()."""
    rows: list[ClientQueryRow] = []
    error: ResultError | None = None
    if isinstance(outcome, ResultError):
        error = outcome
    else:
        query_id, rows = outcome
    return ClientQueryResponse(
        query_id=query_id,
        rows=rows,
        error=error,
        connection=backend.connection,
        server=backend.address.base_url,
        backend=backend.name,
        elapsed_ms=round((time.perf_counter() - start) * 1000, 3),
    )


def client_query_body(
    client_relevance: str,
    computer_ids: Sequence[int],
    *,
    use_client_context: bool | None = None,
) -> bytes:
    """Validate the targets and build the XML body. Bad input is a caller bug.

    ``use_client_context`` None omits ``<UseClientContext>``, so the body is
    what servers older than the 11.0.7 schema were sent.
    """
    ids = check_computer_ids(computer_ids)
    check_use_client_context(use_client_context)
    # ElementTree escapes the text, so the client relevance can hold < & etc.
    root = ET.Element("BESAPI")
    query = ET.SubElement(root, "ClientQuery")
    ET.SubElement(query, "ApplicabilityRelevance").text = "true"
    ET.SubElement(query, "QueryText").text = client_relevance
    if use_client_context is not None:
        # ClientQuery is an xs:sequence: this must sit between QueryText and Target.
        ET.SubElement(query, "UseClientContext").text = "true" if use_client_context else "false"
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
        row = row_from_json(item)
        if row is None:
            return _format_error(response, backend, f"unexpected result row: {item!r}"[:200])
        rows.append(row)
    return rows


def row_from_json(item: Any, *, id_key: str = "computerID") -> ClientQueryRow | None:
    """One result row, or None if it is not the shape both APIs answer with.

    REST spells the id ``computerID``, BigFix SaaS ``computerId``.
    """
    if not isinstance(item, dict):
        return None
    computer_id = item.get(id_key)
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
