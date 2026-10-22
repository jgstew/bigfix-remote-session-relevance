"""Root server REST API: ``POST /api/query``.

How the relevance must be encoded depends on what the root server does with
it, which depends on whether a BigFix Explorer is reachable from it
(observed on 11.0.7):

* With Explorer, the root server forwards the query to it. A JSON body sent
  as ``application/json+relevance`` is evaluated exactly. Form posts are
  decoded only once there, so besapi's double-quoting breaks every query
  ("This expression contained a character which is not allowed.", or 400
  "Invalid JSON" when the quoted value is still valid JSON), and a
  plain form value that is itself valid JSON (``123``, ``true``,
  ``"hello"``) is rejected as "Invalid JSON".
* Without Explorer, ``application/json+relevance`` answers 503 "no reachable
  BigFix Explorer", and the form value is URL-decoded twice, so it must be
  percent-quoted first (as besapi does).

So the JSON body is tried first, and on that specific 503 the backend falls
back to the double-quoted form, remembering the choice for a while so a
server without Explorer does not pay an extra round trip on every query
(each one already costs ~3 s there: the root server waits for Explorer
before answering itself). If Explorer comes back during that window, the
form starts failing with "character which is not allowed", or with 400
"Invalid JSON" when the percent-quoted value is still valid JSON (``1``,
``true``, ``1.5``; string literals become ``%22...`` and get the first error);
either error triggers one JSON retry, which either answers or confirms
Explorer is down.
"""

from __future__ import annotations

import json
import re
import time
import urllib.parse
from collections.abc import Awaitable, Callable, Mapping, Sequence
from typing import Any
from xml.etree.ElementTree import ParseError

import defusedxml.ElementTree as SafeET
import httpx
from defusedxml import DefusedXmlException

from ..result import ResultError, SessionRelevanceResult
from ._parsing import parse_session_relevance_response
from .base import Backend, error_from_status
from .client_query import (
    ClientQueryResponse,
    ClientQueryRow,
    client_query_body,
    parse_results,
    parse_submit,
)
from .explorer_extras import explorer_body

JSON_RELEVANCE = "application/json+relevance"
# How long to keep using the form fallback before trying Explorer again.
EXPLORER_RECHECK_SECONDS = 300.0
_NO_EXPLORER_RE = re.compile(r"no reachable BigFix Explorer", re.IGNORECASE)
# Form errors that can mean Explorer is back (see the module docstring).
_RETRY_JSON_RE = re.compile(r"character which is not allowed|invalid json", re.IGNORECASE)
# A client query call: (query id, rows so far), or the server's error.
_Outcome = tuple[int | None, list[ClientQueryRow]] | ResultError
# The root server's lists of the servers registered with it: (backend, path,
# element). XML, not ?output=json: the JSON Web Reports entries carry each
# server's token, which the library has no use for.
REGISTERED_SERVER_LISTS = (
    ("explorer", "/api/explorers", "Explorer"),
    ("webreports", "/api/webreports", "WebReports"),
)


def encode_session_relevance(session_relevance: str) -> str:
    # Without Explorer the server URL-decodes the query twice, so quote it here
    # and let the form encoding quote it again; otherwise escapes such as %22
    # inside the relevance are decoded too early. Same as
    # besapi.session_relevance_xml.
    return urllib.parse.quote(session_relevance, safe=":+")


class RestBackend(Backend):
    name = "rest"

    def __init__(self, server: Any, **kwargs: Any) -> None:
        super().__init__(server, **kwargs)
        self._form_until = 0.0  # monotonic deadline for the no-Explorer fallback

    async def _evaluate(
        self, client: httpx.AsyncClient, session_relevance: str
    ) -> SessionRelevanceResult:
        if time.monotonic() >= self._form_until:
            response = await self._post_json(client, {"relevance": session_relevance})
            if not _no_explorer(response):
                return parse_session_relevance_response(session_relevance, response, self.name)
            self._form_until = time.monotonic() + EXPLORER_RECHECK_SECONDS
        response = await client.post(
            "/api/query",
            data={"relevance": encode_session_relevance(session_relevance), "output": "json"},
        )
        result = parse_session_relevance_response(session_relevance, response, self.name)
        error = result.error
        # Only the server's own answer counts: our "invalid JSON: ..." for a
        # garbled body (response_format) says nothing about Explorer.
        if (
            error is not None
            and error.kind == "session_relevance"
            and _RETRY_JSON_RE.search(error.message)
        ):
            # If Explorer came back during the fallback, the double-quoted form
            # now fails every query: "not allowed", or 400 "Invalid JSON" when
            # the form value is itself valid JSON. One JSON retry tells the two
            # apart: a 503 means Explorer is still down and the error is real.
            retry = await self._post_json(client, {"relevance": session_relevance})
            if not _no_explorer(retry):
                self._form_until = 0.0
                return parse_session_relevance_response(session_relevance, retry, self.name)
        return result

    async def evaluate_explorer(
        self,
        session_relevance: str,
        *,
        keys: str | None = None,
        filters: Mapping[str, str] | None = None,
    ) -> SessionRelevanceResult:
        """Explorer extras via the root server, which forwards to Explorer.

        There is no fallback here: without a reachable Explorer the server
        answers 503 (reported as ``http`` / ``service_unavailable``).
        """
        body = explorer_body(session_relevance, keys, filters)

        async def _op(client: httpx.AsyncClient) -> SessionRelevanceResult:
            response = await self._post_json(client, body)
            return parse_session_relevance_response(session_relevance, response, self.name)

        return await self._run(session_relevance, _op)

    async def submit_client_query(
        self, client_relevance: str, computer_ids: Sequence[int]
    ) -> ClientQueryResponse:
        """Submit client relevance to these computers; the response has the query id.

        Opt-in BigFix Query (see ``client_query``). Raises only for caller
        bugs (no computer ids, or ids that are not integers).
        """
        body = client_query_body(client_relevance, computer_ids)

        async def _op(client: httpx.AsyncClient) -> _Outcome:
            response = await client.post(
                "/api/clientquery", content=body, headers={"Content-Type": "application/xml"}
            )
            found = parse_submit(response, self.name)
            return found if isinstance(found, ResultError) else (found, [])

        return await self._client_query(None, _op)

    async def client_query_results(self, query_id: int) -> ClientQueryResponse:
        """Every row a submitted query has so far; agents keep adding rows."""
        if isinstance(query_id, bool) or not isinstance(query_id, int):
            raise TypeError(f"query_id must be an integer, got {query_id!r}")

        async def _op(client: httpx.AsyncClient) -> _Outcome:
            response = await client.get(
                f"/api/clientqueryresults/{query_id}", params={"output": "json"}
            )
            rows = parse_results(response, self.name)
            return rows if isinstance(rows, ResultError) else (query_id, rows)

        return await self._client_query(query_id, _op)

    async def _client_query(
        self,
        query_id: int | None,
        operation: Callable[[httpx.AsyncClient], Awaitable[_Outcome]],
    ) -> ClientQueryResponse:
        start = time.perf_counter()
        outcome = await self._with_trust(operation)
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
            connection=self.connection,
            server=self.address.base_url,
            backend=self.name,
            elapsed_ms=round((time.perf_counter() - start) * 1000, 3),
        )

    async def registered_servers(self) -> list[tuple[str, str]] | ResultError:
        """``(backend, url)`` for each Explorer and Web Reports server the root lists.

        Opt-in, for ``--setup`` to find servers that are not on the root
        server itself. Both lists need a master operator (anyone else gets
        403 "Action requires master operator privileges.", reported as
        ``authentication`` / ``permission_denied``). The URLs are as the root
        server has them, e.g. a short machine name that may not resolve here.
        """

        async def _op(client: httpx.AsyncClient) -> list[tuple[str, str]] | ResultError:
            found: list[tuple[str, str]] = []
            for backend, path, element in REGISTERED_SERVER_LISTS:
                urls = parse_registered_urls(await client.get(path), element, self.name)
                if isinstance(urls, ResultError):
                    return urls
                found.extend((backend, url) for url in urls)
            return found

        return await self._with_trust(_op)

    async def _post_json(self, client: httpx.AsyncClient, body: dict[str, Any]) -> httpx.Response:
        return await client.post(
            "/api/query", content=json.dumps(body), headers={"Content-Type": JSON_RELEVANCE}
        )


def parse_registered_urls(
    response: httpx.Response, element: str, backend: str
) -> list[str] | ResultError:
    """The ``<element><URL>`` texts of a BESAPI list, in order, each once.

    (observed) The root server can list its own Explorer twice.
    """
    if response.status_code != 200:
        return error_from_status(response, backend)
    try:
        root = SafeET.fromstring(response.text)
    except (ParseError, DefusedXmlException) as exc:
        return ResultError(
            kind="response_format",
            backend=backend,
            http_status=response.status_code,
            message=f"invalid XML: {exc}",
            detail=response.text[:500],
        )
    urls = ((entry.findtext("URL") or "").strip() for entry in root.iter(element))
    return list(dict.fromkeys(url for url in urls if url))


def _no_explorer(response: httpx.Response) -> bool:
    return response.status_code == 503 and bool(_NO_EXPLORER_RE.search(response.text))
