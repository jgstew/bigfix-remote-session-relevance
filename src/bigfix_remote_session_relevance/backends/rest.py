"""Root server REST API: ``POST /api/query``.

How the relevance must be encoded depends on what the root server does with
it, which depends on whether a BigFix Explorer is reachable from it
(observed on 11.0.7):

* With Explorer, the root server forwards the query to it. A JSON body sent
  as ``application/json+relevance`` is evaluated exactly. Form posts are
  decoded only once there, so besapi's double-quoting breaks every query
  ("This expression contained a character which is not allowed."), and a
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
"Invalid JSON" for relevance that is itself valid JSON (``"hello"``, ``1``,
``true``); either error triggers one JSON retry, which either answers or
confirms Explorer is down.
"""

from __future__ import annotations

import json
import re
import time
import urllib.parse
from collections.abc import Mapping
from typing import Any

import httpx

from ..result import SessionRelevanceResult
from ._parsing import parse_session_relevance_response
from .base import Backend
from .explorer_extras import explorer_body

JSON_RELEVANCE = "application/json+relevance"
# How long to keep using the form fallback before trying Explorer again.
EXPLORER_RECHECK_SECONDS = 300.0
_NO_EXPLORER_RE = re.compile(r"no reachable BigFix Explorer", re.IGNORECASE)
# Form errors that can mean Explorer is back (see the module docstring).
_RETRY_JSON_RE = re.compile(r"character which is not allowed|invalid json", re.IGNORECASE)


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
        if result.error is not None and _RETRY_JSON_RE.search(result.error.message):
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

    async def _post_json(self, client: httpx.AsyncClient, body: dict[str, Any]) -> httpx.Response:
        return await client.post(
            "/api/query", content=json.dumps(body), headers={"Content-Type": JSON_RELEVANCE}
        )


def _no_explorer(response: httpx.Response) -> bool:
    return response.status_code == 503 and bool(_NO_EXPLORER_RE.search(response.text))
