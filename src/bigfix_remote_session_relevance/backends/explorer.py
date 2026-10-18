"""BigFix Explorer: ``POST /api/relevance`` with a JSON body."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import httpx

from ..result import ResultError, SessionRelevanceResult
from ._parsing import parse_session_relevance_response
from .base import Backend
from .explorer_extras import explorer_body


class ExplorerBackend(Backend):
    name = "explorer"

    async def _evaluate(
        self, client: httpx.AsyncClient, session_relevance: str
    ) -> SessionRelevanceResult:
        return await self._post(client, session_relevance, {"relevance": session_relevance})

    async def evaluate_explorer(
        self,
        session_relevance: str,
        *,
        keys: str | None = None,
        filters: Mapping[str, str] | None = None,
    ) -> SessionRelevanceResult:
        """Evaluate with Explorer ``keys``/``filters`` (additive; see explorer_extras)."""
        body = explorer_body(session_relevance, keys, filters)
        return await self._run(
            session_relevance, lambda client: self._post(client, session_relevance, body)
        )

    async def _post(
        self, client: httpx.AsyncClient, session_relevance: str, body: dict[str, Any]
    ) -> SessionRelevanceResult:
        response = await client.post("/api/relevance", json=body)
        result = parse_session_relevance_response(session_relevance, response, self.name)
        return await self._explain_unavailable(client, result, response)

    async def _explain_unavailable(
        self, client: httpx.AsyncClient, result: SessionRelevanceResult, response: httpx.Response
    ) -> SessionRelevanceResult:
        """Say *why* Explorer is not answering.

        While Explorer starts, or after it loses its root server connection, it
        answers POSTs with 405 ("Only HTTP GETs are allowed.") or 401 ("temporarily
        unavailable"), and reports its state on ``GET /``, e.g.
        ``{"status": "Starting", "rootServerConnection": "Invalid Explorer
        Certificate"}``. That state goes into the error message.
        """
        error = result.error
        if error is None:
            return result
        if response.status_code != 405 and error.code != "service_unavailable":
            return result
        message = (
            error.message
            if error.code == "service_unavailable"
            else "BigFix Explorer is not accepting queries"
        )
        status = await self._status(client)
        if status:
            details = "; ".join(
                f"{label}: {status[key]}"
                for key, label in (
                    ("status", "Explorer status"),
                    ("rootServerConnection", "root server connection"),
                )
                if status.get(key)
            )
            if details:
                message = f"{message} ({details})"
        return result.replace(
            error=ResultError(
                kind="http",
                code="service_unavailable",
                backend=self.name,
                http_status=error.http_status,
                message=message,
                detail=error.detail,
            )
        )

    async def _status(self, client: httpx.AsyncClient) -> dict[str, Any] | None:
        try:
            response = await client.get("/")
            data = response.json()
        except (httpx.HTTPError, ValueError):
            return None
        return data if isinstance(data, dict) and "status" in data else None
