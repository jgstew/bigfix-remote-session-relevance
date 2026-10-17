"""BigFix SaaS: reserved in the config schema, not implemented yet.

There is no public documentation of how a SaaS tenant exposes session
relevance (auth, base URL). Until there is, a ``saas`` connection returns a
``not_implemented`` result without touching the network, and the fan-out
moves on to the next connection.
"""

from __future__ import annotations

import httpx

from ..result import ResultError, SessionRelevanceResult
from .base import Backend


class SaasBackend(Backend):
    name = "saas"

    async def evaluate(self, relevance: str) -> SessionRelevanceResult:
        error = ResultError(
            kind="not_implemented",
            backend=self.name,
            message="the BigFix SaaS backend is not implemented yet",
        )
        return SessionRelevanceResult.failure(
            relevance,
            error,
            connection=self.connection,
            deployment_id=self.deployment_id,
            backend=self.name,
            server=self.address.base_url,
            elapsed_ms=0.0,
        )

    async def _evaluate(self, client: httpx.AsyncClient, relevance: str) -> SessionRelevanceResult:
        raise NotImplementedError
