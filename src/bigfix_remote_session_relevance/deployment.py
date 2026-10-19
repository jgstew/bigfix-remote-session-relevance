"""Deployment identity: which connections are the same BigFix deployment.

A deployment is identified by the SHA-256 of its gather URL, asked of the
server itself (``sha256 of gather url of bes license``). REST, Explorer and
Web Reports connections that report the same id are one deployment, so the
default fan-out queries it once. Only the hash is ever stored.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable

from .backends.base import Backend

DEPLOYMENT_ID_SESSION_RELEVANCE = "sha256 of gather url of bes license"
GATHER_URL_RELEVANCE = "gather url of bes license"
_SHA256_HEX = re.compile(r"[0-9a-f]{64}")


def deployment_id_from_hashes(hashes: Iterable[str]) -> str | None:
    """One id per connection.

    A Web Reports server aggregating several datasources reports several
    hashes; it gets a composite ``multi:`` id so it is never mistaken for a
    duplicate of any single deployment. An answer that is not a SHA-256
    (hex) means no id at all: the id is printed, written to the config and
    used for grouping, and it comes from the server.
    """
    unique = sorted({h.strip().lower() for h in hashes if h and h.strip()})
    if not unique or not all(_SHA256_HEX.fullmatch(h) for h in unique):
        return None
    if len(unique) == 1:
        return unique[0]
    return "multi:" + hashlib.sha256(",".join(unique).encode()).hexdigest()


def group_key(connection: str, deployment_id: str | None) -> str:
    return deployment_id or f"connection:{connection}"


async def discover_deployment_id(backend: Backend) -> str | None:
    """Ask a connection for its deployment id; None when it cannot say."""
    result = await backend.evaluate(DEPLOYMENT_ID_SESSION_RELEVANCE)
    if result.ok:
        return deployment_id_from_hashes(str(a) for a in result.answers)
    if result.error is not None and result.error.kind == "session_relevance":
        # Older servers lack `sha256 of <string>`: hash the gather URL here,
        # the same way (UTF-8, lowercase hex), so ids agree across versions.
        fallback = await backend.evaluate(GATHER_URL_RELEVANCE)
        if fallback.ok:
            return deployment_id_from_hashes(
                hashlib.sha256(str(url).encode("utf-8")).hexdigest() for url in fallback.answers
            )
    return None
