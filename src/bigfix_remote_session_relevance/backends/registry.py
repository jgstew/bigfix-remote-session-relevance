"""Map a configured ``backend`` name to its class."""

from __future__ import annotations

from collections.abc import Callable

import httpx

from ..config import ConnectionConfig
from .base import Backend, TrustPolicy
from .explorer import ExplorerBackend
from .rest import RestBackend
from .saas import SaasBackend
from .webreports import WebReportsBackend

BACKEND_CLASSES: dict[str, type[Backend]] = {
    "rest": RestBackend,
    "explorer": ExplorerBackend,
    "webreports": WebReportsBackend,
    "saas": SaasBackend,
}


def backend_from_config(
    conn: ConnectionConfig,
    *,
    trust: TrustPolicy | None = None,
    prompt: Callable[[str], str] | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
) -> Backend:
    """The backend a configured connection names, built from its settings.

    It builds any backend (REST, Explorer, Web Reports, BigFix SaaS), so check
    `supports_client_query()` before using one for ClientQuery, and
    `client_query_max_targets()` for how many computers one query may target.
    """
    return BACKEND_CLASSES[conn.backend].from_config(
        conn, trust=trust, prompt=prompt, transport=transport
    )
