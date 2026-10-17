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
    return BACKEND_CLASSES[conn.backend].from_config(
        conn, trust=trust, prompt=prompt, transport=transport
    )
