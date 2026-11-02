"""Map a configured ``backend`` name to its class."""

from __future__ import annotations

from collections.abc import Callable

import httpx

from ..config import ConnectionConfig
from ..prompts import Prompt
from ..secrets import DEFAULT_SECRET_STORE, SecretStore
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
    prompt: Prompt | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
    secrets: SecretStore | None = DEFAULT_SECRET_STORE,
    save_prompted: Callable[[str], bool] | None = None,
) -> Backend:
    """The backend a configured connection names, built from its settings.

    It builds any backend (REST, Explorer, Web Reports, BigFix SaaS), so check
    `supports_client_query()` before using one for ClientQuery, and
    `client_query_max_targets()` for how many computers one query may target.
    A missing password is asked here, so ``prompt`` must answer at once; use
    `abackend_from_config` for an async prompt (a GUI dialog).
    """
    return BACKEND_CLASSES[conn.backend].from_config(
        conn,
        trust=trust,
        prompt=prompt,
        transport=transport,
        secrets=secrets,
        save_prompted=save_prompted,
    )


async def abackend_from_config(
    conn: ConnectionConfig,
    *,
    trust: TrustPolicy | None = None,
    prompt: Prompt | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
    secrets: SecretStore | None = DEFAULT_SECRET_STORE,
    save_prompted: Callable[[str], bool] | None = None,
) -> Backend:
    """`backend_from_config`, awaiting ``prompt`` if it is async (a GUI dialog)."""
    return await BACKEND_CLASSES[conn.backend].afrom_config(
        conn,
        trust=trust,
        prompt=prompt,
        transport=transport,
        secrets=secrets,
        save_prompted=save_prompted,
    )
