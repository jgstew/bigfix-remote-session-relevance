"""BigFix Explorer extras: ``keys`` (rename/nest output fields) and ``filters``.

Strictly additive. Plain ``evaluate()`` behaves identically on every backend
and never sends these; callers opt in with ``evaluate_explorer()``, which
only backends that can reach Explorer implement: `ExplorerBackend` natively,
and `RestBackend` through ``/api/query``'s forwarding to Explorer.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any, Protocol, runtime_checkable

from ..result import SessionRelevanceResult

# Explorer filter keys, one BigFix object type each (11.0.3+).
FILTER_TYPES = frozenset({"actions", "computers", "computergroups", "content", "sites"})

# keys: names of letters/digits/underscores, separated by spaces, nested with { }.
_KEYS_RE = re.compile(r"^[\sA-Za-z0-9_{}]+$")


@runtime_checkable
class ExplorerExtras(Protocol):
    async def evaluate_explorer(
        self,
        relevance: str,
        *,
        keys: str | None = None,
        filters: Mapping[str, str] | None = None,
    ) -> SessionRelevanceResult: ...


def supports_explorer_extras(backend: object) -> bool:
    return isinstance(backend, ExplorerExtras)


def explorer_body(
    relevance: str, keys: str | None, filters: Mapping[str, str] | None
) -> dict[str, Any]:
    """Validate the extras and build the JSON body. Bad input is a caller bug."""
    body: dict[str, Any] = {"relevance": relevance}
    if keys is not None:
        if not _KEYS_RE.match(keys) or keys.count("{") != keys.count("}"):
            raise ValueError(f"invalid Explorer keys {keys!r}")
        body["keys"] = keys
    if filters is not None:
        for name, condition in filters.items():
            if name not in FILTER_TYPES:
                raise ValueError(
                    f"unknown Explorer filter {name!r}; expected one of {sorted(FILTER_TYPES)}"
                )
            if not isinstance(condition, str):
                raise TypeError(f"Explorer filter {name!r} must be a relevance string")
        body["filters"] = dict(filters)
    return body
