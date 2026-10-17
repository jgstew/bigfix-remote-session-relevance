"""`AsyncSessionRelevanceClient`: fan out across every configured deployment.

Default mode ``per_deployment``: connections are grouped by deployment id
(see ``deployment.py``), every group runs concurrently, and each group
returns one result from the first connection that works, tried in
``backend_preference`` order. A group fails over on outages and auth
failures, never on a relevance error (the same query fails everywhere)
and never around a changed pinned certificate (a security signal).

Mode ``all`` queries every enabled connection and returns each result.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable, Iterable, Mapping
from typing import TYPE_CHECKING, Literal, Self

import httpx

from .backends.base import Backend, TrustPolicy
from .backends.explorer_extras import explorer_body, supports_explorer_extras
from .backends.registry import BACKEND_CLASSES, backend_from_config
from .config import Config, ConnectionConfig, load_config, set_deployment_id
from .deployment import discover_deployment_id, group_key
from .exceptions import ConfigError
from .result import ResultError, SessionRelevanceResult
from .results import SessionRelevanceResults
from .trust import TrustStore

if TYPE_CHECKING:
    from types import TracebackType

log = logging.getLogger(__name__)

Mode = Literal["per_deployment", "all"]
TransportFactory = Callable[[ConnectionConfig], httpx.AsyncBaseTransport | None]

FAILOVER_KINDS = frozenset(
    {"connection", "timeout", "tls", "authentication", "http", "response_format", "not_implemented"}
)
# TLS failures that mean "this server may be an impostor": never route around them.
_NO_FAILOVER_TLS_CODES = frozenset({"pin_mismatch", "pinned_cert_invalid"})
_UNREACHABLE = frozenset({"connection", "timeout"})


class _Default:
    pass


_DEFAULT_TRUST = _Default()


def should_fail_over(error: ResultError | None) -> bool:
    if error is None or error.kind not in FAILOVER_KINDS:
        return False
    return not (error.kind == "tls" and error.code in _NO_FAILOVER_TLS_CODES)


class AsyncSessionRelevanceClient:
    """Query many BigFix connections at once. Use as an async context manager."""

    def __init__(
        self,
        config: Config | Iterable[ConnectionConfig] | None = None,
        *,
        mode: Mode = "per_deployment",
        connections: Iterable[str] | None = None,
        backends: Iterable[str] | None = None,
        trust: TrustPolicy | _Default | None = _DEFAULT_TRUST,
        prompt: Callable[[str], str] | None = None,
        max_concurrency: int = 16,
        raise_errors: bool = False,
        discover: bool = True,
        record_deployment_ids: bool = True,
        transport_factory: TransportFactory | None = None,
    ) -> None:
        if config is None:
            config = load_config()
        elif not isinstance(config, Config):
            config = Config(connections=tuple(config))
        if mode not in ("per_deployment", "all"):
            raise ValueError(f"mode must be 'per_deployment' or 'all', not {mode!r}")
        self.config = config
        self.mode: Mode = mode
        self.raise_errors = raise_errors
        self.discover = discover
        self.record_deployment_ids = record_deployment_ids
        self._prompt = prompt
        self._transport_factory = transport_factory
        self._trust: TrustPolicy | None = TrustStore() if isinstance(trust, _Default) else trust
        self._max_concurrency = max(1, max_concurrency)

        selected = list(config.enabled_connections())
        if connections is not None:
            wanted = set(connections)
            unknown = wanted - {c.name for c in config.connections}
            if unknown:
                raise ConfigError(f"no connection named {', '.join(sorted(unknown))}")
            selected = [c for c in selected if c.name in wanted]
        if backends is not None:
            kinds = set(backends)
            unknown = kinds - set(BACKEND_CLASSES)
            if unknown:
                raise ConfigError(f"unknown backend {', '.join(sorted(unknown))}")
            selected = [c for c in selected if c.backend in kinds]
        self._connections = selected
        self._deployment_ids: dict[str, str | None] = {c.name: c.deployment_id for c in selected}
        self._backends: dict[str, Backend] = {}
        self._preferred: dict[str, str] = {}
        self._discovered = False
        self._discovery_lock: asyncio.Lock | None = None
        self._semaphore: asyncio.Semaphore | None = None

    @property
    def connections(self) -> tuple[ConnectionConfig, ...]:
        return tuple(self._connections)

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        backends, self._backends = self._backends, {}
        await asyncio.gather(*(b.aclose() for b in backends.values()), return_exceptions=True)

    # -- public API -----------------------------------------------------------------

    async def evaluate(self, relevance: str) -> SessionRelevanceResults:
        """Plain session relevance on every deployment (or connection, in ``all`` mode)."""
        return await self._fan_out(relevance, lambda b: b.evaluate(relevance), capable=None)

    async def evaluate_many(self, relevances: Iterable[str]) -> list[SessionRelevanceResults]:
        return list(await asyncio.gather(*(self.evaluate(r) for r in relevances)))

    async def evaluate_explorer(
        self,
        relevance: str,
        *,
        keys: str | None = None,
        filters: Mapping[str, str] | None = None,
    ) -> SessionRelevanceResults:
        """Additive Explorer extras, on connections that can reach Explorer only."""
        explorer_body(relevance, keys, filters)  # validate once, up front

        def call(backend: Backend) -> Awaitable[SessionRelevanceResult]:
            return backend.evaluate_explorer(  # type: ignore[attr-defined, no-any-return]
                relevance, keys=keys, filters=filters
            )

        return await self._fan_out(relevance, call, capable=supports_explorer_extras)

    async def discover_deployments(self, *, force: bool = False) -> dict[str, str | None]:
        """Ask every selected connection for its deployment id (and record it)."""
        self._ensure_backends()
        targets = [
            c
            for c in self._connections
            if c.backend != "saas" and (force or not self._deployment_ids[c.name])
        ]
        await self._discover_for(targets)
        self._discovered = True
        return dict(self._deployment_ids)

    # -- machinery ----------------------------------------------------------------------

    def _ensure_backends(self) -> None:
        # Built sequentially (not inside the fan-out) so interactive password
        # prompts happen one at a time.
        for conn in self._connections:
            if conn.name not in self._backends:
                transport = self._transport_factory(conn) if self._transport_factory else None
                backend = backend_from_config(
                    conn, trust=self._trust, prompt=self._prompt, transport=transport
                )
                backend.deployment_id = self._deployment_ids[conn.name]
                self._backends[conn.name] = backend

    async def _limited(
        self, awaitable: Awaitable[SessionRelevanceResult]
    ) -> SessionRelevanceResult:
        if self._semaphore is None:
            self._semaphore = asyncio.Semaphore(self._max_concurrency)
        async with self._semaphore:
            return await awaitable

    async def _maybe_discover(self) -> None:
        if not self.discover or self._discovered:
            return
        if self._discovery_lock is None:
            self._discovery_lock = asyncio.Lock()
        async with self._discovery_lock:
            if self._discovered:
                return
            missing = [
                c
                for c in self._connections
                if c.backend != "saas" and not self._deployment_ids[c.name]
            ]
            await self._discover_for(missing)
            self._discovered = True

    async def _discover_for(self, targets: list[ConnectionConfig]) -> None:
        if not targets:
            return

        async def one(conn: ConnectionConfig) -> str | None:
            if self._semaphore is None:
                self._semaphore = asyncio.Semaphore(self._max_concurrency)
            async with self._semaphore:
                return await discover_deployment_id(self._backends[conn.name])

        found = await asyncio.gather(*(one(c) for c in targets))
        for conn, deployment_id in zip(targets, found, strict=True):
            if not deployment_id:
                log.info("%s: deployment id not discovered this run", conn.name)
                continue
            self._deployment_ids[conn.name] = deployment_id
            self._backends[conn.name].deployment_id = deployment_id
            self._record(conn, deployment_id)

    def _record(self, conn: ConnectionConfig, deployment_id: str) -> None:
        path = self.config.path
        if not self.record_deployment_ids or path is None or self.config.source != "file":
            return
        if conn.deployment_id == deployment_id:
            return
        try:
            set_deployment_id(path, conn.name, deployment_id)
            log.info("%s: recorded deployment_id in %s", conn.name, path)
        except (ConfigError, OSError) as exc:
            log.warning("%s: could not record deployment_id in %s: %s", conn.name, path, exc)

    def _groups(self) -> list[tuple[str, list[ConnectionConfig]]]:
        groups: dict[str, list[ConnectionConfig]] = {}
        for conn in self._connections:
            key = group_key(conn.name, self._deployment_ids[conn.name])
            groups.setdefault(key, []).append(conn)
        rank = {name: i for i, name in enumerate(self.config.backend_preference)}
        order = {c.name: i for i, c in enumerate(self._connections)}
        for key, members in groups.items():
            members.sort(
                key=lambda c, k=key: (  # type: ignore[misc]
                    0 if self._preferred.get(k) == c.name else 1,
                    rank.get(c.backend, len(rank)),
                    order[c.name],
                )
            )
        return list(groups.items())

    async def _fan_out(
        self,
        relevance: str,
        call: Callable[[Backend], Awaitable[SessionRelevanceResult]],
        *,
        capable: Callable[[Backend], bool] | None,
    ) -> SessionRelevanceResults:
        self._ensure_backends()
        if self.mode == "all":
            tasks = [
                self._limited(call(self._backends[c.name]))
                if capable is None or capable(self._backends[c.name])
                else self._unsupported(relevance, [c])
                for c in self._connections
            ]
            results = await asyncio.gather(*tasks)
        else:
            await self._maybe_discover()
            results = await asyncio.gather(
                *(
                    self._run_group(key, members, relevance, call, capable)
                    for key, members in self._groups()
                )
            )
        out = SessionRelevanceResults(results)
        if self.raise_errors:
            out.raise_for_error()
        return out

    async def _run_group(
        self,
        key: str,
        members: list[ConnectionConfig],
        relevance: str,
        call: Callable[[Backend], Awaitable[SessionRelevanceResult]],
        capable: Callable[[Backend], bool] | None,
    ) -> SessionRelevanceResult:
        candidates = [c for c in members if capable is None or capable(self._backends[c.name])]
        if not candidates:
            return await self._unsupported(relevance, members)
        attempts: list[SessionRelevanceResult] = []
        for index, conn in enumerate(candidates):
            result = await self._limited(call(self._backends[conn.name]))
            if result.ok:
                self._preferred[key] = conn.name
                return result
            attempts.append(result)
            if not should_fail_over(result.error):
                return result
            if index + 1 < len(candidates):
                log.info(
                    "%s: %s; trying %s for this deployment",
                    conn.name,
                    result.error.kind if result.error else "error",
                    candidates[index + 1].name,
                )
        return _summarize(attempts)

    async def _unsupported(
        self, relevance: str, members: list[ConnectionConfig]
    ) -> SessionRelevanceResult:
        first = self._backends[members[0].name]
        return SessionRelevanceResult.failure(
            relevance,
            ResultError(
                kind="unsupported_feature",
                backend=first.name,
                message=(
                    "no connection for this deployment supports BigFix Explorer extras "
                    "(keys/filters); add an explorer or rest connection"
                ),
            ),
            connection=first.connection,
            deployment_id=first.deployment_id,
            backend=first.name,
            server=first.address.base_url,
        )


def _summarize(attempts: list[SessionRelevanceResult]) -> SessionRelevanceResult:
    """One result for a deployment where every connection failed."""
    if len(attempts) == 1:
        return attempts[0]
    primary = next(
        (r for r in attempts if r.error is not None and r.error.kind not in _UNREACHABLE),
        attempts[0],
    )
    if primary.error is None:  # pragma: no cover - attempts are all failures
        return primary
    tried = ", ".join(f"{r.connection}: {r.error.kind if r.error else 'ok'}" for r in attempts)
    error = ResultError(
        kind=primary.error.kind,
        code=primary.error.code,
        backend=primary.error.backend,
        http_status=primary.error.http_status,
        detail=primary.error.detail,
        message=f"{primary.error.message} (tried {tried})",
    )
    return primary.replace(error=error)
