"""`AsyncSessionRelevanceClient`: fan out across every configured deployment.

Default mode ``per_deployment``: connections are grouped by deployment id
(see ``deployment.py``), every group runs concurrently, and each group
returns one result from the first connection that works, tried in
``backend_preference`` order. A group fails over on outages and auth
failures, never on a session relevance error (the same query fails everywhere)
and never around a changed pinned certificate (a security signal).

Mode ``all`` queries every enabled connection and returns each result.

The ``*_stream`` methods yield the same results in completion order, each
the moment it lands, so one slow deployment does not hold up the others.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncGenerator, AsyncIterator, Awaitable, Callable, Iterable, Mapping
from typing import TYPE_CHECKING, Any, Literal, Self

import httpx

from .backends.base import Backend, TrustPolicy
from .backends.explorer_extras import explorer_body, supports_explorer_extras
from .backends.registry import BACKEND_CLASSES, backend_from_config
from .backends.saas import SaasBackend, SaasSessionPool
from .config import (
    Config,
    ConnectionConfig,
    load_config,
    record_local_deployment_id,
    set_deployment_id,
)
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
        # BigFix SaaS connections of one account share one sign-in: --setup
        # saves one per server, and failed logins lock the account for good.
        self._saas_sessions = SaasSessionPool()
        self._preferred: dict[str, str] = {}
        self._discovered = False
        self._local_settled = False
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

    async def evaluate(self, session_relevance: str) -> SessionRelevanceResults:
        """Plain session relevance on every deployment (or connection, in ``all`` mode)."""
        return await self._collect(
            self._stream(
                session_relevance, self._plain(session_relevance), capable=None, streaming=False
            )
        )

    def evaluate_stream(self, session_relevance: str) -> AsyncGenerator[SessionRelevanceResult]:
        """`evaluate`, yielding each result as it lands (completion order).

        Abandoning the iteration early (``break``, or ``aclose()``) cancels
        the queries still running. With ``raise_errors`` it raises at the
        first failed result.
        """
        return self._stream(session_relevance, self._plain(session_relevance), capable=None)

    async def evaluate_many(
        self, session_relevances: Iterable[str]
    ) -> list[SessionRelevanceResults]:
        return list(await asyncio.gather(*(self.evaluate(r) for r in session_relevances)))

    async def evaluate_explorer(
        self,
        session_relevance: str,
        *,
        keys: str | None = None,
        filters: Mapping[str, str] | None = None,
    ) -> SessionRelevanceResults:
        """Additive Explorer extras, on connections that can reach Explorer only."""
        call = self._explorer(session_relevance, keys, filters)
        return await self._collect(
            self._stream(session_relevance, call, capable=supports_explorer_extras, streaming=False)
        )

    def evaluate_explorer_stream(
        self,
        session_relevance: str,
        *,
        keys: str | None = None,
        filters: Mapping[str, str] | None = None,
    ) -> AsyncGenerator[SessionRelevanceResult]:
        """`evaluate_explorer`, yielding each result as it lands. Invalid
        keys or filters raise here, before anything is queried."""
        call = self._explorer(session_relevance, keys, filters)
        return self._stream(session_relevance, call, capable=supports_explorer_extras)

    def result_count(self) -> int | None:
        """How many results an evaluation returns: one per deployment, or per
        connection in ``all`` mode. ``None`` while that still depends on
        deployment ids not discovered yet (the first evaluation finds them),
        or on whether the automatic local root server connection works."""
        if not self._local_settled and self._droppable_local():
            return None
        if self.mode == "all":
            return len(self._connections)
        if self._discovery_pending():
            return None
        return len(self._groups())

    async def discover_deployments(self, *, force: bool = False) -> dict[str, str | None]:
        """Ask every selected connection for its deployment id (and record it)."""
        self._ensure_backends()
        await self._settle_local_credentials()
        targets = [c for c in self._connections if force or not self._deployment_ids[c.name]]
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
                if isinstance(backend, SaasBackend):
                    self._saas_sessions.attach(backend)
                self._backends[conn.name] = backend

    def _droppable_local(self) -> list[ConnectionConfig]:
        """Automatic local root server connections, when something else is selected."""
        auto = [c for c in self._connections if c.auto_detected]
        return auto if len(auto) < len(self._connections) else []

    async def _settle_local_credentials(self) -> None:
        # The automatic connection is an extra: if its credentials cannot be
        # read, leave it out rather than turn every run partial (exit 3).
        # Alone, it stays, so its error says what to do.
        if self._local_settled:
            return
        for conn in self._droppable_local():
            problem = await self._backends[conn.name].resolve_credentials()
            if problem is not None and conn in self._connections:
                log.warning("%s: not used: %s", conn.name, problem.message)
                self._connections.remove(conn)
        self._local_settled = True

    async def _limited(
        self, awaitable: Awaitable[SessionRelevanceResult]
    ) -> SessionRelevanceResult:
        if self._semaphore is None:
            self._semaphore = asyncio.Semaphore(self._max_concurrency)
        async with self._semaphore:
            return await awaitable

    def _discovery_pending(self) -> bool:
        return (
            self.discover
            and not self._discovered
            and any(not self._deployment_ids[c.name] for c in self._connections)
        )

    async def _maybe_discover(self) -> None:
        if not self.discover or self._discovered:
            return
        if self._discovery_lock is None:
            self._discovery_lock = asyncio.Lock()
        async with self._discovery_lock:
            if self._discovered:
                return
            missing = [c for c in self._connections if not self._deployment_ids[c.name]]
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
        if conn.auto_detected and self.record_deployment_ids:
            # Not in the config file: cached next to it instead.
            server = self._backends[conn.name].address.base_url
            try:
                record_local_deployment_id(server, deployment_id)
            except OSError as exc:
                log.warning("%s: could not cache deployment_id: %s", conn.name, exc)
            return
        if (
            not self.record_deployment_ids
            or path is None
            or self.config.source != "file"
            or conn.auto_detected
        ):
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

    @staticmethod
    def _plain(session_relevance: str) -> Callable[[Backend], Awaitable[SessionRelevanceResult]]:
        return lambda backend: backend.evaluate(session_relevance)

    @staticmethod
    def _explorer(
        session_relevance: str, keys: str | None, filters: Mapping[str, str] | None
    ) -> Callable[[Backend], Awaitable[SessionRelevanceResult]]:
        explorer_body(session_relevance, keys, filters)  # validate once, up front

        def call(backend: Backend) -> Awaitable[SessionRelevanceResult]:
            return backend.evaluate_explorer(  # type: ignore[attr-defined, no-any-return]
                session_relevance, keys=keys, filters=filters
            )

        return call

    async def _collect(
        self, stream: AsyncIterator[SessionRelevanceResult]
    ) -> SessionRelevanceResults:
        landed = [result async for result in stream]
        # Back in group (or connection) order, whatever order they landed in.
        if self.mode == "all":
            position = {c.name: i for i, c in enumerate(self._connections)}
        else:
            position = {c.name: i for i, (_, members) in enumerate(self._groups()) for c in members}
        landed.sort(key=lambda r: position.get(str(r.connection), len(position)))
        out = SessionRelevanceResults(landed)
        if self.raise_errors:
            out.raise_for_error()
        return out

    async def _stream(
        self,
        session_relevance: str,
        call: Callable[[Backend], Awaitable[SessionRelevanceResult]],
        *,
        capable: Callable[[Backend], bool] | None,
        streaming: bool = True,
    ) -> AsyncGenerator[SessionRelevanceResult]:
        """Every result as it lands.

        Deployments whose ids are already known start at once; only
        connections still being discovered wait for discovery, so one
        unreachable, undiscovered server does not hold up the rest.
        """
        self._ensure_backends()
        await self._settle_local_credentials()
        finished: asyncio.Queue[asyncio.Future[SessionRelevanceResult | None]] = asyncio.Queue()
        running: set[asyncio.Future[SessionRelevanceResult | None]] = set()
        helpers: list[asyncio.Future[None]] = []

        def spawn(work: Awaitable[SessionRelevanceResult | None]) -> None:
            task = asyncio.ensure_future(work)
            running.add(task)
            task.add_done_callback(finished.put_nowait)

        def group(
            key: str, members: list[ConnectionConfig], discovery: asyncio.Future[None] | None
        ) -> Awaitable[SessionRelevanceResult]:
            return self._run_group(key, members, session_relevance, call, capable, discovery)

        if self.mode == "all":
            for c in self._connections:
                backend = self._backends[c.name]
                if capable is None or capable(backend):
                    spawn(self._limited(call(backend)))
                else:
                    spawn(self._unsupported(session_relevance, [c]))
        elif not self._discovery_pending():
            for key, members in self._groups():
                spawn(group(key, members, None))
        else:
            discovery = asyncio.ensure_future(self._maybe_discover())
            helpers.append(discovery)
            # Before discovery, a connection without an id is a group of its
            # own, keyed by name; every group keyed by an id is fully known.
            started = set()
            for key, members in self._groups():
                if self._deployment_ids[members[0].name]:
                    started.add(key)
                    spawn(group(key, members, discovery))

            async def discovered_groups() -> None:
                await discovery
                for key, members in self._groups():
                    if key not in started:
                        spawn(group(key, members, None))

            spawn(discovered_groups())

        try:
            while running:
                task = await finished.get()
                running.discard(task)
                result = task.result()
                if result is None:
                    continue
                if streaming and self.raise_errors:
                    result.raise_for_error()
                yield result
        finally:
            # A consumer that stops early (break, an exception, raise_errors)
            # must not leave queries running with nobody to collect them.
            leftovers: list[asyncio.Future[Any]] = [*running, *helpers]
            for task in leftovers:
                task.cancel()
            await asyncio.gather(*leftovers, return_exceptions=True)

    async def _run_group(
        self,
        key: str,
        members: list[ConnectionConfig],
        session_relevance: str,
        call: Callable[[Backend], Awaitable[SessionRelevanceResult]],
        capable: Callable[[Backend], bool] | None,
        discovery: asyncio.Future[None] | None = None,
    ) -> SessionRelevanceResult:
        attempts: list[SessionRelevanceResult] = []
        tried: set[str] = set()
        while True:
            candidates = [
                c
                for c in members
                if c.name not in tried and (capable is None or capable(self._backends[c.name]))
            ]
            for index, conn in enumerate(candidates):
                tried.add(conn.name)
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
            if discovery is None:
                break
            # Connections still being discovered may turn out to belong to
            # this deployment: they are its remaining failover candidates.
            await asyncio.shield(discovery)
            discovery = None
            members = dict(self._groups()).get(key, members)
        if not attempts:
            return await self._unsupported(session_relevance, members)
        return _summarize(attempts)

    async def _unsupported(
        self, session_relevance: str, members: list[ConnectionConfig]
    ) -> SessionRelevanceResult:
        first = self._backends[members[0].name]
        return SessionRelevanceResult.failure(
            session_relevance,
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
        message=f"{primary.error.message}{_TRIED}{tried})",
    )
    return primary.replace(error=error)


_TRIED = " (tried "


def without_attempts(message: str) -> str:
    """An error message minus the connections `_summarize` lists as tried,
    which differ per deployment even when the failure itself is the same."""
    head, sep, _ = message.rpartition(_TRIED)
    return head if sep and message.endswith(")") else message
