"""BigFix SaaS: ``POST https://api.bigfix.com/bfproxy/v2/relevance``.

Observed 2026-10-17 (live login, the service's OpenAPI spec, and the
bigfix-saas MCP server, which pins the same choices):

* ``server`` is the web UI host (``login.bigfix.com``, ``eulogin.bigfix.com``)
  or the API host; requests always go to the API host, ``login.`` -> ``api.``.
  The host is allowlisted because the login POST carries the password.
* Every request is a POST of ``{"requestId": uuid4, "timestamp": epoch-ms,
  "data": ...}`` (plus ``sid`` to pick a BigFix server) with the header
  ``x-bfnow-csrf-protection: 1``; without it the gateway answers 403. A
  reused ``requestId`` is rejected as a replay (409).
* Sign-in is ``/auth/v1/user/login`` with ``{email, password[, totp]}``. The
  session is the ``accessToken`` / ``refreshToken`` cookies it sets; the body
  carries ``iat``/``exp`` and the account's servers under ``data.pids.bf``.
  v1 rather than v2: v1 does not register a gateway session (v2 counts
  against a cap of 5 concurrent sessions, and a v2 login here hung).
* ``/auth/v1/token/refresh`` (no data) renews the cookies, even after the
  access token expired.
* Answers come back typed like the REST API's:
  ``{"data": {"answer": [...], "evaltime", "count", "plural", "type"}}``;
  relevance errors are ``{"data": {"error": "..."}}`` with HTTP 200.
* 100 failed logins lock the account for good, so a rejected login is never
  sent again. The only second attempt is the server's own ``totp_required``
  challenge, answered through ``totp_prompt``.
* Backends of one account (API host + email + password) attached to the same
  `SaasSessionPool` share one `SaasSession`: one login, one cached failure and
  one refresh for all of them. ``--setup`` saves one connection per ``sid``,
  so without this an account with N servers would cost N logins per run, and
  a wrong password N failed logins per run.

SaaS ``prefilter`` uses BigFix's criteria DSL, not relevance strings, so this
backend does not implement the Explorer extras.

BigFix Query (fast query, ``ClientQueryExtras``), observed 2026-10-26 on one
Windows agent (client 11.0.5.204) and in the be-bfproxy-service source:

* Submit is core v2 ``clientquery/create`` with ``data = {queryText,
  applicabilityRelevance, useClientContext?, target}`` and answers
  ``{"clientQueryId": "16"}`` (a string). Core stores the query in the
  operator's console history and notifies the console as agents answer.
  ``queryTitle`` / ``description`` / ``category`` / ``parameters`` would make
  it a saved query, so none are sent.
* ``target`` takes ONE of ``computerId`` (one integer, which bfproxy sends
  to the root server as ``<Target><ComputerID>``) / ``computerName`` /
  ``customRelevance`` / ``computerGroup``. bfproxy drops a falsy
  ``computerId``, leaving no target: every device the operator can see, so
  ids must be positive. A ``customRelevance`` target, even ``computer id =
  N``, was never answered by an agent that answered a ``computerId`` target
  in seconds, so several ids cannot be one query: a submit takes one id.
* ``useClientContext: true`` makes fixlet inspectors work: ``relevant
  fixlets of sites`` fails with ``InspectorFixletContextError`` without it.
* Core answers every upstream failure with a bare 500, after it may already
  have submitted to the root server, so a submit is never resent except
  after a 401 (the gateway refusing the cookie, before core sees it).
* Results are bfproxy v1 ``clientquery/listresults`` with ``data = {queryId,
  start, count, stats}``, paged; ``stats`` adds ``totalResults``.
"""

from __future__ import annotations

import asyncio
import hashlib
import re
import time
import uuid
from collections.abc import Callable, Sequence
from dataclasses import replace
from typing import TYPE_CHECKING, Any

import httpx

from ..result import ResultError, SessionRelevanceResult
from ..server_address import saas_api_address
from ..value_types import loads_json
from ._parsing import _float_or_none, _format_error, _session_relevance_error, raw_from_response
from .base import Backend, error_from_status
from .client_query import (
    ClientQueryResponse,
    ClientQueryRow,
    Outcome,
    check_computer_ids,
    check_query_id,
    check_use_client_context,
    response_from,
    row_from_json,
)

_SID_KEY = re.compile(r"[0-9A-Za-z_-]+")

if TYPE_CHECKING:
    from ..config import ConnectionConfig

LOGIN_PATH = "/auth/v1/user/login"
REFRESH_PATH = "/auth/v1/token/refresh"
RELEVANCE_PATH = "/bfproxy/v2/relevance"
CLIENT_QUERY_CREATE_PATH = "/core/v2/clientquery/create"
CLIENT_QUERY_RESULTS_PATH = "/bfproxy/v1/clientquery/listresults"
# Rows per listresults call (the bigfix-saas MCP server's default maximum).
CLIENT_QUERY_PAGE = 1000
# Renew this long before the session's expiry rather than racing it.
EXPIRY_SLACK_S = 30.0

_LOGIN_SIGNAL_MESSAGES = {
    "totp_required": "this account requires a TOTP code (MFA); run interactively to enter it",
    "activate_mfa_required": "MFA must be activated for this account in the BigFix SaaS web UI",
    "password_change_required": "the password must be changed in the BigFix SaaS web UI",
    "mfa_mismatch": "the TOTP code was rejected",
    "max_concurrent_sessions_reached": "the account has reached its concurrent session limit",
}

__all__ = [
    "SaasBackend",
    "SaasSession",
    "SaasSessionPool",
    "parse_saas_session_relevance",
    "saas_api_address",
]


class SaasSession:
    """One sign-in to a BigFix SaaS account, shared by that account's backends.

    Holds what a login produced (the cookies, the expiry, the account's
    servers) or the login failure, behind a lock, so concurrent backends wait
    for a single login and reuse its success or its failure. ``generation``
    counts sign-ins and renewals: a backend copies the cookies into its own
    HTTP client when it is behind, and skips a renewal that another backend
    already made (the refresh token appears to be single-use).
    """

    def __init__(self) -> None:
        self.cookies = httpx.Cookies()
        self.until: float | None = None  # monotonic deadline
        self.failure: ResultError | None = None
        self.servers: tuple[str, ...] = ()
        self.generation = 0
        self.lock = asyncio.Lock()

    def fresh(self) -> bool:
        return (
            self.failure is None
            and self.until is not None
            and time.monotonic() < self.until - EXPIRY_SLACK_S
        )


class SaasSessionPool:
    """Sessions keyed by account: API host, email (any case) and password.

    `AsyncSessionRelevanceClient` owns one and attaches every SaaS backend it
    builds. The password is part of the key (as a digest), so a connection
    with a different password never borrows, or poisons, another's session.
    """

    def __init__(self) -> None:
        self._sessions: dict[tuple[str, str, str], SaasSession] = {}

    def attach(self, backend: SaasBackend) -> None:
        """Share the account's session. Call before the backend's first request."""
        backend._session = self._sessions.setdefault(backend._account_key(), SaasSession())


class SaasBackend(Backend):
    name = "saas"
    supports_token = False
    # Fast query targets one computer per query (client_query_max_targets()).
    client_query_max_targets: int | None = 1

    def __init__(
        self,
        server: Any,
        *,
        sid: str | None = None,
        totp_prompt: Callable[[str], str] | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(server, **kwargs)
        self.address = saas_api_address(self.address)
        self.sid = sid
        self._totp_prompt = totp_prompt
        self._session = SaasSession()  # private unless a SaasSessionPool attaches it
        self._synced: tuple[httpx.AsyncClient, int] | None = None

    @property
    def servers(self) -> tuple[str, ...]:
        """The account's BigFix servers (``sid`` values), known after sign-in."""
        return self._session.servers

    def _account_key(self) -> tuple[str, str, str]:
        password = hashlib.sha256((self._password or "").encode()).hexdigest()
        # (observed) The service signs in the same account whatever the
        # email's case, so casings share one session and one cached failure.
        return (self.address.base_url, (self.username or "").lower(), password)

    @classmethod
    def _config_kwargs(
        cls, conn: ConnectionConfig, prompt: Callable[[str], str] | None
    ) -> dict[str, Any]:
        return {"sid": conn.sid, "totp_prompt": prompt}

    # Credentials travel in the login body; the session in cookies.
    def _basic_auth(self) -> httpx.BasicAuth | None:
        return None

    def _request_headers(self) -> dict[str, str]:
        return {"Accept": "application/json", "x-bfnow-csrf-protection": "1"}

    def _auth_problem(self) -> ResultError | None:
        if not self.username or self._password is None:
            return ResultError(
                kind="authentication",
                backend=self.name,
                message=(
                    "BigFix SaaS needs a username (email) and a password "
                    "(set password_env, password, or run interactively)"
                ),
            )
        return None

    async def _evaluate(
        self, client: httpx.AsyncClient, session_relevance: str
    ) -> SessionRelevanceResult:
        response = await self._signed_in_post(client, RELEVANCE_PATH, {"query": session_relevance})
        if isinstance(response, ResultError):
            return SessionRelevanceResult.failure(session_relevance, response)
        return parse_saas_session_relevance(session_relevance, response, self.name)

    async def _signed_in_post(
        self, client: httpx.AsyncClient, path: str, data: dict[str, Any]
    ) -> httpx.Response | ResultError:
        """POST to this backend's server, signing in first and renewing once on a 401.

        A 401 is the gateway refusing the cookie before the request reaches
        the service, so the one resend cannot repeat anything.
        """
        problem = await self._ensure_session(client)
        if problem is not None:
            return problem
        generation = self._sync_cookies(client)
        response = await self._post(client, path, data, sid=self.sid)
        if response.status_code == 401:
            problem = await self._renew(client, generation)
            if problem is not None:
                return problem
            self._sync_cookies(client)
            response = await self._post(client, path, data, sid=self.sid)
        return response

    # -- BigFix Query (fast query) ----------------------------------------------------

    async def submit_client_query(
        self,
        client_relevance: str,
        computer_ids: Sequence[int],
        *,
        use_client_context: bool | None = None,
    ) -> ClientQueryResponse:
        """Submit client relevance to these computers; the response has the query id.

        The same opt-in BigFix Query as `RestBackend.submit_client_query`,
        through the BigFix SaaS fast query API. It also appears in the
        operator's console history. Unlike REST it targets one computer per
        query (see the module docstring): several ids are an
        ``unsupported_feature`` / ``multiple_targets`` error result, sent
        nowhere. Raises only for caller bugs: no computer ids, ids that are
        not positive integers, or a ``use_client_context`` that is not a bool
        or None.
        """
        ids = list(dict.fromkeys(check_computer_ids(computer_ids)))
        if any(computer_id <= 0 for computer_id in ids):
            # bfproxy drops a falsy computerId, which would leave no target
            # and reach every device the operator can see.
            raise ValueError(f"computer_ids must be positive, got {ids}")
        check_use_client_context(use_client_context)
        start = time.perf_counter()
        if len(ids) > 1:
            # Valid input that REST takes, so a result rather than a raise:
            # callers written against ClientQueryExtras keep working.
            refused = ResultError(
                kind="unsupported_feature",
                code="multiple_targets",
                backend=self.name,
                message=(
                    f"BigFix SaaS fast query targets one computer per query, got {len(ids)}"
                    " ids; submit one query per computer"
                ),
            )
            return response_from(self, None, refused, start)
        data: dict[str, Any] = {"queryText": client_relevance, "applicabilityRelevance": "true"}
        if use_client_context is not None:
            data["useClientContext"] = use_client_context
        data["target"] = {"computerId": ids[0]}

        async def _op(client: httpx.AsyncClient) -> Outcome:
            response = await self._signed_in_post(client, CLIENT_QUERY_CREATE_PATH, data)
            if isinstance(response, ResultError):
                return response
            found = _parse_create(response, self.name)
            return found if isinstance(found, ResultError) else (found, [])

        return response_from(self, None, await self._with_trust(_op), start)

    async def client_query_results(self, query_id: int) -> ClientQueryResponse:
        """Every row a submitted query has so far, reading every page."""
        check_query_id(query_id)

        async def _op(client: httpx.AsyncClient) -> Outcome:
            rows: list[ClientQueryRow] = []
            while True:
                data = {
                    "queryId": str(query_id),
                    "start": len(rows),
                    "count": CLIENT_QUERY_PAGE,
                    "stats": True,
                }
                response = await self._signed_in_post(client, CLIENT_QUERY_RESULTS_PATH, data)
                if isinstance(response, ResultError):
                    return response
                page = _parse_results_page(response, self.name)
                if isinstance(page, ResultError):
                    return page
                found, total = page
                rows += found
                # A short page is the end of what is there, even if agents
                # answered meanwhile and the total grew; without a total, only
                # a short page tells.
                if len(found) < CLIENT_QUERY_PAGE or (total is not None and len(rows) >= total):
                    return (query_id, rows)

        start = time.perf_counter()
        return response_from(self, query_id, await self._with_trust(_op), start)

    # -- session ----------------------------------------------------------------------

    def _sync_cookies(self, client: httpx.AsyncClient) -> int:
        """Give this client the session's current cookies; return their generation."""
        session = self._session
        if self._synced != (client, session.generation):
            client.cookies = session.cookies
            self._synced = (client, session.generation)
        return session.generation

    async def _ensure_session(self, client: httpx.AsyncClient) -> ResultError | None:
        session = self._session
        if session.fresh():
            return None
        async with session.lock:  # whoever waited here reuses the first login's outcome
            if session.failure is not None:
                return session.failure
            if session.until is None:
                return await self._login(client)
            if session.fresh():
                return None
            return await self._refresh(client)

    async def _renew(self, client: httpx.AsyncClient, generation: int) -> ResultError | None:
        """After a 401 on a request sent with ``generation``'s cookies."""
        session = self._session
        async with session.lock:
            if session.failure is not None:
                return session.failure
            if session.generation != generation:
                return None  # another backend renewed the session meanwhile
            return await self._refresh(client)

    async def _refresh(self, client: httpx.AsyncClient) -> ResultError | None:
        """Refresh the cookies; if that fails, sign in again. Holds the lock.

        A fresh login is safe here: it only happens after an earlier login
        with these credentials succeeded, so it cannot add to a failure count.
        """
        self._sync_cookies(client)
        response = await self._post(client, REFRESH_PATH, None)
        if response.status_code == 200 and self._accept_session(client, response):
            return None
        self._session.until = None
        return await self._login(client)

    async def _login(
        self, client: httpx.AsyncClient, totp: str | None = None
    ) -> ResultError | None:
        """Sign in. Holds the session lock, so at most one login per account runs."""
        data: dict[str, Any] = {"email": self.username or "", "password": self._password or ""}
        if totp is not None:
            data["totp"] = totp
        response = await self._post(client, LOGIN_PATH, data)
        if response.status_code == 200 and self._accept_session(client, response):
            return None
        signal = _error_message(response)
        if (
            response.status_code == 401
            and signal == "totp_required"
            and totp is None
            and self._totp_prompt is not None
        ):
            # The server's own challenge, not a retry of a failed login.
            code = self._totp_prompt(f"TOTP code for {self.username} (BigFix SaaS): ").strip()
            return await self._login(client, totp=code)
        if response.status_code >= 500:
            return error_from_status(response, self.name)  # transient: may retry later
        known = signal in _LOGIN_SIGNAL_MESSAGES
        error = ResultError(
            kind="authentication",
            code=signal if known else "login_failed",
            backend=self.name,
            http_status=response.status_code,
            message=_LOGIN_SIGNAL_MESSAGES[signal] if known and signal else "credentials rejected",
            detail=signal,
        )
        # Never POST these credentials again, from this backend or any other
        # sharing the session: repeated failures lock the account for good.
        self._session.failure = error
        return error

    def _accept_session(self, client: httpx.AsyncClient, response: httpx.Response) -> bool:
        try:
            body = response.json()
        except ValueError:
            return False
        data = body.get("data") if isinstance(body, dict) else None
        if not isinstance(data, dict):
            return False
        # Lifetime from the server's own iat/exp, timed on our clock, so clock
        # skew between here and the service does not matter.
        iat, exp = data.get("iat"), data.get("exp")
        lifetime = float(exp - iat) if isinstance(iat, int) and isinstance(exp, int) else 3600.0
        session = self._session
        session.until = time.monotonic() + max(lifetime, 0.0)
        pids = data.get("pids")
        if isinstance(pids, dict) and isinstance(pids.get("bf"), dict):
            # A sid is shown by --setup and becomes part of a connection name.
            session.servers = tuple(f"bf{key}" for key in pids["bf"] if _SID_KEY.fullmatch(key))
        session.cookies = httpx.Cookies(client.cookies)  # a copy: each client has its own jar
        session.generation += 1
        self._synced = (client, session.generation)
        return True

    async def _post(
        self,
        client: httpx.AsyncClient,
        path: str,
        data: dict[str, Any] | None,
        *,
        sid: str | None = None,
    ) -> httpx.Response:
        envelope: dict[str, Any] = {
            "requestId": str(uuid.uuid4()),  # a reused id is rejected as a replay
            "timestamp": str(int(time.time() * 1000)),
            "data": data,
        }
        if sid is not None:
            envelope["sid"] = sid
        return await client.post(path, json=envelope)


def _client_query_data(
    response: httpx.Response, backend: str, *, submit: bool = False
) -> dict[str, Any] | ResultError:
    """The envelope's ``data`` object, or the error a non-200 or bad body means."""
    if response.status_code != 200:
        error = error_from_status(response, backend)
        message = _error_message(response)
        if message:
            error = replace(error, message=message)
        if submit and response.status_code == 500:
            error = replace(
                error,
                message=(
                    f"{error.message} (BigFix SaaS answers 500 for any failed client query"
                    " submit, including client relevance the root server rejects)"
                ),
            )
        return error
    try:
        body = loads_json(response.text)
    except ValueError as exc:
        return _client_query_format_error(response, backend, f"invalid JSON: {exc}")
    data = body.get("data") if isinstance(body, dict) else None
    if not isinstance(data, dict):
        return _client_query_format_error(response, backend, 'expected a "data" object')
    return data


def _parse_create(response: httpx.Response, backend: str) -> int | ResultError:
    data = _client_query_data(response, backend, submit=True)
    if isinstance(data, ResultError):
        return data
    found = data.get("clientQueryId")
    # The id comes as a string ("2"); ClientQueryResponse.query_id is an int.
    # ASCII digits only: str.isdigit() also accepts "²", which int() rejects.
    if isinstance(found, str) and re.fullmatch(r"[0-9]+", found.strip()):
        found = int(found)
    if isinstance(found, bool) or not isinstance(found, int) or found <= 0:
        return _client_query_format_error(response, backend, "no integer clientQueryId")
    return found


def _parse_results_page(
    response: httpx.Response, backend: str
) -> tuple[list[ClientQueryRow], int | None] | ResultError:
    data = _client_query_data(response, backend)
    if isinstance(data, ResultError):
        return data
    results = data.get("results")
    if not isinstance(results, list):
        return _client_query_format_error(response, backend, 'expected a "results" list')
    rows: list[ClientQueryRow] = []
    for item in results:
        row = row_from_json(item, id_key="computerId")
        if row is None:
            message = f"unexpected result row: {item!r}"[:200]
            return _client_query_format_error(response, backend, message)
        rows.append(row)
    total = data.get("totalResults")
    return rows, total if isinstance(total, int) and not isinstance(total, bool) else None


def _client_query_format_error(response: httpx.Response, backend: str, message: str) -> ResultError:
    return ResultError(
        kind="response_format",
        backend=backend,
        http_status=response.status_code,
        message=message,
        detail=response.text[:500],
    )


def _error_message(response: httpx.Response) -> str | None:
    try:
        body = response.json()
    except ValueError:
        return None
    data = body.get("data") if isinstance(body, dict) else None
    if isinstance(data, dict) and isinstance(data.get("errorMessage"), str):
        return str(data["errorMessage"])
    return None


def parse_saas_session_relevance(
    session_relevance: str, response: httpx.Response, backend: str
) -> SessionRelevanceResult:
    raw = raw_from_response(response)
    if response.status_code in (401, 403):
        return SessionRelevanceResult.failure(
            session_relevance, error_from_status(response, backend), raw=raw
        )
    if raw.format != "json":
        if response.status_code >= 400:
            return SessionRelevanceResult.failure(
                session_relevance, error_from_status(response, backend), raw=raw
            )
        return _format_error(session_relevance, raw, backend, "expected JSON from BigFix SaaS")
    try:
        body = loads_json(raw.text)
    except ValueError as exc:
        return _format_error(session_relevance, raw, backend, f"invalid JSON: {exc}")
    data = body.get("data") if isinstance(body, dict) else None
    if response.status_code >= 400:
        error = error_from_status(response, backend)
        message = _error_message(response)
        if message:
            error = ResultError(
                kind=error.kind,
                code=error.code,
                backend=backend,
                http_status=error.http_status,
                message=message,
                detail=error.detail,
            )
        return SessionRelevanceResult.failure(session_relevance, error, raw=raw)
    if isinstance(data, dict):
        if isinstance(data.get("error"), str):
            return _session_relevance_error(session_relevance, data["error"], raw, backend)
        if "answer" in data:
            values = data["answer"] if isinstance(data["answer"], list) else [data["answer"]]
            plural = data.get("plural")
            return SessionRelevanceResult.from_values(
                session_relevance,
                values,
                type=data.get("type"),
                plural=plural if isinstance(plural, bool) else None,
                evaluation_time_ms=_float_or_none(data.get("evaltime")),
                raw=raw,
            )
    return _format_error(session_relevance, raw, backend, "BigFix SaaS response has no answer")
