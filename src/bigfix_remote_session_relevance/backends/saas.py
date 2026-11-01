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
* Sessions are saved across runs (`SaasSessionStore`, saas_sessions.py), so
  an MFA account needs a TOTP code only when the 7-day refresh token runs
  out. The refresh token is single-use and a request sent with an expired
  access token can spend it, so a session is renewed by the wall clock before
  ``exp``, under a file lock shared with other processes; never logged out.
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
import logging
import re
import time
import uuid
from collections.abc import Callable, Sequence
from dataclasses import replace
from typing import TYPE_CHECKING, Any

import httpx

from ..result import ResultError, SessionRelevanceResult
from ..saas_sessions import (
    REFRESH_LIFETIME_S,
    SaasSessionStore,
    SavedSaasSession,
    default_saas_session_store,
    jwt_claims,
)
from ..secrets import DEFAULT_SECRET_STORE
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
    from filelock import FileLock

    from ..config import ConnectionConfig
    from ..secrets import SecretStore

log = logging.getLogger(__name__)

LOGIN_PATH = "/auth/v1/user/login"
REFRESH_PATH = "/auth/v1/token/refresh"
RELEVANCE_PATH = "/bfproxy/v2/relevance"
CLIENT_QUERY_CREATE_PATH = "/core/v2/clientquery/create"
CLIENT_QUERY_RESULTS_PATH = "/bfproxy/v1/clientquery/listresults"
# Rows per listresults call (the bigfix-saas MCP server's default maximum).
CLIENT_QUERY_PAGE = 1000
# Renew this long before the session's expiry rather than racing it.
EXPIRY_SLACK_S = 30.0
# Within this long of the refresh token's fixed expiry, sign in for a new week
# rather than refresh (a refresh cannot extend it).
REFRESH_MARGIN_S = 3600.0
# How long to wait for another process's refresh before refreshing anyway.
LOCK_TIMEOUT_S = 35.0
LOCK_POLL_S = 0.05
# The ``session_store`` default: `default_saas_session_store()`.
DEFAULT_SESSION_STORE: Any = object()
# Login answers that do not count toward the lockout and leave the refresh
# token usable: a renewal login that gets one falls back to the refresh.
_RENEWAL_LOGIN_SOFT = frozenset(
    {
        "totp_required",
        "activate_mfa_required",
        "password_change_required",
        "max_concurrent_sessions_reached",
    }
)
_TOTP_NO_SESSION = (
    "this account requires a TOTP code (MFA) and has no usable saved session; sign in"
    " interactively (--setup, or any run from a terminal) to enter one, and the session"
    " is then saved for up to 7 days"
)

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
        # Wall-clock expiries (epoch seconds) of the access token and of the
        # refresh token. The monotonic clock may stop while a device sleeps.
        self.expires_at: float | None = None
        self.refresh_exp: float | None = None
        # When these tokens were issued (or saved, if adopted): a saved pair
        # is newer only if stored later, not merely because it differs.
        self.obtained_at: float | None = None

    def fresh(self) -> bool:
        return (
            self.failure is None
            and self.until is not None
            and time.monotonic() < self.until - EXPIRY_SLACK_S
            and (self.expires_at is None or time.time() < self.expires_at - EXPIRY_SLACK_S)
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
        session_store: SaasSessionStore | None = DEFAULT_SESSION_STORE,
        reuse_saved_session: bool = True,
        **kwargs: Any,
    ) -> None:
        """``session_store``: where sessions are saved across runs (default
        `default_saas_session_store()`, off with ``BFRSR_SESSION_CACHE=0``;
        None for none). ``reuse_saved_session=False`` signs in rather than
        adopt a saved session (to check a password), and still saves the new one.
        """
        super().__init__(server, **kwargs)
        self.address = saas_api_address(self.address)
        self.sid = sid
        self._totp_prompt = totp_prompt
        self._store: SaasSessionStore | None = (
            default_saas_session_store()
            if session_store is DEFAULT_SESSION_STORE
            else session_store
        )
        self._reuse_saved = reuse_saved_session
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
        cls,
        conn: ConnectionConfig,
        prompt: Callable[[str], str] | None,
        secrets: SecretStore | None = DEFAULT_SECRET_STORE,
    ) -> dict[str, Any]:
        store = default_saas_session_store(secrets) if conn.session_cache else None
        return {"sid": conn.sid, "totp_prompt": prompt, "session_store": store}

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

    async def sign_in(self) -> ResultError | None:
        """Sign in now, if not already, without a query; the error if it failed.

        The same single login every request makes first (`servers` is set
        after it), so it never adds a login: a live session is reused and a
        rejected one is returned without sending the credentials again.

        The one exception: a cached ``totp_required`` (another backend on the
        session had no way to answer the challenge) is dropped when this one
        has a TOTP prompt. The password was accepted, so the login it sends
        is the challenge being answered, not a rejected login resent. A
        rejected code (``mfa_mismatch``) stays cached like any rejection.
        """
        failure = self._session.failure
        if (
            failure is not None
            and failure.code == "totp_required"
            and self._totp_prompt is not None
        ):
            self._session.failure = None
        return await self._with_trust(self._ensure_session)

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
                saved = await self._load_saved() if self._reuse_saved else None
                if saved is not None and saved.access_remaining() > EXPIRY_SLACK_S:
                    self._adopt(client, saved)
                    return None
                if saved is not None and saved.refresh_remaining() > 0:
                    self._adopt(client, saved)
                    return await self._refresh(client)
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
        with these credentials succeeded (or a saved session showed the
        account signed in), so it adds at most one failure per run.

        Near the refresh token's fixed expiry a login comes first, for a new
        week. Without a TOTP prompt an MFA account answers it
        ``totp_required``, which does not count toward the lockout, and the
        refresh still works until the expiry.
        """
        session = self._session
        if (
            session.refresh_exp is not None
            and session.refresh_exp - time.time() <= REFRESH_MARGIN_S
        ):
            problem = await self._login(client)
            soft = problem is not None and (
                problem.kind != "authentication" or problem.code in _RENEWAL_LOGIN_SOFT
            )
            if problem is None or not soft or session.refresh_exp <= time.time():
                return problem
            session.failure = None  # not a rejection: nothing counted toward the lockout
        if self._store is not None:
            renewed = await self._coordinated_refresh(client, self._store)
        else:
            renewed = await self._post_refresh(client)
        if renewed is True:
            return None
        if isinstance(renewed, ResultError):
            return renewed  # transient: the token was probably not spent
        session.until = None
        return await self._login(client)

    async def _post_refresh(self, client: httpx.AsyncClient) -> bool | ResultError:
        """True if renewed; False if the token was refused (401); else the error."""
        self._sync_cookies(client)
        response = await self._post(client, REFRESH_PATH, None)
        if response.status_code == 200 and self._accept_session(client, response):
            return True
        if response.status_code == 401:
            return False
        # A 5xx or 429 is not the service saying the token is spent, so the
        # session is kept for the next try rather than dropped for a sign-in.
        if response.status_code >= 400:
            return error_from_status(response, self.name)
        return ResultError(
            kind="response_format",
            backend=self.name,
            http_status=response.status_code,
            message="BigFix SaaS token refresh returned no session",
        )

    async def _coordinated_refresh(
        self, client: httpx.AsyncClient, store: SaasSessionStore
    ) -> bool | ResultError:
        """Refresh under the store's file lock, so processes never spend one token twice.

        Under the lock the saved pair is read first: one newer than this
        session's means another process already refreshed, and is adopted
        (or refreshed, if its access token has expired too). A refresh
        rejected as spent reads the store again for the same reason, and
        only then drops the entry, if it still holds the spent token.
        """
        lock = await self._lock(store)
        # Shielded: once the refresh is sent the old token is spent, so a
        # cancellation (Ctrl-C, a timeout around the query) must not lose
        # the new pair before it is saved. The lock goes when the work ends.
        work = asyncio.ensure_future(self._refresh_under_lock(client, store))
        if lock is not None:

            def release(done: asyncio.Future[bool | ResultError]) -> None:
                lock.release()
                if not done.cancelled():
                    done.exception()  # retrieved, if the caller was cancelled

            work.add_done_callback(release)
        result: bool | ResultError = await asyncio.shield(work)
        return result

    async def _refresh_under_lock(
        self, client: httpx.AsyncClient, store: SaasSessionStore
    ) -> bool | ResultError:
        session = self._session
        for attempt in range(2):  # this session's token, then a newer saved one
            sent = _cookie(session.cookies, "refreshToken")
            saved = await self._store_call(store.load, self.address, self.username or "")
            newer = (
                saved is not None
                and saved.refresh_token != sent
                and (session.obtained_at is None or saved.stored_at > session.obtained_at)
            )
            if saved is not None and newer:
                if saved.access_remaining() > EXPIRY_SLACK_S:
                    self._adopt(client, saved)
                    return True
                if saved.refresh_remaining() <= 0:
                    return False
                self._adopt(client, saved)
                sent = saved.refresh_token
            elif attempt:
                return False  # nothing newer: the token is spent
            renewed = await self._post_refresh(client)
            if renewed is True:
                await self._save(store)
                return True
            if isinstance(renewed, ResultError):
                return renewed
            if sent is not None:
                await self._store_call(
                    store.forget, self.address, self.username or "", refresh_token=sent
                )
        return False

    async def _login(
        self, client: httpx.AsyncClient, totp: str | None = None
    ) -> ResultError | None:
        """Sign in. Holds the session lock, so at most one login per account runs."""
        data: dict[str, Any] = {"email": self.username or "", "password": self._password or ""}
        if totp is not None:
            data["totp"] = totp
        response = await self._post(client, LOGIN_PATH, data)
        if response.status_code == 200 and self._accept_session(client, response, login=True):
            if self._store is not None:
                lock = await self._lock(self._store)
                try:
                    await self._save(self._store)
                finally:
                    if lock is not None:
                        lock.release()
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
        message = _LOGIN_SIGNAL_MESSAGES[signal] if known and signal else "credentials rejected"
        if signal == "totp_required" and self._store is not None:
            message = _TOTP_NO_SESSION
        error = ResultError(
            kind="authentication",
            code=signal if known else "login_failed",
            backend=self.name,
            http_status=response.status_code,
            message=message,
            detail=signal,
        )
        # Never POST these credentials again, from this backend or any other
        # sharing the session: repeated failures lock the account for good.
        self._session.failure = error
        return error

    def _accept_session(
        self, client: httpx.AsyncClient, response: httpx.Response, *, login: bool = False
    ) -> bool:
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
        now = time.time()
        session.expires_at = now + max(lifetime, 0.0)
        # One cookie per name, on the API host with path "/": the values this
        # response set win over older ones however the service scoped them
        # (a Domain= cookie would otherwise sit beside an adopted one).
        values = {cookie.name: cookie.value for cookie in client.cookies.jar}
        values.update({cookie.name: cookie.value for cookie in response.cookies.jar})
        jar = httpx.Cookies()
        for name, value in values.items():
            if value is not None:
                jar.set(name, value, domain=self.address.host, path="/")
        session.obtained_at = now
        session.refresh_exp = _refresh_expiry(
            values.get("refreshToken"),
            iat if isinstance(iat, int) else None,
            now,
            None if login else session.refresh_exp,
        )
        pids = data.get("pids")
        if isinstance(pids, dict) and isinstance(pids.get("bf"), dict):
            # A sid is shown by --setup and becomes part of a connection name.
            session.servers = tuple(f"bf{key}" for key in pids["bf"] if _SID_KEY.fullmatch(key))
        session.cookies = jar
        session.generation += 1
        client.cookies = jar  # a copy: each client has its own jar
        self._synced = (client, session.generation)
        return True

    # -- saved sessions ---------------------------------------------------------------

    async def _store_call(
        self, fn: Callable[..., Any], *args: Any, _saving: bool = False, **kwargs: Any
    ) -> Any:
        """A store operation in a thread (file and Keychain I/O); None if it failed."""
        try:
            return await asyncio.to_thread(fn, *args, **kwargs)
        except Exception as exc:  # noqa: BLE001 - a store failure costs at most a sign-in
            if _saving:
                # Worth seeing: the next run may need a sign-in (and a TOTP code).
                log.warning(
                    "%s: could not save the BigFix SaaS session (%s)",
                    self.connection or self.name,
                    type(exc).__name__,
                )
            else:
                log.debug(
                    "%s: saved SaaS session: %s", self.connection or self.name, type(exc).__name__
                )
            return None

    async def _load_saved(self) -> SavedSaasSession | None:
        if self._store is None:
            return None
        found: SavedSaasSession | None = await self._store_call(
            self._store.load, self.address, self.username or ""
        )
        return found

    async def _save(self, store: SaasSessionStore) -> None:
        """Save this session's tokens. The caller holds the store's lock."""
        session, cookies = self._session, self._session.cookies
        access, refresh = _cookie(cookies, "accessToken"), _cookie(cookies, "refreshToken")
        if not access or not refresh or session.expires_at is None or session.refresh_exp is None:
            return
        saved = SavedSaasSession(
            access_token=access,
            refresh_token=refresh,
            access_exp=session.expires_at,
            refresh_exp=session.refresh_exp,
            servers=session.servers,
            stored_at=session.obtained_at or time.time(),
        )
        await self._store_call(store.save, self.address, self.username or "", saved, _saving=True)

    def _adopt(self, client: httpx.AsyncClient, saved: SavedSaasSession) -> None:
        """Use a saved session: its cookies, its expiries, its servers."""
        session = self._session
        jar = httpx.Cookies()
        # On the API host with path "/", as the service sets them, so a later
        # Set-Cookie replaces these rather than adding a second of each name.
        jar.set("accessToken", saved.access_token, domain=self.address.host, path="/")
        jar.set("refreshToken", saved.refresh_token, domain=self.address.host, path="/")
        session.cookies = jar
        session.until = time.monotonic() + max(saved.access_remaining(), 0.0)
        session.expires_at = saved.access_exp
        session.refresh_exp = saved.refresh_exp
        session.obtained_at = saved.stored_at
        if saved.servers:
            session.servers = saved.servers
        session.generation += 1
        self._sync_cookies(client)

    async def _lock(self, store: SaasSessionStore) -> FileLock | None:
        """The store's file lock, held; None if it could not be had in time.

        Without it the refresh goes ahead anyway: a spent token's 401 then
        reads the store again, so the worst case is one sign-in.
        """
        from filelock import Timeout

        try:
            lock = await asyncio.to_thread(store.lock)
        except OSError as exc:
            log.debug("%s: no SaaS session lock: %s", self.connection or self.name, exc)
            return None
        # Polled, not a blocking acquire in a thread: a 35 s wait per account
        # would tie up the default executor that store I/O also runs on.
        deadline = time.monotonic() + LOCK_TIMEOUT_S
        while True:
            try:
                lock.acquire(blocking=False)
                break
            except Timeout:
                if time.monotonic() >= deadline:
                    log.warning(
                        "%s: another process held the BigFix SaaS session lock for %.0f s;"
                        " going ahead",
                        self.connection or self.name,
                        LOCK_TIMEOUT_S,
                    )
                    return None
                await asyncio.sleep(LOCK_POLL_S)
            except OSError as exc:
                log.debug("%s: no SaaS session lock: %s", self.connection or self.name, exc)
                return None
        return lock

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


def _cookie(cookies: httpx.Cookies, name: str) -> str | None:
    """The cookie's value, the last set if several (``Cookies.get`` raises then)."""
    found = None
    for cookie in cookies.jar:
        if cookie.name == name:
            found = cookie.value
    return found


def _refresh_expiry(
    refresh_token: str | None, iat: int | None, now: float, previous: float | None
) -> float:
    """When the refresh token expires, on this machine's clock (epoch seconds).

    From the token's own ``exp``, less the response's ``iat`` (the service's
    "now"), so clock skew does not matter. Without it: unchanged by a refresh,
    7 days from a login.
    """
    claims = jwt_claims(refresh_token) if refresh_token else None
    exp = claims.get("exp") if claims else None
    if isinstance(exp, int) and not isinstance(exp, bool):
        return now + (exp - (iat if iat is not None else now))
    if previous is not None:
        return previous
    return now + REFRESH_LIFETIME_S


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
                    " submit, including an unknown computer id or client relevance the"
                    " root server rejects)"
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
