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
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import time
import uuid
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

import httpx

from ..result import ResultError, SessionRelevanceResult
from ..server_address import saas_api_address
from ._parsing import _float_or_none, _format_error, _relevance_error, raw_from_response
from .base import Backend, error_from_status

if TYPE_CHECKING:
    from ..config import ConnectionConfig

LOGIN_PATH = "/auth/v1/user/login"
REFRESH_PATH = "/auth/v1/token/refresh"
RELEVANCE_PATH = "/bfproxy/v2/relevance"
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
    "parse_saas_relevance",
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
    """Sessions keyed by account: API host, email and password.

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
        return (self.address.base_url, self.username or "", password)

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

    async def _evaluate(self, client: httpx.AsyncClient, relevance: str) -> SessionRelevanceResult:
        problem = await self._ensure_session(client)
        if problem is not None:
            return SessionRelevanceResult.failure(relevance, problem)
        generation = self._sync_cookies(client)
        response = await self._post(client, RELEVANCE_PATH, {"query": relevance}, sid=self.sid)
        if response.status_code == 401:
            problem = await self._renew(client, generation)
            if problem is not None:
                return SessionRelevanceResult.failure(relevance, problem)
            self._sync_cookies(client)
            response = await self._post(client, RELEVANCE_PATH, {"query": relevance}, sid=self.sid)
        return parse_saas_relevance(relevance, response, self.name)

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
            session.servers = tuple(f"bf{key}" for key in pids["bf"])
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


def _error_message(response: httpx.Response) -> str | None:
    try:
        body = response.json()
    except ValueError:
        return None
    data = body.get("data") if isinstance(body, dict) else None
    if isinstance(data, dict) and isinstance(data.get("errorMessage"), str):
        return str(data["errorMessage"])
    return None


def parse_saas_relevance(
    relevance: str, response: httpx.Response, backend: str
) -> SessionRelevanceResult:
    raw = raw_from_response(response)
    if response.status_code in (401, 403):
        return SessionRelevanceResult.failure(
            relevance, error_from_status(response, backend), raw=raw
        )
    if raw.format != "json":
        if response.status_code >= 400:
            return SessionRelevanceResult.failure(
                relevance, error_from_status(response, backend), raw=raw
            )
        return _format_error(relevance, raw, backend, "expected JSON from BigFix SaaS")
    try:
        body = json.loads(raw.text)
    except ValueError as exc:
        return _format_error(relevance, raw, backend, f"invalid JSON: {exc}")
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
        return SessionRelevanceResult.failure(relevance, error, raw=raw)
    if isinstance(data, dict):
        if isinstance(data.get("error"), str):
            return _relevance_error(relevance, data["error"], raw, backend)
        if "answer" in data:
            values = data["answer"] if isinstance(data["answer"], list) else [data["answer"]]
            plural = data.get("plural")
            return SessionRelevanceResult.from_values(
                relevance,
                values,
                type=data.get("type"),
                plural=plural if isinstance(plural, bool) else None,
                evaluation_time_ms=_float_or_none(data.get("evaltime")),
                raw=raw,
            )
    return _format_error(relevance, raw, backend, "BigFix SaaS response has no answer")
