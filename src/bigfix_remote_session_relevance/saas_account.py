"""`saas_sign_in`: sign in to a BigFix SaaS account and list its servers.

For a front end's "Add BigFix SaaS account" screen, and the setup wizard's
SaaS path. It sends at most one login, two when the service answers with its
own ``totp_required`` challenge and a code is given (``totp``) or asked for
(``prompt``). A rejected sign-in comes back as the result, never retried:
100 failed logins lock the account for good (see ``backends/saas.py``).
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

import httpx

from .backends.saas import SaasBackend, SaasSessionPool
from .config import ConnectionConfig
from .result import ResultError
from .server_address import normalize_server, saas_api_address

# The wizard's probe settings: a public CA-signed service, so no trust on
# first use, and short timeouts because a person is waiting.
_CONNECT_TIMEOUT = 4.0
_READ_TIMEOUT = 30.0


@dataclass(frozen=True)
class SaasAccount:
    """What signing in found: the account's BigFix servers, or why it failed."""

    host: str  # as given: login.bigfix.com, eulogin.bigfix.com, or an API host
    email: str
    servers: tuple[str, ...] = ()  # sid values; one (or none) means no sid is needed
    error: ResultError | None = None  # authentication / totp_required / …, never raised

    @property
    def ok(self) -> bool:
        return self.error is None

    def connections(self, *, name_prefix: str | None = None) -> tuple[ConnectionConfig, ...]:
        """One connection per server, named as ``--setup`` names them; none if failed.

        They carry no password: set ``password`` or ``password_env`` (with
        `dataclasses.replace`) where the caller keeps it. ``name_prefix``
        defaults to ``bigfix-saas`` (``bigfix-saas-eu`` for the EU service);
        with several servers each name ends in its ``sid``.
        """
        if not self.ok:
            return ()
        prefix = name_prefix or saas_connection_name(self.host)
        sids: tuple[str | None, ...] = self.servers if len(self.servers) > 1 else (None,)
        return tuple(
            ConnectionConfig(
                name=f"{prefix}-{sid}" if sid else prefix,
                backend="saas",
                server=self.host,
                username=self.email,
                sid=sid,
                verify=True,
            )
            for sid in sids
        )


def saas_connection_name(host: str, sid: str | None = None) -> str:
    """``bigfix-saas[-eu][-<sid>]``, the default name for a SaaS connection."""
    api = saas_api_address(normalize_server(host, "saas"))
    region = "-eu" if api.host.startswith("eu") else ""
    return f"bigfix-saas{region}-{sid}" if sid else f"bigfix-saas{region}"


async def saas_sign_in(
    host: str,
    email: str,
    password: str,
    *,
    totp: str | None = None,
    prompt: Callable[[str], str] | None = None,
    pool: SaasSessionPool | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
) -> SaasAccount:
    """Sign in once and list the account's servers; failures are in ``error``.

    ``totp`` answers the service's MFA challenge with a code the caller
    already has; ``prompt`` asks for one only if challenged. With neither, an
    MFA account comes back as ``authentication`` / ``totp_required``, so a
    front end can ask for the code and call again (with the same ``pool``
    too: a pending challenge is not kept as a rejection). ``prompt`` is
    called synchronously, on the event loop, and whatever it raises (a
    cancelled dialog, say) propagates (async prompts are not supported yet). ``pool``:
    backends later attached to the same `SaasSessionPool` reuse this sign-in,
    and a rejected one (a wrong password or TOTP code) is never sent again
    through it. ``email`` is stripped.

    Raises only for caller bugs: a host that is not BigFix SaaS (`ConfigError`,
    before anything is sent) or both ``totp`` and ``prompt``.
    """
    if totp is not None and prompt is not None:
        raise ValueError("give totp or prompt, not both")
    email = email.strip()
    totp_prompt = _answer(totp) if totp is not None else prompt
    backend = new_saas_backend(host, email, password, totp_prompt=totp_prompt, transport=transport)
    if not email or not password:
        # Sent, an empty email or password would still count as a failed login.
        blank = ResultError(
            kind="authentication",
            backend=backend.name,
            message="BigFix SaaS needs an email and a password",
        )
        return SaasAccount(host, email, error=blank)
    if pool is not None:
        pool.attach(backend)
    async with backend:
        error = await backend.sign_in()
    return SaasAccount(host, email, () if error else backend.servers, error)


def _answer(code: str) -> Callable[[str], str]:
    return lambda _text: code


def new_saas_backend(
    host: str,
    email: str,
    password: str,
    *,
    totp_prompt: Callable[[str], str] | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
) -> SaasBackend:
    """A backend for signing in and probing, as the wizard and `saas_sign_in` use."""
    return SaasBackend(
        host,
        username=email,
        password=password,
        totp_prompt=totp_prompt,
        verify=True,
        connect_timeout=_CONNECT_TIMEOUT,
        read_timeout=_READ_TIMEOUT,
        retries=0,
        transport=transport,
    )


__all__ = ["SaasAccount", "new_saas_backend", "saas_connection_name", "saas_sign_in"]
