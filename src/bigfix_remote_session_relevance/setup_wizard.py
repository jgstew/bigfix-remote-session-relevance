"""``--setup``: find what a BigFix server exposes and write the connections.

Asks for a host, username and password, probes each backend's default port
concurrently (pinning certificates with the user's confirmation), shows
which endpoints answered and which deployment they belong to, then saves
the chosen ones with only the non-default parts of ``server`` written out.

A BigFix SaaS host (``login.bigfix.com``, ``eulogin.bigfix.com``) instead
signs in once with an email and password (answering a TOTP challenge if the
service sends one) and saves one connection per BigFix server the account
can reach.
"""

from __future__ import annotations

import asyncio
import functools
import getpass
import ipaddress
import re
import sys
from collections.abc import Callable, Collection, Coroutine
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, cast

import httpx

from .backends.base import Backend, TrustPolicy
from .backends.registry import BACKEND_CLASSES
from .backends.rest import RestBackend
from .backends.saas import SaasSessionPool
from .config import ConnectionConfig, load_config, resolve_config_path, save_connection
from .deployment import (
    DEPLOYMENT_ID_SESSION_RELEVANCE,
    deployment_id_from_hashes,
    discover_deployment_id,
)
from .escapes import escape_controls
from .exceptions import ConfigError
from .render import EXIT_NOTHING_REACHABLE, EXIT_USAGE
from .result import ResultError
from .saas_account import new_saas_backend, saas_connection_name, saas_sign_in
from .server_address import (
    DEFAULT_PORTS,
    ServerAddress,
    normalize_server,
    saas_api_address,
    split_server,
)
from .trust import CertInfo, TrustStore

InputFn = Callable[[str], str]
ProbeTransportFactory = Callable[[str, str], httpx.AsyncBaseTransport | None]
# Asked with the root server's listed (backend, server) pairs not yet tried;
# True sends the same credentials to them.
ConfirmListedFn = Callable[[list[tuple[str, str]]], bool]
ProbeFn = Callable[[str, str, str, TrustPolicy | None], Coroutine[Any, Any, list["ProbeResult"]]]
SaasProbeFn = Callable[[str, str, str, InputFn], Coroutine[Any, Any, list["ProbeResult"]]]

# What can be saved: it answered, even if only to say no.
SAVEABLE = ("ok", "auth", "unavailable")
# Not a rejected SaaS login: saving it would send the rejected password on
# every run, and failed logins lock a SaaS account for good.
SAAS_SAVEABLE = ("ok", "unavailable")


@dataclass(frozen=True)
class ProbeResult:
    backend: str
    server: str  # as it would be written to the config
    status: str  # ok | auth | unavailable | unreachable | tls | error
    deployment_id: str | None
    message: str
    sid: str | None = None  # BigFix SaaS server, when the account has several
    listed: bool = False  # found in the root server's lists, not from the host given


def is_saas_host(host: str) -> bool:
    """A BigFix SaaS web UI or API host (https, ``*.bigfix.com``)."""
    try:
        address = saas_api_address(normalize_server(host, "saas"))
    except ConfigError:
        return False
    return address.host.endswith(".bigfix.com")


def candidates(host: str) -> list[tuple[str, str]]:
    """Endpoints to try, https and default ports first.

    A host given with a port is tried only on that port, and one given with
    a scheme only over that scheme: the person already said where to look,
    and appending a default port to a given one made an invalid address.
    """
    scheme, bare, port = split_server(host)
    if scheme == "http":
        return [("webreports", host)]
    given = [(backend, host) for backend in ("explorer", "rest", "webreports")]
    if port:
        # Web Reports is often plain http on its own port (e.g. 8080).
        return given if scheme else [*given, ("webreports", f"http://{host}")]
    bare = f"[{bare}]" if ":" in bare else bare  # IPv6
    if scheme:
        return [*given, ("webreports", f"{bare}:8083")]
    return [
        *given,
        ("webreports", f"{bare}:8083"),
        ("webreports", f"http://{bare}"),
        ("webreports", f"http://{bare}:8080"),
    ]


async def probe(
    host: str,
    username: str,
    password: str,
    trust: TrustPolicy | None,
    *,
    backends: Collection[str] | None = None,
    transport_factory: ProbeTransportFactory | None = None,
    confirm_listed: ConfirmListedFn | None = None,
) -> list[ProbeResult]:
    """Probe the host's candidates, then the servers its root server lists.

    The listed servers are probed only if ``confirm_listed`` agrees: the
    root server's lists are not the user's word, and a listed server may be
    anywhere, over http.
    """

    def build(backend_name: str, server: str) -> Backend:
        transport = transport_factory(backend_name, server) if transport_factory else None
        return BACKEND_CLASSES[backend_name](
            server,
            username=username,
            password=password,
            verify="tofu",
            trust=trust,
            connect_timeout=4,
            read_timeout=30,
            retries=0,
            transport=transport,
        )

    async def one(backend_name: str, server: str) -> ProbeResult:
        async with build(backend_name, server) as backend:
            return await _probe_one(backend, server)

    tried = [(b, s) for b, s in candidates(host) if backends is None or b in backends]
    found = await asyncio.gather(*(one(b, s) for b, s in tried))
    results = [r for r in found if r.backend != "webreports"]
    web_reports = [r for r in found if r.backend == "webreports"]
    working = [r for r in web_reports if r.status in SAVEABLE]
    if web_reports:
        results.append(working[0] if working else web_reports[0])

    rest = next((r for r in results if r.backend == "rest" and r.status == "ok"), None)
    wanted = {"explorer", "webreports"} if backends is None else set(backends)
    if rest is None or not wanted & {"explorer", "webreports"}:
        return results
    async with cast(RestBackend, build("rest", rest.server)) as root:
        listed = await root.registered_servers()
    if isinstance(listed, ResultError):
        note = (
            "listing other Explorer and Web Reports servers needs a master operator"
            if listed.code == "permission_denied"
            else f"could not list other Explorer and Web Reports servers: {listed.message}"
        )
        results[results.index(rest)] = replace(rest, message=note)
        return results
    # Compared as addresses, so "bf" and "https://bf:9383" are one Explorer.
    seen = {(b, normalize_server(s, b)) for b, s in tried}
    extra: list[tuple[str, str]] = []
    for backend_name, url in listed:
        try:
            address = normalize_server(url, backend_name)
        except ConfigError:
            continue  # not a usable address; nothing to probe
        if backend_name in wanted and (backend_name, address) not in seen:
            seen.add((backend_name, address))
            extra.append((backend_name, _config_server(backend_name, address)))
    if not extra:
        return results
    if confirm_listed is None or not confirm_listed(extra):
        note = f"the root server lists {len(extra)} other servers, not probed"
        results[results.index(rest)] = replace(rest, message=note)
        return results
    found = await asyncio.gather(*(one(b, s) for b, s in extra))
    return [*results, *(replace(r, listed=True) for r in found)]


def confirm_listed_prompt(input_fn: InputFn) -> ConfirmListedFn:
    """Show the listed servers and ask before the password goes to them."""

    def confirm(listed: list[tuple[str, str]]) -> bool:
        _say("\nThe root server lists these other servers:")
        for backend, server in listed:
            # Server text: the root server's, so escaped like any other.
            clear = " (cleartext)" if server.startswith("http://") else ""
            _say(f"  {backend:<10} {escape_controls(server)}{clear}")
        answer = input_fn("Send the same username and password to them too? [y/N] ")
        return answer.strip().lower() in ("y", "yes")

    return confirm


async def probe_saas(
    host: str,
    email: str,
    password: str,
    totp_prompt: InputFn,
    *,
    transport: httpx.AsyncBaseTransport | None = None,
) -> list[ProbeResult]:
    """Sign in to BigFix SaaS once and probe every server the account lists.

    The sign-in is `saas_sign_in`'s, shared through a pool, so one login: a
    rejected login is never sent again, and every server is asked over the
    same session. An account with one server needs no ``sid`` (the
    gateway's default is that server).
    """
    pool = SaasSessionPool()
    account = await saas_sign_in(
        host, email, password, prompt=totp_prompt, pool=pool, transport=transport
    )
    if account.error is not None:
        return [ProbeResult("saas", host, _status(account.error), None, account.error.message)]
    # The prompt too, in case the session must be renewed mid-probe.
    backend = new_saas_backend(host, email, password, totp_prompt=totp_prompt, transport=transport)
    pool.attach(backend)
    async with backend:
        if len(account.servers) <= 1:
            return [await _probe_one(backend, host)]
        results = []
        for sid in account.servers:
            backend.sid = sid
            results.append(replace(await _probe_one(backend, host), sid=sid))
        return results


async def _probe_one(backend: Backend, server: str) -> ProbeResult:
    result = await backend.evaluate(DEPLOYMENT_ID_SESSION_RELEVANCE)
    if result.ok:
        found = deployment_id_from_hashes(str(a) for a in result.answers)
        return ProbeResult(backend.name, server, "ok", found, "")
    error = result.error
    if error is None or error.kind == "session_relevance":
        found = await discover_deployment_id(backend)
        return ProbeResult(backend.name, server, "ok", found, "")
    return ProbeResult(backend.name, server, _status(error), None, error.message)


def _status(error: ResultError) -> str:
    if error.code == "service_unavailable":
        return "unavailable"
    return {
        "authentication": "auth",
        "connection": "unreachable",
        "timeout": "unreachable",
        "tls": "tls",
    }.get(error.kind, "error")


def run_setup(
    path: str | Path | None = None,
    *,
    backends: Collection[str] | None = None,
    input_fn: InputFn = input,
    getpass_fn: InputFn = getpass.getpass,
    probe_fn: ProbeFn | None = None,
    saas_probe_fn: SaasProbeFn | None = None,
) -> int:
    """Interactively probe a server and save its connections; the exit code.

    ``path=None`` is the config ``--setup`` would use. ``backends`` limits
    which backends are probed and offered for saving, e.g. ``("rest",)``
    for a caller that needs only the REST API.
    """
    if isinstance(backends, str):
        raise TypeError(f"backends must be a collection of names, e.g. ({backends!r},)")
    if backends is not None:
        backends = frozenset(backends)
        unknown = backends - set(BACKEND_CLASSES)
        if not backends or unknown:
            raise ValueError(
                f"backends must be some of {sorted(BACKEND_CLASSES)}, got {sorted(backends)}"
            )
    path = resolve_config_path(path)
    say = _say
    say(f"Adding BigFix connections to {path}")
    host = input_fn(
        "Host name or IP of a BigFix root server, Explorer or Web Reports, with :port if "
        "not the default (login.bigfix.com or eulogin.bigfix.com for BigFix SaaS): "
    ).strip()
    if not host:
        say("a host is required")
        return EXIT_USAGE
    try:
        normalize_server(host, "rest")  # any backend: this checks the scheme and port
    except ConfigError as exc:
        say(str(exc))
        return EXIT_USAGE
    saas = is_saas_host(host)
    # Decided before asking for a password, so nothing is sent to a host that
    # cannot offer any of the requested backends.
    if saas and backends is not None and "saas" not in backends:
        say(f"{host} is BigFix SaaS, which is not one of {', '.join(sorted(backends))}")
        return EXIT_USAGE
    if not saas and backends == frozenset({"saas"}):
        say(f"{host} is not a BigFix SaaS host (login.bigfix.com or eulogin.bigfix.com)")
        return EXIT_USAGE
    username = input_fn("Email: " if saas else "Username: ").strip()
    password = getpass_fn("Password: ")

    if saas:
        say(f"Signing in to BigFix SaaS at {host} ...")
        # The TOTP code is single-use, so it is echoed like any other answer.
        results = asyncio.run((saas_probe_fn or probe_saas)(host, username, password, input_fn))
    else:

        def confirm_cert(info: CertInfo) -> bool:
            say(f"\n{info.host_port} presents a certificate that is not CA-signed.")
            say(f"  SHA-256 fingerprint: {info.fingerprint}")
            return input_fn("Trust and pin it? [Y/n] ").strip().lower() in ("", "y", "yes")

        trust = TrustStore(callback=confirm_cert)
        say(f"Probing {host} ...")
        results = asyncio.run(
            (
                probe_fn
                or functools.partial(
                    probe, backends=backends, confirm_listed=confirm_listed_prompt(input_fn)
                )
            )(host, username, password, trust)
        )
    answered_elsewhere: list[str] = []
    if backends is not None:
        answered_elsewhere = sorted(
            {r.backend for r in results if r.backend not in backends and r.status in SAVEABLE}
        )
        results = [r for r in results if r.backend in backends]

    say("")
    for r in results:
        dep = f" deployment {r.deployment_id[:12]}…" if r.deployment_id else ""
        # The message can be the server's text; the wizard always talks to a person.
        # A working REST result's message is about the root server's lists.
        note = f" ({escape_controls(r.message)})" if r.message else ""
        listed = " (listed by the root server)" if r.listed else ""
        say(f"  {r.backend:<10} {_where(r):<32} {r.status}{dep}{listed}{note}")
    ids = {r.deployment_id for r in results if r.deployment_id}
    if len(ids) == 1 and len(results) > 1:
        say("  The endpoints that answered belong to one deployment.")
    saveable = [r for r in results if r.status in (SAAS_SAVEABLE if saas else SAVEABLE)]
    if not saveable:
        if saas and any(r.status == "auth" for r in results):
            say(
                "BigFix SaaS did not accept the sign-in, so nothing is saved: failed logins "
                "count toward a permanent account lock. Check the email, password and MFA "
                "in the web UI before running --setup again."
            )
        elif answered_elsewhere and backends is not None:
            say(
                f"{', '.join(answered_elsewhere)} answered, but none of "
                f"{', '.join(sorted(backends))} did; check the host, firewall and ports."
            )
        else:
            say("Nothing answered; check the host, firewall and ports.")
        return EXIT_NOTHING_REACHABLE

    store = (
        input_fn(
            "Store the password in the config file (mode 0600) [f], or read it from an "
            "environment variable [e]? [F/e] "
        )
        .strip()
        .lower()
    )
    password_env: str | None = None
    if store.startswith("e"):
        bare = split_server(host)[1].upper()
        default_env = f"BFRSR_{re.sub(r'[^A-Z0-9]+', '_', bare).strip('_')}_PASSWORD"
        password_env = input_fn(f"Environment variable name [{default_env}]: ").strip()
        password_env = password_env or default_env

    try:
        existing = {c.name for c in load_config(path).connections} if path.is_file() else set()
    except ConfigError as exc:
        say(f"cannot read {path}: {exc}")
        return EXIT_USAGE

    saved: list[str] = []
    for r in saveable:
        flag = " (credentials were rejected)" if r.status == "auth" else ""
        if input_fn(f"Save {r.backend} at {_where(r)}{flag}? [Y/n] ").strip().lower() not in (
            "",
            "y",
            "yes",
        ):
            continue
        default_name = _default_name(host, r)
        # A listed server can shorten to the name just saved (the root's own
        # Explorer under its machine name): number it rather than replace.
        base, n = default_name, 2
        while default_name in saved:
            default_name, n = f"{base}-{n}", n + 1
        name = input_fn(f"Connection name [{default_name}]: ").strip() or default_name
        replace = False
        if name in existing:
            if input_fn(f"{name!r} exists; replace it? [y/N] ").strip().lower() not in ("y", "yes"):
                continue
            replace = True
        conn = ConnectionConfig(
            name=name,
            backend=r.backend,
            server=r.server,
            username=username,
            password=None if password_env else password,
            password_env=password_env,
            deployment_id=r.deployment_id,
            sid=r.sid,
            verify=True if r.backend == "saas" else None,
        )
        save_connection(path, conn, replace=replace)
        existing.add(name)
        saved.append(name)

    if saved:
        say(f"Saved {', '.join(saved)} to {path}")
        if password_env:
            say(f"Set the password before running queries, e.g.: export {password_env}=...")
    else:
        say("Nothing saved.")
    return 0


def _config_server(backend: str, address: ServerAddress) -> str:
    """``server`` as the config would have it: only the non-default parts."""
    if address.scheme == "http":
        return address.base_url
    if address.port != DEFAULT_PORTS[backend]:
        return address.host_port
    return f"[{address.host}]" if ":" in address.host else address.host


def _where(r: ProbeResult) -> str:
    return f"{r.server} {r.sid}" if r.sid else r.server


def _default_name(host: str, r: ProbeResult) -> str:
    if r.backend != "saas":
        return f"{_short(r.server if r.listed else host)}-{r.backend}"
    return saas_connection_name(host, r.sid)


def _short(host: str) -> str:
    host = split_server(host)[1]
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return host.split(".")[0].lower()
    return re.sub(r"[^0-9a-f]+", "-", host.lower()).strip("-")


def _say(message: str) -> None:
    print(message, file=sys.stderr)
