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
import ipaddress
import re
import sys
from collections.abc import Callable, Coroutine
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

import httpx

from .backends.base import Backend, TrustPolicy
from .backends.registry import BACKEND_CLASSES
from .backends.saas import SaasBackend
from .config import ConnectionConfig, load_config, save_connection
from .deployment import DEPLOYMENT_ID_RELEVANCE, deployment_id_from_hashes, discover_deployment_id
from .exceptions import ConfigError
from .render import EXIT_NOTHING_REACHABLE, EXIT_USAGE
from .server_address import normalize_server, saas_api_address
from .trust import CertInfo, TrustStore

InputFn = Callable[[str], str]
ProbeTransportFactory = Callable[[str, str], httpx.AsyncBaseTransport | None]
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


def is_saas_host(host: str) -> bool:
    """A BigFix SaaS web UI or API host (https, ``*.bigfix.com``)."""
    try:
        address = saas_api_address(normalize_server(host, "saas"))
    except ConfigError:
        return False
    return address.host.endswith(".bigfix.com")


def candidates(host: str) -> list[tuple[str, str]]:
    """Endpoints to try, https and default ports first."""
    return [
        ("explorer", host),
        ("rest", host),
        ("webreports", host),
        ("webreports", f"{host}:8083"),
        ("webreports", f"http://{host}"),
        ("webreports", f"http://{host}:8080"),
    ]


async def probe(
    host: str,
    username: str,
    password: str,
    trust: TrustPolicy | None,
    *,
    transport_factory: ProbeTransportFactory | None = None,
) -> list[ProbeResult]:
    async def one(backend_name: str, server: str) -> ProbeResult:
        transport = transport_factory(backend_name, server) if transport_factory else None
        backend = BACKEND_CLASSES[backend_name](
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
        async with backend:
            return await _probe_one(backend, server)

    found = await asyncio.gather(*(one(b, s) for b, s in candidates(host)))
    results = [r for r in found if r.backend != "webreports"]
    web_reports = [r for r in found if r.backend == "webreports"]
    working = [r for r in web_reports if r.status in SAVEABLE]
    results.append(working[0] if working else web_reports[0])
    return results


async def probe_saas(
    host: str,
    email: str,
    password: str,
    totp_prompt: InputFn,
    *,
    transport: httpx.AsyncBaseTransport | None = None,
) -> list[ProbeResult]:
    """Sign in to BigFix SaaS once and probe every server the account lists.

    One backend, so one login: a rejected login is never sent again, and
    every server is asked over the same session. An account with one server
    needs no ``sid`` (the gateway's default is that server).
    """
    backend = SaasBackend(
        host,
        username=email,
        password=password,
        totp_prompt=totp_prompt,
        verify=True,  # a public CA-signed service: no trust on first use
        connect_timeout=4,
        read_timeout=30,
        retries=0,
        transport=transport,
    )
    async with backend:
        first = await _probe_one(backend, host)
        if len(backend.servers) <= 1:
            return [first]
        results = []
        for sid in backend.servers:
            backend.sid = sid
            results.append(replace(await _probe_one(backend, host), sid=sid))
        return results


async def _probe_one(backend: Backend, server: str) -> ProbeResult:
    result = await backend.evaluate(DEPLOYMENT_ID_RELEVANCE)
    if result.ok:
        found = deployment_id_from_hashes(str(a) for a in result.answers)
        return ProbeResult(backend.name, server, "ok", found, "")
    error = result.error
    if error is None or error.kind == "relevance":
        found = await discover_deployment_id(backend)
        return ProbeResult(backend.name, server, "ok", found, "")
    status = {
        "authentication": "auth",
        "connection": "unreachable",
        "timeout": "unreachable",
        "tls": "tls",
    }.get(error.kind, "error")
    if error.code == "service_unavailable":
        status = "unavailable"
    return ProbeResult(backend.name, server, status, None, error.message)


def run_setup(
    path: Path,
    *,
    input_fn: InputFn,
    getpass_fn: InputFn,
    probe_fn: ProbeFn | None = None,
    saas_probe_fn: SaasProbeFn | None = None,
) -> int:
    say = _say
    say(f"Adding BigFix connections to {path}")
    host = input_fn(
        "BigFix server host name or IP (login.bigfix.com or eulogin.bigfix.com for BigFix SaaS): "
    ).strip()
    if not host:
        say("a host is required")
        return EXIT_USAGE
    saas = is_saas_host(host)
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
        results = asyncio.run((probe_fn or probe)(host, username, password, trust))

    say("")
    for r in results:
        dep = f" deployment {r.deployment_id[:12]}…" if r.deployment_id else ""
        note = f" ({r.message})" if r.message and r.status != "ok" else ""
        say(f"  {r.backend:<10} {_where(r):<32} {r.status}{dep}{note}")
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
        default_env = f"BFRSR_{re.sub(r'[^A-Z0-9]+', '_', host.upper()).strip('_')}_PASSWORD"
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


def _where(r: ProbeResult) -> str:
    return f"{r.server} {r.sid}" if r.sid else r.server


def _default_name(host: str, r: ProbeResult) -> str:
    if r.backend != "saas":
        return f"{_short(host)}-{r.backend}"
    region = "-eu" if saas_api_address(normalize_server(host, "saas")).host.startswith("eu") else ""
    return f"bigfix-saas{region}-{r.sid}" if r.sid else f"bigfix-saas{region}"


def _short(host: str) -> str:
    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return host.split(".")[0].lower()
    return re.sub(r"[^0-9a-f]+", "-", host.lower()).strip("-")


def _say(message: str) -> None:
    print(message, file=sys.stderr)
