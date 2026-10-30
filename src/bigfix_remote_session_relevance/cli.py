"""``bigfix-remote-session-relevance "session relevance"``: query every reachable deployment.

Exit codes: 0 all ok, 1 a session relevance error, 2 nothing reachable (or auth
failed everywhere), 3 partial (some deployments failed), 64 usage/config.
"""

from __future__ import annotations

import argparse
import asyncio
import dataclasses
import getpass
import io
import json
import logging
import sys
import threading
from collections.abc import Callable, Iterable
from importlib.metadata import PackageNotFoundError, version
from typing import Any, NoReturn, TextIO

from .backends.explorer_extras import explorer_body
from .client import TransportFactory
from .config import Config, load_config, redacted_summary, resolve_config_path
from .escapes import escape_controls
from .exceptions import ConfigError
from .render import EXIT_USAGE, HumanRenderer, exit_code, format_error, is_terminal
from .result import SessionRelevanceResult
from .results import SessionRelevanceResults
from .server_address import normalize_server
from .sync import SessionRelevanceClient
from .trust import CertInfo, KnownCerts, TrustStore, fetch_server_cert

log = logging.getLogger(__name__)

InputFn = Callable[[str], str]


class _UsageError(Exception):
    pass


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        raise _UsageError(message)


def _version() -> str:
    try:
        return version("bigfix-remote-session-relevance")
    except PackageNotFoundError:  # pragma: no cover - running from a source tree
        return "0+unknown"


def build_parser() -> argparse.ArgumentParser:
    p = _Parser(
        prog="bigfix-remote-session-relevance",
        description=(
            "Evaluate BigFix session relevance on every configured deployment "
            "(REST API, BigFix Explorer, Web Reports)."
        ),
    )
    p.add_argument("session_relevance", nargs="?", help='session relevance, or "-" to read stdin')
    p.add_argument("--version", action="version", version=_version())
    p.add_argument(
        "--config",
        metavar="PATH",
        help="config file (default: $BFRSR_CONFIG or ~/.bigfix/.remote_session_connections.toml)",
    )

    setup = p.add_argument_group("setup")
    setup.add_argument("--setup", action="store_true", help="interactively add connections")
    setup.add_argument(
        "--show-config", action="store_true", help="list configured connections (no secrets)"
    )
    setup.add_argument(
        "--discover-deployments",
        action="store_true",
        help="re-detect which connections share a deployment",
    )
    setup.add_argument("--show-certs", action="store_true", help="list pinned certificates")
    setup.add_argument(
        "--trust-cert", metavar="NAME|HOST:PORT", help="fetch and (re)pin a server certificate"
    )
    setup.add_argument("--forget-cert", metavar="HOST:PORT", help="remove a pinned certificate")

    sel = p.add_argument_group("selection")
    sel.add_argument(
        "--all-connections",
        "--all",
        "-all",
        action="store_true",
        help="query every connection, not one per deployment",
    )
    sel.add_argument("--connection", action="append", metavar="NAME", help="only this connection")
    sel.add_argument(
        "--backend",
        action="append",
        choices=["rest", "explorer", "webreports", "saas"],
        help="only this backend",
    )

    out = p.add_argument_group("output")
    out.add_argument("--json", action="store_true", help="JSON list of result objects")
    out.add_argument("--raw", action="store_true", help="include the raw server response")
    out.add_argument(
        "--keep-escapes",
        action="store_true",
        help="show %% and control characters in answers as %%xx (as Web Reports sends them)",
    )
    out.add_argument("-v", "--verbose", action="count", default=0)

    net = p.add_argument_group("network")
    net.add_argument(
        "--no-tofu",
        action="store_true",
        help="never trust a new self-signed certificate automatically",
    )
    net.add_argument("--connect-timeout", type=float, metavar="SECONDS")
    net.add_argument("--timeout", type=float, metavar="SECONDS", help="read timeout")

    ex = p.add_argument_group("BigFix Explorer extras (additive)")
    ex.add_argument("--keys", help='rename/nest output fields, e.g. "id name agent { version }"')
    ex.add_argument(
        "--filter",
        action="append",
        metavar="TYPE=RELEVANCE",
        help="Explorer filter, e.g. computers='name of it starts with \"a\"'",
    )
    return p


def main(
    argv: list[str] | None = None,
    *,
    transport_factory: TransportFactory | None = None,
    input_fn: InputFn | None = None,
    getpass_fn: InputFn | None = None,
    interactive: bool | None = None,
) -> int:
    _tolerate_unencodable(sys.stdout)
    _tolerate_unencodable(sys.stderr)
    is_interactive = (
        (sys.stdin.isatty() and sys.stderr.isatty()) if interactive is None else interactive
    )
    ask: InputFn = input_fn or _stderr_input
    secret: InputFn = getpass_fn or getpass.getpass
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except _UsageError as exc:
        parser.print_usage(sys.stderr)
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE
    _configure_logging(args.verbose)

    try:
        if args.show_certs:
            return _show_certs()
        if args.forget_cert:
            return _forget_cert(args.forget_cert)
        if args.setup:
            from .setup_wizard import run_setup

            return run_setup(resolve_config_path(args.config), input_fn=ask, getpass_fn=secret)
        config = load_config(args.config)
        if args.trust_cert:
            return _trust_cert(args.trust_cert, config, ask)
        if args.show_config:
            return _show_config(config)
        if not config.connections:
            return _no_connections(args, is_interactive, ask, secret)
        config = _apply_timeouts(config, args)
        # Prompts run on the client's loop thread while answers stream out on
        # this one; holding the terminal keeps answers from landing mid-prompt.
        ask_held, secret_held = _holding_terminal(ask), _holding_terminal(secret)
        # Not interactive, the CLI keeps classic TOFU ("auto") explicitly: there
        # is no one to ask, and --no-tofu is the documented way to refuse.
        if args.no_tofu:
            trust = TrustStore(trust_on_first_use=False)
        elif is_interactive:
            trust = TrustStore(callback=lambda info: _prompt_trust(info, ask_held))
        else:
            trust = TrustStore(trust_on_first_use="auto")
        client_kwargs: dict[str, Any] = {
            "mode": "all" if args.all_connections else "per_deployment",
            "connections": args.connection,
            "backends": args.backend,
            "trust": trust,
            "prompt": secret_held if is_interactive else None,
            "transport_factory": transport_factory,
        }
        if args.discover_deployments:
            return _discover(config, client_kwargs)
        session_relevance = _read_session_relevance(args.session_relevance)
        filters = _parse_filters(args.filter)
        explorer = args.keys is not None or filters is not None
        if explorer:
            # Bad input is rejected before any connection, prompt or discovery.
            try:
                explorer_body(session_relevance, args.keys, filters)
            except (ValueError, TypeError) as exc:
                print(f"error: {exc}", file=sys.stderr)
                return EXIT_USAGE
        unescape = not args.keep_escapes
        with SessionRelevanceClient(config, **client_kwargs) as client:
            if args.json:
                # One JSON document needs every result in; it alone waits.
                results = (
                    client.evaluate_explorer(
                        session_relevance, keys=args.keys, filters=filters, unescape=unescape
                    )
                    if explorer
                    else client.evaluate(session_relevance, unescape=unescape)
                )
                print(json.dumps(results.to_dict(include_raw=args.raw), indent=2))
            else:
                stream = (
                    client.evaluate_explorer_stream(
                        session_relevance, keys=args.keys, filters=filters, unescape=unescape
                    )
                    if explorer
                    else client.evaluate_stream(session_relevance, unescape=unescape)
                )
                count = client.result_count()
                labelled = None if count is None else count > 1
                results = _print_stream(stream, args, labelled=labelled)
    except _UsageError as exc:
        parser.print_usage(sys.stderr)
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE
    except ConfigError as exc:
        print(f"config error: {exc}", file=sys.stderr)
        return EXIT_USAGE

    return exit_code(results)


# -- helpers -------------------------------------------------------------------------


# Held while a prompt waits for input and while a result is written, so the two
# never interleave on the terminal.
_TERMINAL = threading.Lock()


def _holding_terminal(fn: InputFn) -> InputFn:
    def held(prompt: str) -> str:
        with _TERMINAL:
            return fn(prompt)

    return held


def _print_stream(
    stream: Iterable[SessionRelevanceResult], args: argparse.Namespace, *, labelled: bool | None
) -> SessionRelevanceResults:
    """Print each result as it lands; exit codes still wait for all of them."""
    collected: list[SessionRelevanceResult] = []
    renderer = HumanRenderer(
        out=sys.stdout, err=sys.stderr, verbose=args.verbose, labelled=labelled
    )
    for r in stream:
        collected.append(r)
        with _TERMINAL:
            if not args.raw:
                renderer.add(r)
            elif r.raw is not None:
                print(r.raw.text, flush=True)
            elif r.error is not None:
                print(format_error(r, escape=is_terminal(sys.stderr)), file=sys.stderr, flush=True)
    if not args.raw:
        with _TERMINAL:
            renderer.close()
    return SessionRelevanceResults(collected)


# Error handlers that write every character somehow; anything else (strict,
# surrogateescape) can raise on an answer.
_NEVER_FAILING_ERRORS = frozenset(
    {"backslashreplace", "replace", "ignore", "xmlcharrefreplace", "namereplace"}
)


def _tolerate_unencodable(stream: TextIO) -> None:
    """Write what the stream's encoding can't hold as ``\\uXXXX``, not raise.

    Answers can hold text no encoding can: JSON allows a lone surrogate
    (``\\ud800``), which UTF-8 refuses, and a non-UTF-8 console refuses much
    more. A failing handler would end the run mid-stream on one answer. That
    includes ``surrogateescape``, CPython's stdout default in UTF-8 mode and
    the C locale, which only covers \\udc80-\\udcff. A handler that can't fail
    is kept. The change is to the process's stream, as fits the entry point.
    """
    try:
        if isinstance(stream, io.TextIOWrapper) and stream.errors not in _NEVER_FAILING_ERRORS:
            stream.reconfigure(errors="backslashreplace")
    except (ValueError, OSError):  # closed or detached; a flush that failed
        pass


def _stderr_input(prompt: str) -> str:
    # Prompts go to stderr so stdout stays answers-only even when piped.
    sys.stderr.write(prompt)
    sys.stderr.flush()
    return sys.stdin.readline().rstrip("\n")


def _configure_logging(verbose: int) -> None:
    level = logging.WARNING if verbose == 0 else logging.INFO if verbose == 1 else logging.DEBUG
    logging.basicConfig(stream=sys.stderr, level=level, format="%(levelname)s: %(message)s")
    logging.getLogger("bigfix_remote_session_relevance").setLevel(level)
    for noisy in ("httpx", "httpcore"):
        logging.getLogger(noisy).setLevel(logging.DEBUG if verbose > 2 else logging.WARNING)


def _read_session_relevance(value: str | None) -> str:
    if value is None:
        raise _UsageError("a session relevance expression is required (or --setup)")
    text = sys.stdin.read() if value == "-" else value
    text = text.strip()
    if not text:
        raise _UsageError("the session relevance expression is empty")
    return text


def _parse_filters(values: list[str] | None) -> dict[str, str] | None:
    if not values:
        return None
    filters: dict[str, str] = {}
    for item in values:
        name, sep, condition = item.partition("=")
        if not sep or not name.strip() or not condition.strip():
            raise _UsageError(f"--filter must be TYPE=RELEVANCE, not {item!r}")
        filters[name.strip()] = condition.strip()
    return filters


def _apply_timeouts(config: Config, args: argparse.Namespace) -> Config:
    if args.connect_timeout is None and args.timeout is None:
        return config
    connections = tuple(
        dataclasses.replace(
            c,
            connect_timeout=c.connect_timeout
            if args.connect_timeout is None
            else args.connect_timeout,
            read_timeout=c.read_timeout if args.timeout is None else args.timeout,
        )
        for c in config.connections
    )
    return dataclasses.replace(config, connections=connections)


def _no_connections(
    args: argparse.Namespace, interactive: bool, ask: InputFn, secret: InputFn
) -> int:
    path = resolve_config_path(args.config)
    if interactive:
        answer = ask(f"No connections configured in {path}. Run setup now? [Y/n] ")
        if answer.strip().lower() in ("", "y", "yes"):
            from .setup_wizard import run_setup

            return run_setup(path, input_fn=ask, getpass_fn=secret)
    print(
        f"no connections configured in {path}; run: bigfix-remote-session-relevance --setup",
        file=sys.stderr,
    )
    return EXIT_USAGE


def _prompt_trust(info: CertInfo, ask: InputFn) -> bool:
    sys.stderr.write(
        f"\nThe certificate for {info.host_port} is not signed by a trusted CA.\n"
        f"  SHA-256 fingerprint: {info.fingerprint}\n"
        "Compare it with the server's certificate before trusting it.\n"
    )
    return ask("Trust and pin this certificate? [y/N] ").strip().lower() in ("y", "yes")


def _show_config(config: Config) -> int:
    rows = redacted_summary(config)
    print(f"# {config.path or '(no file)'} ({config.source})")
    if not rows:
        print("(no connections)")
        return 0
    columns = [
        "name",
        "backend",
        "server",
        "auth",
        "password",
        "token",
        "deployment_id",
        "verify",
        "enabled",
    ]
    table = [[_cell(c, r[c]) for c in columns] for r in rows]
    widths = [max(len(c), *(len(row[i]) for row in table)) for i, c in enumerate(columns)]
    print("  ".join(c.ljust(w) for c, w in zip(columns, widths, strict=True)))
    for row in table:
        print("  ".join(v.ljust(w) for v, w in zip(row, widths, strict=True)))
    return 0


def _cell(column: str, value: Any) -> str:
    if value is None:
        return "-"
    # A deployment id cached before ids were checked can hold server text.
    text = escape_controls(str(value))
    if column == "deployment_id":
        return f"{text[:12]}…"
    return text


def _show_certs() -> int:
    known = KnownCerts()
    pins = known.all()
    print(f"# {known.path}")
    for pin in pins:
        print(
            f"{pin.host_port}  sha256={pin.sha256[:16]}…  first_seen={pin.first_seen}  "
            f"trusted_by={pin.trusted_by}"
        )
    if not pins:
        print("(no pinned certificates)")
    return 0


def _forget_cert(host_port: str) -> int:
    if KnownCerts().forget(host_port):
        print(f"forgot the pinned certificate for {host_port}")
        return 0
    print(f"no pinned certificate for {host_port}", file=sys.stderr)
    return 1


def _trust_cert(target: str, config: Config, ask: InputFn) -> int:
    names = {c.name: c for c in config.connections}
    if target in names:
        address = names[target].address
    else:
        if ":" not in target.split("]")[-1]:
            raise _UsageError("--trust-cert needs a connection NAME or HOST:PORT")
        address = normalize_server(target, "rest")
    if address.scheme != "https":
        raise _UsageError(f"{target} uses http://; there is no certificate to trust")
    info = asyncio.run(fetch_server_cert(address.host, address.port))
    known = KnownCerts()
    existing = known.get(info.host_port)
    print(f"{info.host_port}\n  SHA-256 fingerprint: {info.fingerprint}")
    if existing and existing.sha256 == info.sha256:
        print("  already pinned with this fingerprint")
        return 0
    if existing:
        print(
            f"  REPLACES the pinned sha256 {existing.sha256[:16]}… "
            f"(first seen {existing.first_seen})"
        )
    if ask("Trust and pin this certificate? [y/N] ").strip().lower() not in ("y", "yes"):
        print("not pinned", file=sys.stderr)
        return 1
    known.pin(info, trusted_by="prompt")
    print(f"pinned in {known.path}")
    return 0


def _discover(config: Config, client_kwargs: dict[str, Any]) -> int:
    with SessionRelevanceClient(config, **client_kwargs) as client:
        found = client.discover_deployments(force=True)
    for name, deployment_id in found.items():
        # An id configured or cached before ids were checked can hold server text.
        shown = escape_controls(deployment_id) if deployment_id else "(not discovered)"
        print(f"{name}: {shown}")
    return 0 if any(found.values()) else 2


def run() -> None:  # pragma: no cover - console entry convenience
    sys.exit(main())
