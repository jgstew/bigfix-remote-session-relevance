"""Capture real server responses as redacted test fixtures.

    uv run python scripts/capture_fixtures.py [--config PATH] [--out tests/fixtures]
        [--backend NAME ...] [--only CASE ...]

Runs a fixed set of probe queries against every enabled connection (through
the library itself, so TLS pinning and auth behave exactly as in use), plus
one deliberately wrong password per on-prem connection (never BigFix SaaS,
where failed logins count toward a permanent lock), and writes each raw
response to ``<out>/<backend>/captured/<case>.body`` with a ``.meta.json``
beside it; SaaS responses go to ``<out>/saas/captured/<case>.json`` (body
only, the existing SaaS fixture form). ``--backend`` and ``--only`` limit the
run, e.g. to add one case without re-capturing the rest.

REST answers differently depending on whether the root server can reach a
BigFix Explorer (see backends/rest.py), so note which state the deployment
was in: the committed REST captures without a prefix were taken with no
Explorer, the ``via_explorer__`` ones with Explorer. Capture into a scratch
``--out`` and copy across, rather than overwriting the other state's files.

REST connections also GET the root server's lists of registered Explorer
and Web Reports servers (``REST_GETS``, XML) into ``rest/captured/discovery/``.
A 200 is written as ``<case>``, anything else as ``<case>_<status>``: these
need a master operator, and the 403 an operator gets is worth keeping too.

Redaction: session tokens, IPv4 addresses, configured hosts, the gather URL
host and every configured username/password are replaced, and every 64-hex
value (the deployment hash) becomes the sha256 of REDACTED_GATHER, which is
what an on-prem gather URL redacts to, so the two fixtures stay consistent.
The gather URL is always asked for, even with ``--only``, so its host is
redacted. BigFix SaaS's ``deployment_id`` / ``gather_url_hash_check`` are not
written: its gather URL need not redact to REDACTED_GATHER, and its committed
id is synthetic. Review the diff before committing anyway.
"""

from __future__ import annotations

import argparse
import asyncio
import dataclasses
import hashlib
import json
import re
import sys
from pathlib import Path
from urllib.parse import urlsplit

import httpx

from bigfix_remote_session_relevance import KnownCerts, TrustStore, load_config
from bigfix_remote_session_relevance.backends.registry import backend_from_config
from bigfix_remote_session_relevance.config import ConnectionConfig
from bigfix_remote_session_relevance.redact import redact
from bigfix_remote_session_relevance.result import SessionRelevanceResult

QUERIES = {
    "singular_integer": "number of bes sites",
    "plural_integers": "(1;2;3)",
    "plural_strings": '("alpha";"beta")',
    "empty_plural": "(1;2) whose (it > 5)",
    "singular_string": '"hello"',
    "boolean": "true",
    "time": "now",
    "float": "1.5",
    "tuple": '(1, "a", true)',
    "plural_tuples": '((1, "a"); (2, "b"))',
    "nested_tuple": '(1, (2, "x"))',
    "error_unknown": "foo bar baz",
    "error_type": '1 + "a"',
    "deployment_id": "sha256 of gather url of bes license",
    "gather_url_hash_check": "gather url of bes license",
    # Web Reports keeps qna-style %xx escapes in answer text (issue #5).
    "escaped_strings": '("a%25b"; "a%2541"; "x%0Ay"; "a%09b"; "a%01b"; "a%7Fb")',
    "escaped_tuple": '("a%25b", 1)',
    "error_escaped": 'error "a%25b%09c"',
    # Types beyond integer/string/boolean/time. "float" above is a literal
    # 1.5, which session relevance rejects; these are real floating points.
    # The server's JSON number text is what Web Reports sends as text.
    "floating_point": '"1.5" as floating point',
    "floating_point_plural": (
        '("1.5" as floating point; "-2.25" as floating point; "3" as floating point)'
    ),
    "floating_point_small": '"0.000001234" as floating point',
    "floating_point_large": '"1e300" as floating point',
    "floating_point_tiny": '"0.0000001" as floating point',
    "floating_point_rounding": '"0.30000000000000004" as floating point',
    "integer_above_2_53": "9007199254740993",
    "date": 'date "17 Oct 2026"',
    "time_of_day": 'time_of_day "13:45:00"',
    "time_interval": "(now - (now - 90*minute))",
    "version": '"11.0.7" as version',
    # PRESERVED below, or redact() would take it for an IPv4 address.
    "version_four_part": '"11.0.7.48" as version',
    "date_parts": (
        "(day_of_week of it, month of it, year of it, day_of_month of it, "
        'month_and_year of it) of date "17 Oct 2026"'
    ),
    "big_integer": "9223372036854775807",
    "negative_integer": "(0 - 5)",
    "empty_string": '""',
    "tuple_mixed": '(date "17 Oct 2026", "1.5" as floating point, "1.2" as version)',
    # The live suite's special characters: REST's URL decoding and SOAP's XML
    # escaping must leave them intact (%22 is relevance's own quote escape).
    "special_chars": "\"a+b & c %22 <q> 's' \\ / ?x=1#y\"",
    # BigFix's floating point text in more shapes (the SaaS gateway's differs).
    "floating_point_forms": (
        '("2.5e-8" as floating point; "100" as floating point; "0" as floating point; '
        '"-0.5" as floating point; "-1e300" as floating point; "1234567" as floating point; '
        '"123456789012.5" as floating point; "1e100" as floating point)'
    ),
    # Evaluation errors beyond an unknown operator.
    "error_too_large": '"12345678901234567890" as floating point',
    # A plural of objects with no string form: every backend answers that
    # the "string" operator (used to render answers) is not defined.
    "error_no_string": "(bes sites) whose (master site flag of it)",
    "error_nonexistent": '"3 days 04:05:06" as time interval',
}
# Root server REST lists that --setup reads; never their JSON forms, whose
# Web Reports entries carry each server's token.
REST_GETS = {"explorers": "/api/explorers", "webreports": "/api/webreports"}
# Probe literals redact() would take for an IPv4 address, kept only in the
# body of their own case and only as a whole value.
PRESERVED = {"version_four_part": ("11.0.7.48",)}
REDACTED_GATHER = "http://bigfix.example.com:52311/cgi-bin/bfgather.exe/actionsite"
_SAAS_NOT_WRITTEN = frozenset({"deployment_id", "gather_url_hash_check"})
_HASH_RE = re.compile(r"\b[0-9a-f]{64}\b")


async def capture(
    conn: ConnectionConfig, trust: TrustStore, only: set[str] | None = None
) -> dict[str, SessionRelevanceResult | httpx.Response]:
    results: dict[str, SessionRelevanceResult | httpx.Response] = {}
    async with backend_from_config(conn, trust=trust) as backend:
        for key, session_relevance in QUERIES.items():
            # The gather URL always: its host must be redacted from the rest.
            if only is None or key in only or key == "gather_url_hash_check":
                results[key] = await backend.evaluate(session_relevance)
        for key, url in REST_GETS.items() if conn.backend == "rest" else ():
            if only is None or key in only:
                # Through _with_trust, so auth and pinning are the library's own.
                response = await backend._with_trust(lambda c, url=url: c.get(url))
                if isinstance(response, httpx.Response):
                    results[key] = response
                else:
                    print(f"{conn.name} {key}: no response ({response})", file=sys.stderr)
    wanted = only is None or "bad_password" in only
    if wanted and conn.backend in ("rest", "explorer", "webreports") and conn.auth == "basic":
        # A fresh backend, so no session cookie or token from above is reused.
        wrong = dataclasses.replace(conn, password="definitely-wrong", password_env=None)  # noqa: S106
        async with backend_from_config(wrong, trust=trust) as backend:
            results["bad_password"] = await backend.evaluate("1")
    return results


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--config")
    parser.add_argument("--out", default="tests/fixtures", type=Path)
    parser.add_argument("--backend", action="append", help="only connections of this backend")
    parser.add_argument("--only", action="append", metavar="CASE", help="only this case")
    args = parser.parse_args()
    only = set(args.only) if args.only else None
    if only and (unknown := only - set(QUERIES) - set(REST_GETS) - {"bad_password"}):
        parser.error(f"unknown cases: {', '.join(sorted(unknown))}")

    config = load_config(args.config)
    connections = tuple(
        c for c in config.enabled_connections() if not args.backend or c.backend in args.backend
    )
    if not connections:
        print("no enabled connections", file=sys.stderr)
        return 1
    trust = TrustStore(KnownCerts())
    captured = asyncio.run(_capture_all(connections, trust, only))

    hosts: set[str] = {c.address.host for c in connections}
    secrets: set[str] = set()
    for conn in connections:
        secrets.update(filter(None, (conn.username, conn.resolve_password(), conn.resolve_token())))
    for results in captured.values():
        gather = results.get("gather_url_hash_check")
        if not isinstance(gather, SessionRelevanceResult):
            gather = None
        for url in gather.answers if gather and gather.ok else ():
            hosts.add(urlsplit(str(url)).hostname or "")
    fake_hash = hashlib.sha256(REDACTED_GATHER.encode()).hexdigest()

    for conn, results in zip(connections, captured.values(), strict=True):
        out_dir = args.out / conn.backend / "captured"
        out_dir.mkdir(parents=True, exist_ok=True)
        for key, result in results.items():
            if only is not None and key not in only:
                continue
            if isinstance(result, httpx.Response):
                body = _HASH_RE.sub(fake_hash, _redact(result.text, hosts, secrets, key))
                name = key if result.status_code == 200 else f"{key}_{result.status_code}"
                print(f"{conn.name:<24} {name:<24} {result.status_code}")
                _write(out_dir / "discovery", name, body, result)
                continue
            if conn.backend == "saas" and key in _SAAS_NOT_WRITTEN:
                print(f"{conn.name} {key}: not written for BigFix SaaS", file=sys.stderr)
                continue
            if result.raw is None:
                print(f"{conn.name} {key}: no response ({result.error})", file=sys.stderr)
                continue
            body = _HASH_RE.sub(fake_hash, _redact(result.raw.text, hosts, secrets, key))
            print(f"{conn.name:<24} {key:<24} {result.raw.status_code}")
            if conn.backend == "saas":
                (out_dir / f"{key}.json").write_text(body)
                continue
            meta = {"status": result.raw.status_code, "content_type": result.raw.content_type}
            (out_dir / f"{key}.body").write_text(body)
            (out_dir / f"{key}.meta.json").write_text(json.dumps(meta) + "\n")
    print(f"wrote fixtures under {args.out}; review the diff before committing")
    return 0


def _write(out_dir: Path, name: str, body: str, response: httpx.Response) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    meta = {"status": response.status_code, "content_type": response.headers.get("content-type")}
    (out_dir / f"{name}.body").write_text(body)
    (out_dir / f"{name}.meta.json").write_text(json.dumps(meta) + "\n")


def _redact(text: str, hosts: set[str], secrets: set[str], case: str) -> str:
    """`redact`, leaving `case`'s PRESERVED literals as they are.

    Secrets go first, so a secret containing a literal is still replaced;
    then each literal is protected only where it stands alone (the same
    boundaries as redact's IPv4 match), so 111.0.7.48 is not.
    """
    if "\x00" in text:
        sys.exit("refusing to redact a response containing NUL")
    literals = PRESERVED.get(case, ())
    if clash := set(literals) & {h.lower() for h in hosts}:
        sys.exit(f"a PRESERVED literal is a configured host: {', '.join(sorted(clash))}")
    for secret in sorted((s for s in secrets if s), key=len, reverse=True):
        text = text.replace(secret, "REDACTED")
    for i, literal in enumerate(literals):
        text = re.sub(rf"(?<![\d.]){re.escape(literal)}(?![\d.])", f"\x00{i}\x00", text)
    text = redact(text, hosts=hosts, secrets=secrets)
    for i, literal in enumerate(literals):
        text = text.replace(f"\x00{i}\x00", literal)
    return text


async def _capture_all(
    connections: tuple[ConnectionConfig, ...], trust: TrustStore, only: set[str] | None
) -> dict[str, dict[str, SessionRelevanceResult | httpx.Response]]:
    found = await asyncio.gather(*(capture(c, trust, only) for c in connections))
    return {c.name: r for c, r in zip(connections, found, strict=True)}


if __name__ == "__main__":
    sys.exit(main())
