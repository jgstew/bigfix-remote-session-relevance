"""Capture real server responses as redacted test fixtures.

    uv run python scripts/capture_fixtures.py [--config PATH] [--out tests/fixtures]

Runs a fixed set of probe queries against every enabled connection (through
the library itself, so TLS pinning and auth behave exactly as in use), plus
one deliberately wrong password per connection, and writes each raw response
to ``<out>/<backend>/captured/<case>.body`` with a ``.meta.json`` beside it.

REST answers differently depending on whether the root server can reach a
BigFix Explorer (see backends/rest.py), so note which state the deployment
was in: the committed REST captures without a prefix were taken with no
Explorer, the ``via_explorer__`` ones with Explorer. Capture into a scratch
``--out`` and copy across, rather than overwriting the other state's files.

Redaction: session tokens, IPv4 addresses, configured hosts, the gather URL
host and every configured username/password are replaced, and the deployment
hash is recomputed from the redacted gather URL so fixtures stay consistent.
Review the diff before committing anyway.
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
}
REDACTED_GATHER = "http://bigfix.example.com:52311/cgi-bin/bfgather.exe/actionsite"
_HASH_RE = re.compile(r"\b[0-9a-f]{64}\b")


async def capture(conn: ConnectionConfig, trust: TrustStore) -> dict[str, SessionRelevanceResult]:
    results: dict[str, SessionRelevanceResult] = {}
    async with backend_from_config(conn, trust=trust) as backend:
        for key, session_relevance in QUERIES.items():
            results[key] = await backend.evaluate(session_relevance)
    if conn.backend in ("rest", "explorer", "webreports") and conn.auth == "basic":
        # A fresh backend, so no session cookie or token from above is reused.
        wrong = dataclasses.replace(conn, password="definitely-wrong", password_env=None)  # noqa: S106
        async with backend_from_config(wrong, trust=trust) as backend:
            results["bad_password"] = await backend.evaluate("1")
    return results


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--config")
    parser.add_argument("--out", default="tests/fixtures", type=Path)
    args = parser.parse_args()

    config = load_config(args.config)
    # saas is a placeholder with nothing to capture yet.
    connections = tuple(c for c in config.enabled_connections() if c.backend != "saas")
    if not connections:
        print("no enabled connections", file=sys.stderr)
        return 1
    trust = TrustStore(KnownCerts())
    captured = asyncio.run(_capture_all(connections, trust))

    hosts: set[str] = {c.address.host for c in connections}
    secrets: set[str] = set()
    for conn in connections:
        secrets.update(filter(None, (conn.username, conn.resolve_password(), conn.resolve_token())))
    for results in captured.values():
        gather = results.get("gather_url_hash_check")
        for url in gather.answers if gather and gather.ok else ():
            hosts.add(urlsplit(str(url)).hostname or "")
    fake_hash = hashlib.sha256(REDACTED_GATHER.encode()).hexdigest()

    for conn, results in zip(connections, captured.values(), strict=True):
        out_dir = args.out / conn.backend / "captured"
        out_dir.mkdir(parents=True, exist_ok=True)
        for key, result in results.items():
            if result.raw is None:
                print(f"{conn.name} {key}: no response ({result.error})", file=sys.stderr)
                continue
            body = _HASH_RE.sub(fake_hash, redact(result.raw.text, hosts=hosts, secrets=secrets))
            meta = {"status": result.raw.status_code, "content_type": result.raw.content_type}
            (out_dir / f"{key}.body").write_text(body)
            (out_dir / f"{key}.meta.json").write_text(json.dumps(meta) + "\n")
            print(f"{conn.name:<24} {key:<24} {result.raw.status_code}")
    print(f"wrote fixtures under {args.out}; review the diff before committing")
    return 0


async def _capture_all(
    connections: tuple[ConnectionConfig, ...], trust: TrustStore
) -> dict[str, dict[str, SessionRelevanceResult]]:
    found = await asyncio.gather(*(capture(c, trust) for c in connections))
    return {c.name: r for c, r in zip(connections, found, strict=True)}


if __name__ == "__main__":
    sys.exit(main())
