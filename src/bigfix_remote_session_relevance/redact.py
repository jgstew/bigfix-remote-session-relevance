"""Redact captured server responses before they become test fixtures.

Session tokens, IPv4 addresses, configured hostnames and any explicitly
listed secrets (usernames, passwords) are replaced, so a capture can be
committed or pasted into an issue.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

_TOKEN_RE = re.compile(r"(<(?:\w+:)?sessionToken>)[^<]*(</(?:\w+:)?sessionToken>)")
_IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")


def redact(
    text: str,
    *,
    hosts: Iterable[str | None] = (),
    secrets: Iterable[str | None] = (),
) -> str:
    out = _TOKEN_RE.sub(r"\1REDACTED\2", text)
    for secret in sorted((s for s in secrets if s), key=len, reverse=True):
        out = out.replace(secret, "REDACTED")
    for host in sorted((h for h in hosts if h), key=len, reverse=True):
        out = re.sub(re.escape(host), "bigfix.example.com", out, flags=re.IGNORECASE)

    mapping: dict[str, str] = {}

    def _ip(match: re.Match[str]) -> str:
        found = match.group(0)
        if found not in mapping:
            mapping[found] = f"192.0.2.{len(mapping) + 1}"
        return mapping[found]

    return _IPV4_RE.sub(_ip, out)
