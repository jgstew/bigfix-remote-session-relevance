"""Live checks against real servers (opt-in; auto-skipped without them).

Uses the connections in BFRSR_LIVE_CONFIG, or the default config path. The
file is read only through the library's loader; nothing from it is printed.
Pinned certs and discovered deployment ids stay in the test's tmp HOME.

    BFRSR_LIVE_TESTS=1 uv run pytest tests/integration -n0
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import time
from pathlib import Path
from typing import Any

import pytest

from bigfix_remote_session_relevance import (
    AsyncSessionRelevanceClient,
    KnownCerts,
    RestBackend,
    TrustStore,
)
from bigfix_remote_session_relevance.config import load_config
from bigfix_remote_session_relevance.deployment import (
    DEPLOYMENT_ID_SESSION_RELEVANCE,
    GATHER_URL_RELEVANCE,
)

SPECIAL = "a+b & c %22 <q> 's' \\ / ?x=1#y"

CASES: list[tuple[str, tuple[Any, ...], str | None, bool | None]] = [
    ("(1;2;3)", (1, 2, 3), "integer", True),
    ('("alpha";"beta")', ("alpha", "beta"), "string", True),
    ("(1;2) whose (it > 5)", (), "integer", True),
    ('(1, "a", true)', ((1, "a", True),), "( integer, string, boolean )", False),
    ('(1, (2, "x"))', ((1, (2, "x")),), "( integer, ( integer, string ) )", False),
    # %22 inside a relevance string literal is relevance's own escape for a
    # double quote, so the server answers with '"'. Everything else must
    # survive the REST API's double URL-decoding and SOAP's XML escaping intact.
    ('"' + SPECIAL + '"', (SPECIAL.replace("%22", '"'),), "string", False),
    # Types other than integer/boolean are strings, the same on every backend.
    ('date "17 Oct 2026"', ("Sat, 17 Oct 2026",), "date", False),
    ('time_of_day "13:45:00"', ("13:45:00",), "time of day", False),
    ("(now - (now - 90*minute))", ("01:30:00",), "time interval", False),
    ('"11.0.7.48" as version', ("11.0.7.48",), "version", False),
    (
        (
            "(day_of_week of it, month of it, year of it, day_of_month of it, "
            'month_and_year of it) of date "17 Oct 2026"'
        ),
        (("Saturday", "October", "2026", "17", "October 2026"),),
        "( day of week, month, year, day of month, month and year )",
        False,
    ),
    ("(0 - 5)", (-5,), "integer", False),
    ('""', ("",), "string", False),
]

# The same message on every backend (SaaS's mangled exception name included).
ERROR_CASES = [
    ("foo bar baz", 'The operator "foo bar baz" is not defined.'),
    (
        '"12345678901234567890" as floating point',
        "The expression could not be evaluated: class TooLargeForStandardNotation",
    ),
    ('"3 days 04:05:06" as time interval', "Singular expression refers to nonexistent object."),
]

# Numbers keep the server's text. The SaaS gateway re-encodes numbers as
# JavaScript numbers, so it has its own expectations (DESIGN.md § BigFix SaaS).
FLOATS = (
    '("1.5" as floating point; "0.000001234" as floating point; '
    '"1e300" as floating point; "3" as floating point)'
)
FORMS = (
    '("2.5e-8" as floating point; "100" as floating point; "0" as floating point; '
    '"-0.5" as floating point; "-1e300" as floating point)'
)
NUMBER_CASES: dict[str, list[tuple[str, tuple[Any, ...], str | None, bool | None]]] = {
    "on_prem": [
        (FLOATS, ("1.5", "0.000001234", "1.0e+300", "3.0"), "floating point", True),
        ("9223372036854775807", (9223372036854775807,), "integer", False),
        (FORMS, ("0.000000025", "100.0", "0.0", "-0.5", "-1.0e+300"), "floating point", True),
    ],
    "saas": [
        (FLOATS, ("1.5", "0.000001234", "1e+300", "3"), "floating point", True),
        ("9223372036854775807", (9223372036854776000,), "integer", False),
        (FORMS, ("2.5e-8", "100", "0", "-0.5", "-1e+300"), "floating point", True),
    ],
}


async def _client(
    backend: str, live_config_path: Path, tmp_path: Path
) -> AsyncSessionRelevanceClient:
    return AsyncSessionRelevanceClient(
        load_config(live_config_path),
        mode="all",
        backends=[backend],
        trust=TrustStore(KnownCerts(tmp_path / "known.toml")),
        record_deployment_ids=False,
    )


def _params(backend: str) -> list[Any]:
    marker = getattr(pytest.mark, f"live_{backend}")
    cases = CASES + NUMBER_CASES["saas" if backend == "saas" else "on_prem"]
    return [pytest.param(backend, *case, marks=marker, id=f"{backend}-{case[0]}") for case in cases]


@pytest.mark.parametrize(
    ("backend", "session_relevance", "answers", "type_", "plural"),
    _params("rest") + _params("webreports") + _params("explorer") + _params("saas"),
)
async def test_live_normalized_results(
    backend: str,
    session_relevance: str,
    answers: tuple[Any, ...],
    type_: str | None,
    plural: bool | None,
    live_config_path: Path,
    tmp_path: Path,
) -> None:
    async with await _client(backend, live_config_path, tmp_path) as client:
        for result in await client.evaluate(session_relevance):
            assert result.ok, result.error
            assert (result.answers, result.type, result.plural) == (answers, type_, plural)


@pytest.mark.parametrize(
    "backend",
    [
        pytest.param(b, marks=getattr(pytest.mark, f"live_{b}"))
        for b in ("rest", "webreports", "explorer", "saas")
    ],
)
async def test_live_relevance_error(backend: str, live_config_path: Path, tmp_path: Path) -> None:
    async with await _client(backend, live_config_path, tmp_path) as client:
        for session_relevance, message in ERROR_CASES:
            for result in await client.evaluate(session_relevance):
                assert result.error is not None
                assert result.error.kind == "session_relevance"
                assert result.error.message == message


@pytest.mark.parametrize(
    "backend",
    [
        pytest.param(b, marks=getattr(pytest.mark, f"live_{b}"))
        for b in ("rest", "webreports", "explorer", "saas")
    ],
)
async def test_live_deployment_id_matches_local_hash(
    backend: str, live_config_path: Path, tmp_path: Path
) -> None:
    async with await _client(backend, live_config_path, tmp_path) as client:
        hashed = await client.evaluate(DEPLOYMENT_ID_SESSION_RELEVANCE)
        urls = await client.evaluate(GATHER_URL_RELEVANCE)
    for h, u in zip(hashed, urls, strict=True):
        assert h.ok and u.ok, (h.error, u.error)
        assert h.answers == tuple(hashlib.sha256(str(a).encode()).hexdigest() for a in u.answers)


@pytest.mark.live_rest
async def test_live_client_query_round_trip(live_config_path: Path, tmp_path: Path) -> None:
    """BigFix Query: submit ``computer name`` to one computer and poll for its row.

    Needs ``BFRSR_LIVE_CLIENT_QUERY_COMPUTER_ID`` (a computer on that
    deployment that answers quickly); ``BFRSR_LIVE_CLIENT_QUERY_CONNECTION``
    picks the REST connection, else the first enabled one is used.
    """
    computer_id = os.environ.get("BFRSR_LIVE_CLIENT_QUERY_COMPUTER_ID")
    if not computer_id:
        pytest.skip("set BFRSR_LIVE_CLIENT_QUERY_COMPUTER_ID to a computer that answers queries")
    wanted = os.environ.get("BFRSR_LIVE_CLIENT_QUERY_CONNECTION")
    conn = next(
        c
        for c in load_config(live_config_path).connections
        if c.enabled and c.backend == "rest" and (wanted is None or c.name == wanted)
    )
    trust = TrustStore(KnownCerts(tmp_path / "known.toml"))
    async with RestBackend.from_config(conn, trust=trust) as backend:
        submitted = await backend.submit_client_query("computer name", [int(computer_id)])
        assert submitted.ok, submitted.error
        assert submitted.query_id is not None
        deadline = time.monotonic() + 60
        while True:
            results = await backend.client_query_results(submitted.query_id)
            assert results.ok, results.error
            if results.rows or time.monotonic() > deadline:
                break
            await asyncio.sleep(2)
    (row,) = results.rows
    assert row.computer_id == int(computer_id)
    assert not row.is_failure
    assert row.result == row.computer_name
