"""Live checks against real servers (opt-in; auto-skipped without them).

Uses the connections in BFRSR_LIVE_CONFIG, or the default config path. The
file is read only through the library's loader; nothing from it is printed.
Pinned certs and discovered deployment ids stay in the test's tmp HOME.

    BFRSR_LIVE_TESTS=1 uv run pytest tests/integration -n0
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

import pytest

from bigfix_remote_session_relevance import AsyncSessionRelevanceClient, KnownCerts, TrustStore
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

# Numbers keep the server's text. The SaaS gateway re-encodes numbers as
# JavaScript numbers, so it has its own expectations (DESIGN.md § BigFix SaaS).
FLOATS = '("1.5" as floating point; "0.000001234" as floating point; "1e300" as floating point; "3" as floating point)'
NUMBER_CASES: dict[str, list[tuple[str, tuple[Any, ...], str | None, bool | None]]] = {
    "on_prem": [
        (FLOATS, ("1.5", "0.000001234", "1.0e+300", "3.0"), "floating point", True),
        ("9223372036854775807", (9223372036854775807,), "integer", False),
    ],
    "saas": [
        (FLOATS, ("1.5", "0.000001234", "1e+300", "3"), "floating point", True),
        ("9223372036854775807", (9223372036854776000,), "integer", False),
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
        for result in await client.evaluate("foo bar baz"):
            assert result.error is not None
            assert result.error.kind == "session_relevance"
            assert result.error.message == 'The operator "foo bar baz" is not defined.'


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
