"""Explorer extras are additive: a separate API, never sent by plain evaluate()."""

from __future__ import annotations

import json

import httpx
import pytest

from bigfix_remote_session_relevance.backends.explorer import ExplorerBackend
from bigfix_remote_session_relevance.backends.explorer_extras import (
    FILTER_TYPES,
    supports_explorer_extras,
)
from bigfix_remote_session_relevance.backends.rest import RestBackend
from bigfix_remote_session_relevance.backends.webreports import WebReportsBackend

KEYED = {
    "result": [
        {"id": 1, "computer_name": "a", "agent": {"version": "11.0.6", "type": "Native"}},
        {"id": 2, "computer_name": "b", "agent": {"version": "11.0.5", "type": "Native"}},
    ],
    "count": 2,
    "plural": True,
    "type": "( integer, string, ( string, string ) )",
    "evaltime_ms": 3.1,
}
KEYS = "id computer_name agent { version type }"


def test_capability_check() -> None:
    assert supports_explorer_extras(ExplorerBackend("h"))
    assert supports_explorer_extras(RestBackend("h"))
    assert not supports_explorer_extras(WebReportsBackend("h"))


def test_filter_types() -> None:
    assert frozenset({"actions", "computers", "computergroups", "content", "sites"}) == FILTER_TYPES


async def test_explorer_keys_and_filters_body(recording_transport: type) -> None:
    rec = recording_transport([httpx.Response(200, json=KEYED)])
    async with ExplorerBackend("ex", username="u", password="p", transport=rec.transport) as b:
        result = await b.evaluate_explorer(
            "(id of it, name of it, (agent version of it, agent type of it)) of bes computers",
            keys=KEYS,
            filters={"computers": 'exists true whose (if true then (name of it = "a") else false)'},
        )
    body = json.loads(rec.requests[0].content)
    assert str(rec.requests[0].url) == "https://ex:9383/api/relevance"
    assert body["keys"] == KEYS
    assert body["filters"] == {
        "computers": 'exists true whose (if true then (name of it = "a") else false)'
    }
    # Keyed results are dicts, left as the server built them.
    assert result.answers[0] == KEYED["result"][0]
    assert result.answer_strings[0].startswith('{"id": 1')
    assert result.backend == "explorer"


async def test_explorer_extras_without_keys_or_filters_omits_them(
    recording_transport: type,
) -> None:
    rec = recording_transport([httpx.Response(200, json=KEYED)])
    async with ExplorerBackend("ex", username="u", password="p", transport=rec.transport) as b:
        await b.evaluate_explorer("q")
    assert json.loads(rec.requests[0].content) == {"relevance": "q"}


async def test_rest_forwards_extras_with_json_relevance_content_type(
    recording_transport: type,
) -> None:
    rec = recording_transport([httpx.Response(200, json=KEYED)])
    async with RestBackend("root", username="u", password="p", transport=rec.transport) as b:
        result = await b.evaluate_explorer("q", keys=KEYS)
    req = rec.requests[0]
    assert str(req.url) == "https://root:52311/api/query"
    assert req.headers["content-type"] == "application/json+relevance"
    assert json.loads(req.content) == {"relevance": "q", "keys": KEYS}
    assert result.ok
    assert result.backend == "rest"


async def test_plain_evaluate_on_rest_sends_no_extras(recording_transport: type) -> None:
    rec = recording_transport([httpx.Response(200, json={"result": [1], "type": "integer"})])
    async with RestBackend("root", username="u", password="p", transport=rec.transport) as b:
        await b.evaluate("1")
    assert json.loads(rec.requests[0].content) == {"relevance": "1"}


@pytest.mark.parametrize("bad", [{"computer": "x"}, {"computers": 3}])
async def test_bad_filters_raise(bad: dict[str, object]) -> None:
    async with ExplorerBackend("ex", username="u", password="p") as b:
        with pytest.raises((ValueError, TypeError), match="filter"):
            await b.evaluate_explorer("q", filters=bad)  # type: ignore[arg-type]


async def test_bad_keys_raise() -> None:
    async with ExplorerBackend("ex", username="u", password="p") as b:
        with pytest.raises(ValueError, match="keys"):
            await b.evaluate_explorer("q", keys="id; drop")
