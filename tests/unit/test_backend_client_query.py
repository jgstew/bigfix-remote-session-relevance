"""ClientQuery is additive: a separate, opt-in API on RestBackend (and SaasBackend).

The wire tests replay responses captured from an 11.x root server
(``tests/fixtures/rest/captured/clientquery/``, see tests/fixtures/README.md).
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path
from xml.etree.ElementTree import Element

import defusedxml.ElementTree as SafeET
import httpx
import pytest

from bigfix_remote_session_relevance.backends.client_query import (
    ClientQueryResponse,
    ClientQueryRow,
    client_query_body,
    client_query_max_targets,
    supports_client_query,
)
from bigfix_remote_session_relevance.backends.explorer import ExplorerBackend
from bigfix_remote_session_relevance.backends.rest import RestBackend
from bigfix_remote_session_relevance.backends.saas import SaasBackend
from bigfix_remote_session_relevance.backends.webreports import WebReportsBackend

CAPTURED = Path(__file__).parent.parent / "fixtures" / "rest" / "captured" / "clientquery"
# The redacted computer that answered every captured query.
COMPUTER = (1000001, "COMPUTER-1")


def _captured(key: str) -> httpx.Response:
    meta = json.loads((CAPTURED / f"{key}.meta.json").read_text())
    headers = {"content-type": meta["content_type"]} if meta["content_type"] else {}
    return httpx.Response(
        meta["status"], text=(CAPTURED / f"{key}.body").read_text(), headers=headers
    )


def _rest(transport: httpx.MockTransport, **kw: object) -> RestBackend:
    kw.setdefault("username", "u")
    kw.setdefault("password", "p")
    return RestBackend("bf", connection="lab", transport=transport, **kw)


def _sent(request: httpx.Request) -> Element:
    return SafeET.fromstring(request.content)


async def test_submit_posts_xml_with_computer_ids(recording_transport: type) -> None:
    rec = recording_transport([_captured("submit_single")])
    async with _rest(rec.transport) as b:
        response = await b.submit_client_query("computer name", [1000001, 2000002])
    request = rec.requests[0]
    assert request.method == "POST"
    assert str(request.url) == "https://bf:52311/api/clientquery"
    assert request.headers["content-type"] == "application/xml"
    root = _sent(request)
    assert root.tag == "BESAPI"
    query = root.find("ClientQuery")
    assert query is not None
    assert [child.tag for child in query] == ["ApplicabilityRelevance", "QueryText", "Target"]
    assert query.findtext("ApplicabilityRelevance") == "true"
    assert query.findtext("QueryText") == "computer name"
    assert [e.text for e in query.findall("Target/ComputerID")] == ["1000001", "2000002"]
    assert response.ok, response.error
    assert (response.query_id, response.rows) == (210, [])
    assert (response.connection, response.backend) == ("lab", "rest")
    assert response.server == "https://bf:52311"
    assert response.elapsed_ms >= 0


async def test_submit_escapes_client_relevance(recording_transport: type) -> None:
    # The same expression went to a real client (submit_escaped / results_escaped).
    client_relevance = '"a<b" & "&" & "%22c%22"'
    rec = recording_transport([_captured("submit_escaped")])
    async with _rest(rec.transport) as b:
        await b.submit_client_query(client_relevance, [1000001])
    raw = rec.requests[0].content.decode()
    assert "&lt;b" in raw
    assert "&amp;" in raw
    assert _sent(rec.requests[0]).findtext("ClientQuery/QueryText") == client_relevance


async def test_escaped_client_relevance_round_trips(recording_transport: type) -> None:
    rec = recording_transport([_captured("results_escaped")])
    async with _rest(rec.transport) as b:
        response = await b.client_query_results(213)
    assert [r.result for r in response.rows] == ['a<b&"c"']


@pytest.mark.parametrize("computer_ids", [[], ()])
async def test_submit_requires_computer_ids(
    recording_transport: type, computer_ids: list[int]
) -> None:
    rec = recording_transport([_captured("submit_single")])
    async with _rest(rec.transport) as b:
        with pytest.raises(ValueError, match="computer_ids"):
            await b.submit_client_query("computer name", computer_ids)
    assert rec.requests == []


@pytest.mark.parametrize("bad", [["1"], [True], [1.5]])
async def test_submit_rejects_non_integer_computer_ids(
    recording_transport: type, bad: list[object]
) -> None:
    rec = recording_transport([_captured("submit_single")])
    async with _rest(rec.transport) as b:
        with pytest.raises(TypeError, match="computer_ids"):
            await b.submit_client_query("computer name", bad)  # type: ignore[arg-type]
    assert rec.requests == []


async def test_submit_reads_query_id_ignoring_resource_url(recording_transport: type) -> None:
    # (observed) Resource is http://...:52311 although the request was https.
    assert 'Resource="http://' in (CAPTURED / "submit_plural.body").read_text()
    rec = recording_transport([_captured("submit_plural")])
    async with _rest(rec.transport) as b:
        response = await b.submit_client_query("names of drives", [1000001])
    assert response.query_id == 211
    assert len(rec.requests) == 1


@pytest.mark.parametrize(
    ("key", "rows"),
    [
        ("results_pending", []),
        ("results_single", [ClientQueryRow(*COMPUTER, is_failure=False, result="COMPUTER-1")]),
        # A plural answer is one row per value, from the same computer.
        (
            "results_plural",
            [
                ClientQueryRow(*COMPUTER, is_failure=False, result="C:"),
                ClientQueryRow(*COMPUTER, is_failure=False, result="E:"),
            ],
        ),
        (
            "results_failing",
            [
                ClientQueryRow(
                    *COMPUTER,
                    is_failure=True,
                    result='The operator "foo bar baz" is not defined.',
                )
            ],
        ),
    ],
)
async def test_results_get_json_and_map_rows(
    recording_transport: type, key: str, rows: list[ClientQueryRow]
) -> None:
    rec = recording_transport([_captured(key)])
    async with _rest(rec.transport) as b:
        response = await b.client_query_results(210)
    request = rec.requests[0]
    assert request.method == "GET"
    assert request.url.path == "/api/clientqueryresults/210"
    assert dict(request.url.params) == {"output": "json"}
    assert response.ok, response.error
    assert response.query_id == 210
    assert response.rows == rows


async def test_basic_and_bearer_auth_are_sent(recording_transport: type) -> None:
    rec = recording_transport([_captured("submit_single"), _captured("results_single")])
    async with _rest(rec.transport) as b:
        await b.submit_client_query("computer name", [1000001])
        await b.client_query_results(210)
    assert all(r.headers["authorization"].startswith("Basic ") for r in rec.requests)

    rec = recording_transport([_captured("submit_single"), _captured("results_single")])
    async with _rest(rec.transport, username=None, password=None, token="t0k") as b:
        await b.submit_client_query("computer name", [1000001])
        await b.client_query_results(210)
    assert [r.headers["authorization"] for r in rec.requests] == ["Bearer t0k"] * 2


async def test_missing_password_is_a_result_and_sends_nothing(recording_transport: type) -> None:
    rec = recording_transport([_captured("submit_single")])
    async with _rest(rec.transport, password=None) as b:
        response = await b.submit_client_query("computer name", [1000001])
    assert response.error is not None
    assert response.error.kind == "authentication"
    assert rec.requests == []


async def test_permission_denied_mentions_can_submit_queries(recording_transport: type) -> None:
    # Synthetic body: no non-master operator without the permission was
    # available to capture one. The mapping keys on "permission" in the text.
    denied = httpx.Response(403, text="User does not have permission to submit client queries")
    rec = recording_transport([denied])
    async with _rest(rec.transport) as b:
        submitted = await b.submit_client_query("computer name", [1000001])
        fetched = await b.client_query_results(210)
    for response in (submitted, fetched):
        assert response.error is not None
        assert (response.error.kind, response.error.code) == (
            "authentication",
            "permission_denied",
        )
        assert response.error.http_status == 403
        assert "Can Submit Queries" in response.error.message
    assert fetched.query_id == 210


async def test_rejected_credentials_are_authentication(recording_transport: type) -> None:
    rec = recording_transport([httpx.Response(401, text="Login failed")])
    async with _rest(rec.transport) as b:
        response = await b.submit_client_query("computer name", [1000001])
    assert response.error is not None
    assert (response.error.kind, response.error.code) == ("authentication", None)
    assert "Can Submit Queries" not in response.error.message


async def test_errors_are_results_not_raises(recording_transport: type) -> None:
    # (observed) Another operator's or an unknown query id is a 400.
    rec = recording_transport([_captured("results_unknown_id")])
    async with _rest(rec.transport) as b:
        response = await b.client_query_results(999999999)
    assert response.error is not None
    assert (response.error.kind, response.error.http_status) == ("http", 400)
    assert "not submitted by the logged user" in response.error.message
    assert (response.query_id, response.rows) == (999999999, [])

    rec = recording_transport([httpx.ReadTimeout("slow")])
    async with _rest(rec.transport) as b:
        response = await b.submit_client_query("computer name", [1000001])
    assert response.error is not None
    assert response.error.kind == "timeout"
    assert response.query_id is None

    rec = recording_transport([httpx.ConnectError("refused")])
    async with _rest(rec.transport) as b:
        response = await b.client_query_results(210)
    assert response.error is not None
    assert response.error.kind == "connection"


@pytest.mark.parametrize(
    "body",
    [
        "<html>login</html>",
        "<BESAPI><ClientQuery/></BESAPI>",  # no <ID>
        "<BESAPI><ClientQuery><ID>abc</ID></ClientQuery></BESAPI>",
        "<BESAPI><ClientQuery><ID>1",  # truncated
        "",
    ],
)
async def test_malformed_submit_body_is_response_format(
    recording_transport: type, body: str
) -> None:
    rec = recording_transport([httpx.Response(200, text=body)])
    async with _rest(rec.transport) as b:
        response = await b.submit_client_query("computer name", [1000001])
    assert response.error is not None
    assert response.error.kind == "response_format"
    assert response.error.backend == "rest"
    assert response.query_id is None


@pytest.mark.parametrize(
    "body",
    [
        "not json",
        "[]",
        '{"result": []}',
        '{"results": {}}',
        '{"results": [{"computerID": 1, "computerName": "a", "isFailure": false}]}',
        '{"results": [{"computerID": "1", "computerName": "a", "isFailure": false, "result": ""}]}',
        '{"results": [{"computerID": 1, "computerName": "a", "isFailure": 0, "result": ""}]}',
    ],
)
async def test_malformed_results_body_is_response_format(
    recording_transport: type, body: str
) -> None:
    rec = recording_transport([httpx.Response(200, text=body)])
    async with _rest(rec.transport) as b:
        response = await b.client_query_results(210)
    assert response.error is not None
    assert response.error.kind == "response_format"
    assert (response.query_id, response.rows) == (210, [])


async def test_plain_evaluate_is_unchanged(recording_transport: type) -> None:
    rec = recording_transport([httpx.Response(200, json={"result": [1], "plural": False})])
    async with _rest(rec.transport) as b:
        await b.evaluate("1")
    assert rec.requests[0].url.path == "/api/query"


def test_supports_client_query() -> None:
    assert supports_client_query(RestBackend("h"))
    assert not supports_client_query(ExplorerBackend("h"))
    assert not supports_client_query(WebReportsBackend("h"))
    assert supports_client_query(SaasBackend("login.bigfix.com"))


def test_response_to_dict() -> None:
    response = ClientQueryResponse(
        query_id=5,
        rows=[ClientQueryRow(1, "a", is_failure=False, result="x")],
        error=None,
        connection="lab",
        server="https://bf:52311",
        backend="rest",
        elapsed_ms=1.5,
    )
    assert response.to_dict() == {
        "query_id": 5,
        "ok": True,
        "rows": [{"computer_id": 1, "computer_name": "a", "is_failure": False, "result": "x"}],
        "error": None,
        "connection": "lab",
        "server": "https://bf:52311",
        "backend": "rest",
        "elapsed_ms": 1.5,
    }


@pytest.mark.parametrize("bad", ["210", True, 2.5])
async def test_results_rejects_non_integer_query_id(recording_transport: type, bad: object) -> None:
    rec = recording_transport([_captured("results_single")])
    async with _rest(rec.transport) as b:
        with pytest.raises(TypeError, match="query_id"):
            await b.client_query_results(bad)  # type: ignore[arg-type]
    assert rec.requests == []


@pytest.mark.parametrize("key", ["results_empty_plural", "results_empty_string"])
async def test_empty_answers_are_one_empty_row(recording_transport: type, key: str) -> None:
    # (observed) An empty plural answer and "" both come back as one row with
    # result "": the API cannot tell them apart.
    rec = recording_transport([_captured(key)])
    async with _rest(rec.transport) as b:
        response = await b.client_query_results(214)
    assert response.rows == [ClientQueryRow(*COMPUTER, is_failure=False, result="")]


async def test_any_403_mentions_can_submit_queries(recording_transport: type) -> None:
    # Bad REST credentials are a 401 (rest/captured/bad_password), so a 403
    # here is a missing permission whatever the body says.
    rec = recording_transport([httpx.Response(403, text="Forbidden")])
    async with _rest(rec.transport) as b:
        response = await b.submit_client_query("computer name", [1000001])
    assert response.error is not None
    assert response.error.kind == "authentication"
    assert "Can Submit Queries" in response.error.message


async def test_deeply_nested_results_body_is_response_format(recording_transport: type) -> None:
    rec = recording_transport([httpx.Response(200, text="[" * 100_000)])
    async with _rest(rec.transport) as b:
        response = await b.client_query_results(210)
    assert response.error is not None
    assert response.error.kind == "response_format"


async def test_from_config_returns_the_subclass(tmp_path: Path) -> None:
    from typing import assert_type

    from bigfix_remote_session_relevance.config import ConnectionConfig

    conn = ConnectionConfig(name="lab", backend="rest", server="bf", token="t")
    backend = RestBackend.from_config(conn)
    assert_type(backend, RestBackend)
    assert isinstance(backend, RestBackend)


def test_body_without_use_client_context_is_unchanged() -> None:
    # The 1.2.0 body, byte for byte: omitting the element keeps older servers working.
    assert client_query_body("computer name", [1000001]) == (
        b"<?xml version='1.0' encoding='utf-8'?>\n"
        b"<BESAPI><ClientQuery><ApplicabilityRelevance>true</ApplicabilityRelevance>"
        b"<QueryText>computer name</QueryText>"
        b"<Target><ComputerID>1000001</ComputerID></Target></ClientQuery></BESAPI>"
    )


@pytest.mark.parametrize(("flag", "text"), [(True, "true"), (False, "false")])
def test_body_use_client_context_sits_between_query_text_and_target(flag: bool, text: str) -> None:
    # The BESAPI 11.0.7.61 schema makes ClientQuery an xs:sequence, so order matters.
    query = SafeET.fromstring(
        client_query_body("computer name", [1000001], use_client_context=flag)
    ).find("ClientQuery")
    assert query is not None
    assert [child.tag for child in query] == [
        "ApplicabilityRelevance",
        "QueryText",
        "UseClientContext",
        "Target",
    ]
    assert query.findtext("UseClientContext") == text


@pytest.mark.parametrize("bad", [1, 0, "true", "false"])
def test_body_rejects_non_bool_use_client_context(bad: object) -> None:
    with pytest.raises(TypeError, match="use_client_context must be a bool"):
        client_query_body("computer name", [1000001], use_client_context=bad)  # type: ignore[arg-type]


async def test_submit_sends_use_client_context(recording_transport: type) -> None:
    rec = recording_transport([_captured("submit_single")])
    async with _rest(rec.transport) as b:
        response = await b.submit_client_query("computer name", [1000001], use_client_context=True)
    assert response.ok, response.error
    query = _sent(rec.requests[0]).find("ClientQuery")
    assert query is not None
    assert [child.tag for child in query][2:] == ["UseClientContext", "Target"]
    assert query.findtext("UseClientContext") == "true"


async def test_submit_rejects_non_bool_use_client_context(recording_transport: type) -> None:
    rec = recording_transport([_captured("submit_single")])
    async with _rest(rec.transport) as b:
        with pytest.raises(TypeError, match="use_client_context must be a bool"):
            await b.submit_client_query(
                "computer name",
                [1000001],
                use_client_context="false",  # type: ignore[arg-type]
            )
    assert rec.requests == []


class _OnlyClientQuery:
    """A caller's own backend: just the two Protocol methods, no target limit."""

    async def submit_client_query(
        self,
        client_relevance: str,
        computer_ids: Sequence[int],
        *,
        use_client_context: bool | None = None,
    ) -> ClientQueryResponse:
        raise NotImplementedError

    async def client_query_results(self, query_id: int) -> ClientQueryResponse:
        raise NotImplementedError


def test_client_query_max_targets() -> None:
    assert client_query_max_targets(RestBackend("h")) is None
    assert client_query_max_targets(SaasBackend("login.bigfix.com")) == 1


def test_client_query_max_targets_is_additive() -> None:
    # Not a Protocol member, so an implementer without the attribute still counts.
    fake = _OnlyClientQuery()
    assert supports_client_query(fake)
    assert client_query_max_targets(fake) is None


@pytest.mark.parametrize("backend", [WebReportsBackend("h"), ExplorerBackend("h"), object()])
def test_client_query_max_targets_needs_client_query(backend: object) -> None:
    with pytest.raises(TypeError, match="has no ClientQuery API"):
        client_query_max_targets(backend)
