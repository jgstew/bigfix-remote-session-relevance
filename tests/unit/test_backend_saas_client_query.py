"""BigFix Query (fast query) on BigFix SaaS: the same opt-in ClientQueryExtras.

Response bodies under tests/fixtures/saas/captured/clientquery/ are real
(2026-10-26, one Windows agent on client 11.0.5.204, redacted to 1000001 /
COMPUTER-1): create is core v2 ``clientquery/create`` returning
``{"clientQueryId": "2"}``, results are bfproxy v1 ``clientquery/listresults``.
submit_500.json is a real failed create (2026-10-27). Synthetic bodies are only
for what was not captured (other errors, paging).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
import pytest

from bigfix_remote_session_relevance.backends import saas
from bigfix_remote_session_relevance.backends.client_query import (
    ClientQueryRow,
    supports_client_query,
)
from bigfix_remote_session_relevance.backends.saas import SaasBackend

FIXTURES = Path(__file__).parent.parent / "fixtures"
LOGIN_OK_BODY = (FIXTURES / "saas" / "shape_login_ok.json").read_text()
CAPTURED = FIXTURES / "saas" / "captured" / "clientquery"
# The redacted computer that answered every captured query.
COMPUTER = (1000001, "COMPUTER-1")


def _login_ok() -> httpx.Response:
    return httpx.Response(
        200,
        text=LOGIN_OK_BODY,
        headers=[
            ("content-type", "application/json; charset=utf-8"),
            ("set-cookie", "accessToken=ACCESS-1; Path=/; HttpOnly; Secure; SameSite=Strict"),
            ("set-cookie", "refreshToken=REFRESH-1; Path=/; HttpOnly; Secure; SameSite=Strict"),
        ],
    )


def _captured(key: str) -> httpx.Response:
    return httpx.Response(
        200,
        text=(CAPTURED / f"{key}.json").read_text(),
        headers={"content-type": "application/json; charset=utf-8"},
    )


def _ok(data: Any) -> httpx.Response:
    return httpx.Response(200, json={"status": 200, "message": "OK", "data": data})


def _created(query_id: Any = "16") -> httpx.Response:
    return _ok({"clientQueryId": query_id})


def _results(rows: list[dict[str, Any]], total: int | None = None) -> httpx.Response:
    return _ok(
        {
            "results": rows,
            "totalResults": len(rows) if total is None else total,
            "agentCount": len({r["computerId"] for r in rows}),
        }
    )


def _row(computer_id: int = 42, result: str = "Win11", failure: bool = False) -> dict[str, Any]:
    return {
        "computerId": computer_id,
        "computerName": f"COMPUTER-{computer_id}",
        "subQueryId": 1,
        "isFailure": failure,
        "result": result,
        "responseTime": 120,
    }


def _backend(rec: Any, **kw: Any) -> SaasBackend:
    kw.setdefault("sid", "bf1")
    return SaasBackend(
        "login.bigfix.com",
        username="operator@example.com",
        password="pw",
        connection="saas-bf1",
        transport=rec.transport,
        **kw,
    )


def _body(request: httpx.Request) -> dict[str, Any]:
    return json.loads(request.content)


def test_saas_supports_client_query() -> None:
    assert supports_client_query(SaasBackend("login.bigfix.com", username="u", password="p"))


# -- submit -------------------------------------------------------------------------


async def test_submit_one_id_targets_computer_id(recording_transport: type) -> None:
    rec = recording_transport([_login_ok(), _captured("submit_single")])
    async with _backend(rec) as b:
        response = await b.submit_client_query("name of operating system", [42])
    login, create = rec.requests
    assert login.url.path == "/auth/v1/user/login"
    assert (create.method, create.url.host) == ("POST", "api.bigfix.com")
    assert create.url.path == "/core/v2/clientquery/create"
    assert create.headers["x-bfnow-csrf-protection"] == "1"
    body = _body(create)
    assert body["sid"] == "bf1"
    # Ad hoc only: queryTitle / description / category / parameters would
    # make core store it as a SAVED query, so none are sent.
    assert body["data"] == {
        "queryText": "name of operating system",
        "applicabilityRelevance": "true",
        "target": {"computerId": 42},
    }
    assert response.ok, response.error
    assert (response.query_id, response.rows) == (2, [])
    assert (response.connection, response.backend) == ("saas-bf1", "saas")
    assert response.server == "https://api.bigfix.com"


async def test_submit_targets_one_computer_only(recording_transport: type) -> None:
    # The target's computerId is one integer, and (observed 2026-10-26) a
    # customRelevance target, even "computer id = N", never got an answer
    # from an agent that answered a computerId target in seconds.
    # Several ids are valid input that REST accepts, so callers written
    # against ClientQueryExtras get an error result here, not an exception.
    rec = recording_transport([_login_ok(), _created()])
    async with _backend(rec) as b:
        refused = await b.submit_client_query("computer name", [1000001, 2000002])
        assert rec.requests == []  # refused before signing in
        await b.submit_client_query("computer name", [1000001, 1000001])
    assert refused.error is not None
    assert (refused.error.kind, refused.error.code) == ("unsupported_feature", "multiple_targets")
    assert refused.error.backend == "saas"
    assert "one computer" in refused.error.message
    assert (refused.query_id, refused.rows) == (None, [])
    assert (refused.connection, refused.server) == ("saas-bf1", "https://api.bigfix.com")
    assert _body(rec.requests[1])["data"]["target"] == {"computerId": 1000001}


@pytest.mark.parametrize(("flag", "sent"), [(True, True), (False, False)])
async def test_submit_sends_use_client_context(
    recording_transport: type, flag: bool, sent: bool
) -> None:
    rec = recording_transport([_login_ok(), _created()])
    async with _backend(rec) as b:
        await b.submit_client_query("computer name", [42], use_client_context=flag)
    assert _body(rec.requests[1])["data"]["useClientContext"] is sent


@pytest.mark.parametrize(
    ("ids", "error", "match"),
    [
        ([], ValueError, "computer_ids"),
        # bfproxy drops a falsy computerId, leaving no target: every device.
        ([0], ValueError, "positive"),
        ([-1], ValueError, "positive"),
        (["42"], TypeError, "computer_ids"),
        ([True], TypeError, "computer_ids"),
    ],
)
async def test_submit_rejects_bad_ids_without_a_request(
    recording_transport: type, ids: list[Any], error: type[Exception], match: str
) -> None:
    rec = recording_transport([_login_ok(), _created()])
    async with _backend(rec) as b:
        with pytest.raises(error, match=match):
            await b.submit_client_query("computer name", ids)
    assert rec.requests == []


async def test_submit_rejects_non_bool_use_client_context(recording_transport: type) -> None:
    rec = recording_transport([_login_ok(), _created()])
    async with _backend(rec) as b:
        with pytest.raises(TypeError, match="use_client_context must be a bool"):
            await b.submit_client_query(
                "computer name",
                [42],
                use_client_context="false",  # type: ignore[arg-type]
            )
    assert rec.requests == []


async def test_submit_server_error_is_a_result_and_never_resent(
    recording_transport: type,
) -> None:
    # Core submits to the root server before it fails, and answers any
    # upstream failure with a bare 500: a resend could start a second query.
    bare = httpx.Response(500, json={"status": 500, "message": "Server Error", "data": {}})
    rec = recording_transport([_login_ok(), bare, _created()])
    async with _backend(rec) as b:
        response = await b.submit_client_query("computer name", [42])
    assert [r.url.path for r in rec.requests] == [
        "/auth/v1/user/login",
        "/core/v2/clientquery/create",
    ]
    assert response.error is not None
    assert (response.error.kind, response.error.http_status) == ("http", 500)
    assert "root server rejects" in response.error.message
    assert response.query_id is None


async def test_captured_submit_500_is_an_http_result_and_never_resent(
    recording_transport: type,
) -> None:
    # (observed 2026-10-27) The same body for an unknown computer id and for
    # client relevance with a control character: it never says which.
    failed = httpx.Response(
        500,
        text=(CAPTURED / "submit_500.json").read_text(),
        headers={"content-type": "application/json; charset=utf-8"},
    )
    rec = recording_transport([_login_ok(), failed, _created()])
    async with _backend(rec) as b:
        response = await b.submit_client_query("computer name", [42])
    posts = [r for r in rec.requests if r.url.path == "/core/v2/clientquery/create"]
    assert len(posts) == 1
    assert response.error is not None
    assert (response.error.kind, response.error.http_status) == ("http", 500)
    assert response.error.message.startswith("Server Error (")
    assert response.error.message.endswith(
        "(BigFix SaaS answers 500 for any failed client query submit, including an"
        " unknown computer id or client relevance the root server rejects)"
    )
    assert response.query_id is None
    assert response.rows == []


async def test_submit_after_expired_session_refreshes_then_resends(
    recording_transport: type,
) -> None:
    # A 401 is the gateway refusing the cookie before core sees the request,
    # so nothing was submitted and resending once is safe.
    expired = httpx.Response(401, json={"status": 401, "message": "Unauthorized", "data": {}})
    rec = recording_transport([_login_ok(), expired, _login_ok(), _created("17")])
    async with _backend(rec) as b:
        response = await b.submit_client_query("computer name", [42])
    assert [r.url.path for r in rec.requests] == [
        "/auth/v1/user/login",
        "/core/v2/clientquery/create",
        "/auth/v1/token/refresh",
        "/core/v2/clientquery/create",
    ]
    assert response.query_id == 17


@pytest.mark.parametrize(
    "data",
    [
        {},
        {"clientQueryId": ""},
        {"clientQueryId": "abc"},
        # str.isdigit() is True for these, but int() rejects them.
        {"clientQueryId": "\u00b2"},
        {"clientQueryId": "\u2460"},
        {"clientQueryId": "0"},
        {"clientQueryId": True},
        None,
    ],
)
async def test_submit_without_query_id_is_response_format(
    recording_transport: type, data: Any
) -> None:
    rec = recording_transport([_login_ok(), _ok(data)])
    async with _backend(rec) as b:
        response = await b.submit_client_query("computer name", [42])
    assert response.error is not None
    assert (response.error.kind, response.error.backend) == ("response_format", "saas")
    assert response.query_id is None


async def test_submit_with_bad_password_is_authentication(recording_transport: type) -> None:
    rejected = httpx.Response(
        401,
        json={"status": 401, "data": {"errorMessage": "Incorrect username or password."}},
    )
    rec = recording_transport([rejected])
    async with _backend(rec) as b:
        response = await b.submit_client_query("computer name", [42])
    assert response.error is not None
    assert response.error.kind == "authentication"
    assert [r.url.path for r in rec.requests] == ["/auth/v1/user/login"]


# -- results ------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("key", "rows"),
    [
        ("results_pending", []),
        ("results_single", [ClientQueryRow(*COMPUTER, is_failure=False, result="COMPUTER-1")]),
        # values of headers "X-Fixlet-Source-Release-Date" of relevant fixlets
        # of sites, without client context: the agent cannot see fixlets.
        (
            "results_no_client_context",
            [
                ClientQueryRow(
                    *COMPUTER,
                    is_failure=True,
                    result=(
                        "The expression could not be evaluated: class InspectorFixletContextError"
                    ),
                )
            ],
        ),
    ],
)
async def test_captured_results_map_rows(
    recording_transport: type, key: str, rows: list[ClientQueryRow]
) -> None:
    rec = recording_transport([_login_ok(), _captured(key)])
    async with _backend(rec) as b:
        response = await b.client_query_results(2)
    assert response.ok, response.error
    assert response.rows == rows
    assert len(rec.requests) == 2


async def test_captured_client_context_answers_fixlet_inspectors(
    recording_transport: type,
) -> None:
    # The same expression with use_client_context=True: one row per value,
    # "" for a fixlet without the header, and all 135 in one page.
    rec = recording_transport([_login_ok(), _captured("results_client_context")])
    async with _backend(rec) as b:
        response = await b.client_query_results(4)
    assert response.ok, response.error
    assert len(response.rows) == 135
    assert {(r.computer_id, r.computer_name, r.is_failure) for r in response.rows} == {
        (*COMPUTER, False)
    }
    assert "" in {r.result for r in response.rows}
    assert "19 Oct 2004" in {r.result for r in response.rows}
    assert len(rec.requests) == 2


async def test_results_post_listresults_and_map_rows(recording_transport: type) -> None:
    rows = [_row(42, "Win11"), _row(43, 'The operator "foo" is not defined.', failure=True)]
    rec = recording_transport([_login_ok(), _results(rows)])
    async with _backend(rec) as b:
        response = await b.client_query_results(16)
    request = rec.requests[1]
    assert (request.method, request.url.path) == ("POST", "/bfproxy/v1/clientquery/listresults")
    body = _body(request)
    assert body["sid"] == "bf1"
    assert body["data"] == {"queryId": "16", "start": 0, "count": 1000, "stats": True}
    assert response.ok, response.error
    assert response.query_id == 16
    assert response.rows == [
        ClientQueryRow(42, "COMPUTER-42", is_failure=False, result="Win11"),
        ClientQueryRow(
            43, "COMPUTER-43", is_failure=True, result='The operator "foo" is not defined.'
        ),
    ]


async def test_results_pending_is_no_rows(recording_transport: type) -> None:
    rec = recording_transport([_login_ok(), _results([])])
    async with _backend(rec) as b:
        response = await b.client_query_results(16)
    assert response.ok, response.error
    assert response.rows == []


async def test_results_page_until_total(
    recording_transport: type, monkeypatch: pytest.MonkeyPatch
) -> None:
    # REST returns every row so far in one call; SaaS pages, so this reads
    # every page to return the same thing.
    monkeypatch.setattr(saas, "CLIENT_QUERY_PAGE", 2)
    rec = recording_transport(
        [
            _login_ok(),
            _results([_row(1), _row(2)], total=3),
            _results([_row(3)], total=3),
        ]
    )
    async with _backend(rec) as b:
        response = await b.client_query_results(16)
    starts = [_body(r)["data"]["start"] for r in rec.requests[1:]]
    assert starts == [0, 2]
    assert [_body(r)["data"]["count"] for r in rec.requests[1:]] == [2, 2]
    assert [r.computer_id for r in response.rows] == [1, 2, 3]


async def test_results_stop_on_a_short_page(
    recording_transport: type, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Rows keep arriving, so a total that grows past what a page returned
    # must not loop forever: an empty page ends it.
    monkeypatch.setattr(saas, "CLIENT_QUERY_PAGE", 2)
    rec = recording_transport(
        [_login_ok(), _results([_row(1), _row(2)], total=5), _results([], total=5)]
    )
    async with _backend(rec) as b:
        response = await b.client_query_results(16)
    assert len(rec.requests) == 3
    assert [r.computer_id for r in response.rows] == [1, 2]


@pytest.mark.parametrize(
    "data",
    [
        None,
        {"result": []},
        {"results": {}},
        {"results": [{"computerId": 1, "computerName": "a", "isFailure": False}]},
        {"results": [{"computerId": "1", "computerName": "a", "isFailure": False, "result": ""}]},
    ],
)
async def test_malformed_results_are_response_format(recording_transport: type, data: Any) -> None:
    rec = recording_transport([_login_ok(), _ok(data)])
    async with _backend(rec) as b:
        response = await b.client_query_results(16)
    assert response.error is not None
    assert response.error.kind == "response_format"
    assert (response.query_id, response.rows) == (16, [])


async def test_results_error_is_a_result(recording_transport: type) -> None:
    rec = recording_transport(
        [_login_ok(), httpx.Response(400, json={"status": 400, "message": "Bad", "data": {}})]
    )
    async with _backend(rec) as b:
        response = await b.client_query_results(16)
    assert response.error is not None
    assert (response.error.kind, response.error.http_status) == ("http", 400)
    assert response.query_id == 16


@pytest.mark.parametrize("bad", ["16", True, 2.5])
async def test_results_rejects_non_integer_query_id(recording_transport: type, bad: Any) -> None:
    rec = recording_transport([_login_ok()])
    async with _backend(rec) as b:
        with pytest.raises(TypeError, match="query_id"):
            await b.client_query_results(bad)
    assert rec.requests == []


async def test_plain_evaluate_is_unchanged(recording_transport: type) -> None:
    rec = recording_transport(
        [_login_ok(), _ok({"answer": [1], "plural": False, "type": "integer"})]
    )
    async with _backend(rec) as b:
        result = await b.evaluate("1")
    request = rec.requests[1]
    assert request.url.path == "/bfproxy/v2/relevance"
    body = _body(request)
    assert set(body) == {"requestId", "timestamp", "data", "sid"}
    assert (body["data"], body["sid"]) == ({"query": "1"}, "bf1")
    assert result.ok, result.error
    assert (result.answers, result.type, result.plural) == ((1,), "integer", False)


async def test_plain_evaluate_renews_once_on_401(recording_transport: type) -> None:
    expired = httpx.Response(401, json={"status": 401, "message": "Unauthorized", "data": {}})
    rec = recording_transport(
        [_login_ok(), expired, _login_ok(), _ok({"answer": [1], "plural": False})]
    )
    async with _backend(rec) as b:
        result = await b.evaluate("1")
    assert [r.url.path for r in rec.requests] == [
        "/auth/v1/user/login",
        "/bfproxy/v2/relevance",
        "/auth/v1/token/refresh",
        "/bfproxy/v2/relevance",
    ]
    assert result.ok, result.error


def _page(rows: list[dict[str, Any]], **stats: Any) -> httpx.Response:
    """A listresults page with exactly these stats keys (none when omitted)."""
    return _ok({"results": rows, **stats})


async def test_results_keep_paging_full_pages_without_a_total(
    recording_transport: type, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Without totalResults, a full page may not be the last one.
    monkeypatch.setattr(saas, "CLIENT_QUERY_PAGE", 2)
    rec = recording_transport([_login_ok(), _page([_row(1), _row(2)]), _page([_row(3)])])
    async with _backend(rec) as b:
        response = await b.client_query_results(16)
    assert [_body(r)["data"]["start"] for r in rec.requests[1:]] == [0, 2]
    assert [r.computer_id for r in response.rows] == [1, 2, 3]


async def test_results_stop_on_a_short_page_even_if_the_total_grew(
    recording_transport: type, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Agents answered between the two calls: the total grew past what the
    # short page returned, but a short page is the end of what is there.
    monkeypatch.setattr(saas, "CLIENT_QUERY_PAGE", 2)
    rec = recording_transport(
        [
            _login_ok(),
            _page([_row(1), _row(2)], totalResults=3),
            _page([_row(3)], totalResults=5),
        ]
    )
    async with _backend(rec) as b:
        response = await b.client_query_results(16)
    assert len(rec.requests) == 3
    assert [r.computer_id for r in response.rows] == [1, 2, 3]


async def test_results_renew_on_a_401_between_pages(
    recording_transport: type, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(saas, "CLIENT_QUERY_PAGE", 2)
    expired = httpx.Response(401, json={"status": 401, "message": "Unauthorized", "data": {}})
    rec = recording_transport(
        [
            _login_ok(),
            _page([_row(1), _row(2)], totalResults=3),
            expired,
            _login_ok(),
            _page([_row(3)], totalResults=3),
        ]
    )
    async with _backend(rec) as b:
        response = await b.client_query_results(16)
    assert [r.url.path for r in rec.requests] == [
        "/auth/v1/user/login",
        "/bfproxy/v1/clientquery/listresults",
        "/bfproxy/v1/clientquery/listresults",
        "/auth/v1/token/refresh",
        "/bfproxy/v1/clientquery/listresults",
    ]
    assert [_body(r)["data"]["start"] for r in rec.requests if "listresults" in r.url.path] == [
        0,
        2,
        2,
    ]
    assert response.ok, response.error
    assert [r.computer_id for r in response.rows] == [1, 2, 3]


async def test_results_error_on_a_later_page_drops_every_row(
    recording_transport: type, monkeypatch: pytest.MonkeyPatch
) -> None:
    # All or nothing, as on REST: rows with an error would read as complete.
    monkeypatch.setattr(saas, "CLIENT_QUERY_PAGE", 2)
    rec = recording_transport(
        [
            _login_ok(),
            _page([_row(1), _row(2)], totalResults=3),
            httpx.Response(503, json={"status": 503, "message": "Unavailable", "data": {}}),
        ]
    )
    async with _backend(rec) as b:
        response = await b.client_query_results(16)
    assert response.error is not None
    assert response.error.http_status == 503
    assert (response.query_id, response.rows) == (16, [])
