from __future__ import annotations

import json

import httpx

from bigfix_remote_session_relevance.backends.explorer import ExplorerBackend

PAYLOAD = {
    "result": [[1, "a"]],
    "count": 1,
    "plural": True,
    "type": "( integer, string )",
    "evaltime_ms": 2.5,
}


async def test_request_shape_plain(recording_transport: type) -> None:
    rec = recording_transport([httpx.Response(200, json=PAYLOAD)])
    async with ExplorerBackend(
        "ex.example.com", username="op", password="pw", transport=rec.transport
    ) as backend:
        result = await backend.evaluate("(id of it, name of it) of bes computers")
    req = rec.requests[0]
    assert str(req.url) == "https://ex.example.com:9383/api/relevance"
    assert req.method == "POST"
    # Plain evaluate never sends Explorer extras.
    assert json.loads(req.content) == {"relevance": "(id of it, name of it) of bes computers"}
    assert result.answers == ((1, "a"),)
    assert result.evaluation_time_ms == 2.5
    assert result.backend == "explorer"


async def test_auth_failure(recording_transport: type) -> None:
    rec = recording_transport([httpx.Response(401, text="Unauthorized")])
    async with ExplorerBackend(
        "ex", username="op", password="bad", transport=rec.transport
    ) as backend:
        result = await backend.evaluate("1")
    assert result.error is not None
    assert result.error.kind == "authentication"


async def test_mtls_only_sends_no_authorization_header(
    recording_transport: type, tmp_path: object
) -> None:
    rec = recording_transport([httpx.Response(200, json=PAYLOAD)])
    # With an injected transport the client cert is not loaded (no TLS), but
    # no Basic/Bearer header must be sent either.
    async with ExplorerBackend(
        "ex", client_cert="/nonexistent.pem", transport=rec.transport
    ) as backend:
        result = await backend.evaluate("1")
    assert result.ok
    assert "authorization" not in rec.requests[0].headers
