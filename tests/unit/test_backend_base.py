from __future__ import annotations

import logging
import ssl

import httpx
import pytest

from bigfix_remote_session_relevance.backends.base import (
    error_from_exception,
    error_from_status,
    normalize_relevance_error,
)
from bigfix_remote_session_relevance.backends.rest import RestBackend

OK_JSON = {"result": [1], "count": 1, "plural": False, "type": "integer", "evaltime_ms": 0.5}


def _verify_failure() -> httpx.ConnectError:
    try:
        try:
            raise ssl.SSLCertVerificationError(1, "[SSL: CERTIFICATE_VERIFY_FAILED] self-signed")
        except ssl.SSLCertVerificationError as inner:
            raise httpx.ConnectError("handshake failed") from inner
    except httpx.ConnectError as exc:
        return exc


@pytest.mark.parametrize(
    ("exc", "kind", "code"),
    [
        (httpx.ConnectTimeout("t"), "timeout", None),
        (httpx.ReadTimeout("t"), "timeout", None),
        (httpx.ConnectError("[Errno 61] Connection refused"), "connection", None),
        (httpx.ConnectError("nodename nor servname provided"), "connection", None),
        (httpx.ReadError("reset"), "connection", None),
        (httpx.RemoteProtocolError("bad"), "connection", None),
        (_verify_failure(), "tls", "cert_verify_failed"),
        (httpx.ConnectError("[SSL: WRONG_VERSION_NUMBER] wrong version"), "tls", "tls_handshake"),
    ],
)
def test_error_from_exception(exc: Exception, kind: str, code: str | None) -> None:
    err = error_from_exception(exc, "rest")
    assert (err.kind, err.code, err.backend) == (kind, code, "rest")
    assert err.message


@pytest.mark.parametrize(
    ("status", "kind"),
    [(401, "authentication"), (403, "authentication"), (500, "http"), (404, "http"), (502, "http")],
)
def test_error_from_status(status: int, kind: str) -> None:
    response = httpx.Response(status, text="nope " * 500)
    err = error_from_status(response, "explorer")
    assert err.kind == kind
    assert err.http_status == status
    assert err.detail is not None
    assert len(err.detail) <= 500


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ('Error: The operator "foo" is not defined.', 'The operator "foo" is not defined.'),
        ('ERROR: The operator "foo" is not defined.', 'The operator "foo" is not defined.'),
        ('  The operator  "foo"\n is not defined.  ', 'The operator "foo" is not defined.'),
        ("Relevance error: Error: x", "x"),
        ("", "unknown error"),
    ],
)
def test_normalize_relevance_error(raw: str, expected: str) -> None:
    assert normalize_relevance_error(raw) == expected


async def test_evaluate_stamps_metadata(recording_transport: type) -> None:
    rec = recording_transport([httpx.Response(200, json=OK_JSON)])
    backend = RestBackend(
        "bigfix.example.com",
        username="op",
        password="pw",
        transport=rec.transport,
        connection="dev-root",
        deployment_id="d" * 64,
    )
    async with backend:
        result = await backend.evaluate("1")
    assert result.ok
    assert result.connection == "dev-root"
    assert result.deployment_id == "d" * 64
    assert result.backend == "rest"
    assert result.server == "https://bigfix.example.com:52311"
    assert result.elapsed_ms is not None
    assert result.elapsed_ms >= 0


async def test_transport_exception_becomes_error_result(recording_transport: type) -> None:
    rec = recording_transport([httpx.ConnectError("[Errno 61] Connection refused")])
    async with RestBackend("h", username="u", password="p", transport=rec.transport) as backend:
        result = await backend.evaluate("1")
    assert not result.ok
    assert result.error is not None
    assert result.error.kind == "connection"
    assert result.server == "https://h:52311"


async def test_basic_auth_without_password_makes_no_request(recording_transport: type) -> None:
    rec = recording_transport([httpx.Response(200, json=OK_JSON)])
    async with RestBackend("h", username="u", password=None, transport=rec.transport) as backend:
        result = await backend.evaluate("1")
    assert result.error is not None
    assert result.error.kind == "authentication"
    assert "password" in result.error.message
    assert rec.requests == []


async def test_basic_auth_header(recording_transport: type) -> None:
    rec = recording_transport([httpx.Response(200, json=OK_JSON)])
    async with RestBackend("h", username="u", password="p", transport=rec.transport) as backend:
        await backend.evaluate("1")
    assert rec.requests[0].headers["authorization"].startswith("Basic ")


async def test_bearer_token_header(recording_transport: type) -> None:
    rec = recording_transport([httpx.Response(200, json=OK_JSON)])
    async with RestBackend("h", token="t0k", transport=rec.transport) as backend:
        await backend.evaluate("1")
    assert rec.requests[0].headers["authorization"] == "Bearer t0k"


async def test_cleartext_warning_logged_once(
    recording_transport: type, caplog: pytest.LogCaptureFixture
) -> None:
    rec = recording_transport([httpx.Response(200, json=OK_JSON)])
    with caplog.at_level(logging.WARNING):
        async with RestBackend(
            "http://h:8080", username="u", password="p", transport=rec.transport
        ) as backend:
            await backend.evaluate("1")
            await backend.evaluate("1")
    assert caplog.text.count("cleartext") == 1
    assert "p" not in caplog.text.split("cleartext")[0][-3:]


def test_secrets_not_in_repr() -> None:
    backend = RestBackend("h", username="u", password="s3cret-pw")
    assert "s3cret-pw" not in repr(backend)
    backend2 = RestBackend("h", token="s3cret-tok")
    assert "s3cret-tok" not in repr(backend2)


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        (
            "The expression could not be evaluated: 27TooLargeForStandardNotation",
            "The expression could not be evaluated: class TooLargeForStandardNotation",
        ),
        (  # already on-prem form
            "The expression could not be evaluated: class TooLargeForStandardNotation",
            "The expression could not be evaluated: class TooLargeForStandardNotation",
        ),
        (  # length doesn't match: not a mangled name, left alone
            "The expression could not be evaluated: 12abc",
            "The expression could not be evaluated: 12abc",
        ),
        ("Error: 27TooLargeForStandardNotation", "27TooLargeForStandardNotation"),
    ],
)
def test_normalize_relevance_error_unmangles_saas_exception_names(text: str, expected: str) -> None:
    assert normalize_relevance_error(text) == expected
