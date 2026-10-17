from __future__ import annotations

import hashlib

import httpx

from bigfix_remote_session_relevance.backends.rest import RestBackend
from bigfix_remote_session_relevance.backends.webreports import WebReportsBackend
from bigfix_remote_session_relevance.deployment import (
    DEPLOYMENT_ID_RELEVANCE,
    GATHER_URL_RELEVANCE,
    deployment_id_from_hashes,
    discover_deployment_id,
    group_key,
)

GATHER = "http://bigfix.example.com:52311/cgi-bin/bfgather.exe/actionsite"
HASH = hashlib.sha256(GATHER.encode()).hexdigest()


def test_relevance_is_the_designed_query() -> None:
    assert DEPLOYMENT_ID_RELEVANCE == "sha256 of gather url of bes license"
    assert GATHER_URL_RELEVANCE == "gather url of bes license"


def test_deployment_id_from_hashes() -> None:
    assert deployment_id_from_hashes([]) is None
    assert deployment_id_from_hashes([HASH.upper()]) == HASH
    assert deployment_id_from_hashes([HASH, HASH]) == HASH
    multi = deployment_id_from_hashes(["b" * 64, "a" * 64])
    assert multi == "multi:" + hashlib.sha256(("a" * 64 + "," + "b" * 64).encode()).hexdigest()
    assert deployment_id_from_hashes(["a" * 64, "b" * 64]) == multi  # order-independent


def test_group_key() -> None:
    assert group_key("dev-root", HASH) == HASH
    assert group_key("dev-root", None) == "connection:dev-root"


async def test_discovery_uses_server_side_hash(recording_transport: type) -> None:
    rec = recording_transport(
        [httpx.Response(200, json={"result": [HASH], "plural": False, "type": "string"})]
    )
    async with RestBackend("h", username="u", password="p", transport=rec.transport) as b:
        assert await discover_deployment_id(b) == HASH
    assert len(rec.requests) == 1


async def test_discovery_falls_back_to_local_hash(recording_transport: type) -> None:
    # An older server without `sha256 of <string>` reports a relevance error.
    rec = recording_transport(
        [
            httpx.Response(
                200, json={"result": [], "error": 'The operator "sha256" is not defined.'}
            ),
            httpx.Response(200, json={"result": [GATHER], "plural": False, "type": "string"}),
        ]
    )
    async with RestBackend("h", username="u", password="p", transport=rec.transport) as b:
        assert await discover_deployment_id(b) == HASH
    assert len(rec.requests) == 2


async def test_discovery_unreachable_returns_none(recording_transport: type) -> None:
    rec = recording_transport([httpx.ConnectError("[Errno 61] Connection refused")])
    async with RestBackend("h", username="u", password="p", transport=rec.transport) as b:
        assert await discover_deployment_id(b) is None


async def test_multi_datasource_web_reports(recording_transport: type) -> None:
    body = (
        '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"><soapenv:Body>'
        '<GetStructuredRelevanceResultResponse xmlns="http://schemas.bigfix.com/Relevance">'
        f"<StructuredRelevanceResult><results><String>{'a' * 64}</String><String>{'b' * 64}"
        "</String></results><plural>true</plural><type>string</type><evaltime>1</evaltime>"
        "</StructuredRelevanceResult></GetStructuredRelevanceResultResponse></soapenv:Body>"
        "</soapenv:Envelope>"
    )
    rec = recording_transport(
        [httpx.Response(200, text=body, headers={"content-type": "text/xml"})]
    )
    async with WebReportsBackend("wr", username="u", password="p", transport=rec.transport) as b:
        found = await discover_deployment_id(b)
    assert found is not None
    assert found.startswith("multi:")
