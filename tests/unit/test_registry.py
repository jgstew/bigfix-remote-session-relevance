from __future__ import annotations

import pytest

from bigfix_remote_session_relevance.backends.explorer import ExplorerBackend
from bigfix_remote_session_relevance.backends.registry import BACKEND_CLASSES, backend_from_config
from bigfix_remote_session_relevance.backends.rest import RestBackend
from bigfix_remote_session_relevance.backends.saas import SaasBackend
from bigfix_remote_session_relevance.backends.webreports import WebReportsBackend
from bigfix_remote_session_relevance.config import ConnectionConfig


def test_registry() -> None:
    assert {
        "rest": RestBackend,
        "explorer": ExplorerBackend,
        "webreports": WebReportsBackend,
        "saas": SaasBackend,
    } == BACKEND_CLASSES


def test_backend_from_config(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PW", "secret")
    conn = ConnectionConfig(
        name="dev-root",
        backend="rest",
        server="h",
        username="u",
        password_env="PW",
        deployment_id="d" * 64,
        verify="tofu",
        connect_timeout=2,
        read_timeout=9,
    )
    backend = backend_from_config(conn)
    assert isinstance(backend, RestBackend)
    assert backend.connection == "dev-root"
    assert backend.deployment_id == "d" * 64
    assert backend.address.base_url == "https://h:52311"
    assert backend.timeout.connect == 2
    assert backend.timeout.read == 9


async def test_saas_is_a_not_implemented_stub() -> None:
    conn = ConnectionConfig(name="tenant", backend="saas", server="tenant.example.com")
    async with backend_from_config(conn) as backend:
        result = await backend.evaluate("1")
    assert result.error is not None
    assert result.error.kind == "not_implemented"
    assert result.connection == "tenant"
    assert result.backend == "saas"
