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


def test_saas_from_config() -> None:
    conn = ConnectionConfig(
        name="tenant",
        backend="saas",
        server="login.bigfix.com",
        username="operator@example.com",
        password="pw",
        sid="bf160001489",
    )
    backend = backend_from_config(conn)
    assert isinstance(backend, SaasBackend)
    assert backend.sid == "bf160001489"
    assert backend.address.base_url == "https://api.bigfix.com"
    assert backend.connection == "tenant"
