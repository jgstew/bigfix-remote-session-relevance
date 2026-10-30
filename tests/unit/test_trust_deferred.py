"""Deferred trust: refuse a first-use certificate, remember it, pin it later.

Offline: `fetch_server_cert` is faked, so these never open a socket. The
real-handshake versions live in test_trust.py.
"""

from __future__ import annotations

import warnings
from pathlib import Path

import pytest

from bigfix_remote_session_relevance import trust
from bigfix_remote_session_relevance.server_address import ServerAddress
from bigfix_remote_session_relevance.trust import CertInfo, KnownCerts, TrustStore

ADDRESS = ServerAddress("https", "bes.example", 52311)
INFO = CertInfo(host_port="bes.example:52311", sha256="ab" * 32, pem="PEM")


@pytest.fixture
def fetches(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Fake bare handshakes; returns the host:ports fetched."""
    seen: list[str] = []

    async def fake_fetch(host: str, port: int, *, handshake_timeout: float = 10.0) -> CertInfo:
        seen.append(f"{host}:{port}")
        return INFO

    monkeypatch.setattr(trust, "fetch_server_cert", fake_fetch)
    return seen


@pytest.fixture(autouse=True)
def _fresh_warning(monkeypatch: pytest.MonkeyPatch) -> None:
    # The implicit-auto warning is once per process; each test starts fresh.
    monkeypatch.setattr(trust, "_implicit_auto_warned", False)


def _known(tmp_path: Path) -> KnownCerts:
    return KnownCerts(tmp_path / "known.toml")


# -- pending / accept (issue tests 1-3) -------------------------------------------


async def test_declined_callback_records_pending(tmp_path: Path, fetches: list[str]) -> None:
    store = TrustStore(_known(tmp_path), callback=lambda info: False)
    assert await store.on_untrusted(ADDRESS) is False
    assert store.pending == {"bes.example:52311": INFO}
    assert store.known.get("bes.example:52311") is None


async def test_tofu_disabled_fetches_and_records_pending(
    tmp_path: Path, fetches: list[str]
) -> None:
    store = TrustStore(_known(tmp_path), trust_on_first_use=False)
    assert await store.on_untrusted(ADDRESS) is False
    assert fetches == ["bes.example:52311"]
    assert store.pending == {"bes.example:52311": INFO}
    assert store.known.get("bes.example:52311") is None


async def test_tofu_disabled_without_recording_fetches_nothing(
    tmp_path: Path, fetches: list[str]
) -> None:
    store = TrustStore(_known(tmp_path), trust_on_first_use=False, record_refused=False)
    assert await store.on_untrusted(ADDRESS) is False
    assert fetches == []
    assert store.pending == {}


async def test_accepted_callback_leaves_pending_empty(tmp_path: Path, fetches: list[str]) -> None:
    store = TrustStore(_known(tmp_path), callback=lambda info: True)
    assert await store.on_untrusted(ADDRESS) is True
    assert store.pending == {}
    pin = store.known.get("bes.example:52311")
    assert pin is not None
    assert pin.trusted_by == "prompt"


async def test_auto_leaves_pending_empty(tmp_path: Path, fetches: list[str]) -> None:
    store = TrustStore(_known(tmp_path), trust_on_first_use="auto")
    assert await store.on_untrusted(ADDRESS) is True
    assert store.pending == {}
    pin = store.known.get("bes.example:52311")
    assert pin is not None
    assert pin.trusted_by == "auto"


async def test_fetch_failure_records_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def failing_fetch(host: str, port: int, *, handshake_timeout: float = 10.0) -> CertInfo:
        raise OSError("refused")

    monkeypatch.setattr(trust, "fetch_server_cert", failing_fetch)
    store = TrustStore(_known(tmp_path), trust_on_first_use=False)
    assert await store.on_untrusted(ADDRESS) is False
    assert store.pending == {}


async def test_accept_pins_pending_cert(tmp_path: Path, fetches: list[str]) -> None:
    store = TrustStore(_known(tmp_path), trust_on_first_use=False)
    await store.on_untrusted(ADDRESS)
    pin = store.accept("bes.example:52311")
    assert (pin.host_port, pin.sha256, pin.pem, pin.trusted_by) == (
        "bes.example:52311",
        INFO.sha256,
        "PEM",
        "prompt",
    )
    assert store.pending == {}
    assert store.is_pinned(ADDRESS)
    # Now pinned, a later first-use check neither fetches nor records again.
    fetches.clear()
    assert await store.on_untrusted(ADDRESS) is True
    assert fetches == []


def test_accept_takes_trusted_by(tmp_path: Path) -> None:
    store = TrustStore(_known(tmp_path), trust_on_first_use=False)
    store.pending[INFO.host_port] = INFO
    assert store.accept(INFO.host_port, trusted_by="ui").trusted_by == "ui"


def test_accept_unknown_host_port_raises_key_error(tmp_path: Path) -> None:
    store = TrustStore(_known(tmp_path), trust_on_first_use=False)
    with pytest.raises(KeyError):
        store.accept("bes.example:52311")
    assert store.known.all() == []


# -- explicit auto-accept (issue test 6, decision (b)) ----------------------------


def test_implicit_auto_accept_warns_once(tmp_path: Path) -> None:
    with pytest.warns(DeprecationWarning, match=r'trust_on_first_use="auto"') as record:
        TrustStore(_known(tmp_path))
    message = str(record[0].message)
    assert "callback" in message
    assert "trust_on_first_use=False" in message
    assert "2.0" in message
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        TrustStore(_known(tmp_path))  # once per process


def test_implicit_auto_warning_points_at_the_caller(tmp_path: Path) -> None:
    with pytest.warns(DeprecationWarning) as record:
        TrustStore(_known(tmp_path))
    assert record[0].filename == __file__


@pytest.mark.parametrize(
    "kwargs",
    [
        {"trust_on_first_use": "auto"},
        {"trust_on_first_use": False},
        {"callback": lambda info: True},
        {"callback": lambda info: True, "trust_on_first_use": True},
    ],
    ids=["auto", "false", "callback", "callback-true"],
)
def test_explicit_choices_do_not_warn(tmp_path: Path, kwargs: dict[str, object]) -> None:
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        TrustStore(_known(tmp_path), **kwargs)  # type: ignore[arg-type]


def test_explicit_true_without_callback_still_auto_accepts_but_warns(tmp_path: Path) -> None:
    # True without a callback means auto-accept in 1.x and refuse-and-record
    # in 2.0, so it warns too: only "auto" keeps today's behaviour for good.
    with pytest.warns(DeprecationWarning):
        TrustStore(_known(tmp_path), trust_on_first_use=True)


async def test_implicit_default_still_auto_pins(tmp_path: Path, fetches: list[str]) -> None:
    with pytest.warns(DeprecationWarning):
        store = TrustStore(_known(tmp_path))
    assert await store.on_untrusted(ADDRESS) is True
    pin = store.known.get("bes.example:52311")
    assert pin is not None
    assert pin.trusted_by == "auto"


@pytest.mark.parametrize("value", ["yes", "AUTO", 1, None])
def test_unknown_trust_on_first_use_raises(tmp_path: Path, value: object) -> None:
    with pytest.raises(ValueError, match="trust_on_first_use"):
        TrustStore(_known(tmp_path), trust_on_first_use=value)  # type: ignore[arg-type]


def test_auto_with_callback_raises(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="callback"):
        TrustStore(_known(tmp_path), callback=lambda info: True, trust_on_first_use="auto")


# -- exports (issue test 5) -------------------------------------------------------


def test_trust_policy_and_server_address_are_exported() -> None:
    import bigfix_remote_session_relevance as pkg
    from bigfix_remote_session_relevance import ServerAddress as Exported
    from bigfix_remote_session_relevance import TrustPolicy
    from bigfix_remote_session_relevance.backends.base import TrustPolicy as Internal

    assert TrustPolicy is Internal
    assert Exported is ServerAddress
    assert {"TrustPolicy", "ServerAddress"} <= set(pkg.__all__)


def test_trust_store_satisfies_trust_policy(tmp_path: Path) -> None:
    from bigfix_remote_session_relevance import TrustPolicy

    policy: TrustPolicy = TrustStore(_known(tmp_path), trust_on_first_use=False)
    assert not policy.is_pinned(ADDRESS)
