"""TOFU prompts are serialized: two hosts never prompt at the same time."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from bigfix_remote_session_relevance import trust
from bigfix_remote_session_relevance.server_address import ServerAddress
from bigfix_remote_session_relevance.trust import CertInfo, KnownCerts, TrustStore


async def test_callbacks_never_overlap(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_fetch(host: str, port: int, *, handshake_timeout: float = 10.0) -> CertInfo:
        return CertInfo(host_port=f"{host}:{port}", sha256=f"{port:064d}", pem="PEM")

    monkeypatch.setattr(trust, "fetch_server_cert", fake_fetch)
    active = 0
    peak = 0

    async def callback(info: CertInfo) -> bool:
        nonlocal active, peak
        active += 1
        peak = max(peak, active)
        await asyncio.sleep(0.02)
        active -= 1
        return False

    store = TrustStore(KnownCerts(tmp_path / "k.toml"), callback=callback)
    addresses = [ServerAddress("https", f"h{i}", 443) for i in range(4)]
    await asyncio.gather(*(store.on_untrusted(a) for a in addresses))
    assert peak == 1
