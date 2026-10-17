from __future__ import annotations

import stat
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest

from bigfix_remote_session_relevance.config import load_config
from bigfix_remote_session_relevance.setup_wizard import (
    ProbeResult,
    candidates,
    probe,
    run_setup,
)

D1 = "1" * 64


def test_candidates_prefer_https_and_default_ports() -> None:
    assert candidates("bf.example.com") == [
        ("explorer", "bf.example.com"),
        ("rest", "bf.example.com"),
        ("webreports", "bf.example.com"),
        ("webreports", "bf.example.com:8083"),
        ("webreports", "http://bf.example.com"),
        ("webreports", "http://bf.example.com:8080"),
    ]


def _answers(*values: str) -> Any:
    it: Iterator[str] = iter(values)
    prompts: list[str] = []

    def ask(prompt: str) -> str:
        prompts.append(prompt)
        try:
            return next(it)
        except StopIteration:
            raise AssertionError(f"unexpected prompt: {prompt!r}") from None

    ask.prompts = prompts  # type: ignore[attr-defined]
    return ask


def _fake_probe(results: list[ProbeResult]) -> Any:
    async def fake(host: str, username: str, password: str, trust: Any) -> list[ProbeResult]:
        assert (username, password) == ("op", "pw")
        return results

    return fake


OK_RESULTS = [
    ProbeResult("explorer", "bf.example.com", "unavailable", None, "temporarily unavailable"),
    ProbeResult("rest", "bf.example.com", "ok", D1, ""),
    ProbeResult("webreports", "http://bf.example.com:888", "ok", D1, ""),
]


def test_setup_writes_connections_with_inline_password(tmp_path: Path) -> None:
    path = tmp_path / "c.toml"
    ask = _answers(
        "bf.example.com",  # host
        "op",  # username
        "f",  # store password in file
        "y",
        "",  # save explorer, default name
        "y",
        "",  # save rest
        "y",
        "wr",  # save web reports, custom name
    )
    code = run_setup(
        path, input_fn=ask, getpass_fn=lambda p: "pw", probe_fn=_fake_probe(OK_RESULTS)
    )
    assert code == 0
    conns = {c.name: c for c in load_config(path).connections}
    assert set(conns) == {"bf-explorer", "bf-rest", "wr"}
    assert conns["bf-rest"].server == "bf.example.com"
    assert conns["bf-rest"].deployment_id == D1
    assert conns["wr"].server == "http://bf.example.com:888"
    assert conns["wr"].resolve_password() == "pw"
    if sys.platform != "win32":
        assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_setup_env_var_password_never_written(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "c.toml"
    ask = _answers("bf.example.com", "op", "e", "", "n", "y", "", "n")
    code = run_setup(
        path, input_fn=ask, getpass_fn=lambda p: "pw", probe_fn=_fake_probe(OK_RESULTS)
    )
    assert code == 0
    text = path.read_text()
    assert "pw" not in text.replace("password_env", "")
    (conn,) = load_config(path).connections
    assert conn.password_env == "BFRSR_BF_EXAMPLE_COM_PASSWORD"
    out = capsys.readouterr()
    assert "BFRSR_BF_EXAMPLE_COM_PASSWORD" in out.out + out.err
    assert "pw" not in (out.out + out.err).replace("password", "")


def test_setup_nothing_reachable(tmp_path: Path) -> None:
    results = [ProbeResult("rest", "h", "unreachable", None, "refused")]
    code = run_setup(
        tmp_path / "c.toml",
        input_fn=_answers("h", "op"),
        getpass_fn=lambda p: "pw",
        probe_fn=_fake_probe(results),
    )
    assert code == 2
    assert not (tmp_path / "c.toml").exists()


def test_setup_existing_name_asks_to_replace(tmp_path: Path) -> None:
    path = tmp_path / "c.toml"
    results = [ProbeResult("rest", "bf.example.com", "ok", D1, "")]
    run_setup(
        path,
        input_fn=_answers("bf.example.com", "op", "f", "y", ""),
        getpass_fn=lambda p: "pw",
        probe_fn=_fake_probe(results),
    )
    ask = _answers("bf.example.com", "op", "f", "y", "", "n")
    assert (
        run_setup(path, input_fn=ask, getpass_fn=lambda p: "pw", probe_fn=_fake_probe(results)) == 0
    )
    assert any("replace" in p.lower() for p in ask.prompts)
    assert len(load_config(path).connections) == 1


def test_setup_empty_host_is_usage_error(tmp_path: Path) -> None:
    assert (
        run_setup(
            tmp_path / "c.toml",
            input_fn=_answers(""),
            getpass_fn=lambda p: "pw",
            probe_fn=_fake_probe([]),
        )
        == 64
    )


# -- probe() with fake transports ----------------------------------------------


def _wr_ok() -> httpx.Response:
    return httpx.Response(
        200,
        headers={"content-type": "text/xml"},
        text=(
            '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">'
            '<soapenv:Body><GetStructuredRelevanceResultResponse xmlns="http://schemas.bigfix.com/'
            f'Relevance"><StructuredRelevanceResult><results><String>{D1}</String></results>'
            "<plural>false</plural><type>string</type><evaltime>1</evaltime>"
            "</StructuredRelevanceResult></GetStructuredRelevanceResultResponse></soapenv:Body>"
            "</soapenv:Envelope>"
        ),
    )


async def test_probe_classifies_and_picks_first_working_web_reports() -> None:
    refused = httpx.ConnectError("[Errno 61] Connection refused")
    routes: dict[tuple[str, str], Any] = {
        ("explorer", "bf"): httpx.Response(
            401,
            json={
                "error": (
                    "This API is temporarily unavailable while the connection "
                    "to the Root Server is being re-established."
                )
            },
        ),
        ("rest", "bf"): httpx.Response(
            200, json={"result": [D1], "plural": False, "type": "string"}
        ),
        ("webreports", "bf"): refused,
        ("webreports", "bf:8083"): _wr_ok(),
        ("webreports", "http://bf"): _wr_ok(),
        ("webreports", "http://bf:8080"): refused,
    }

    def factory(backend: str, server: str) -> httpx.AsyncBaseTransport:
        def handler(request: httpx.Request) -> httpx.Response:
            item = routes[(backend, server)]
            if isinstance(item, BaseException):
                raise item
            return item

        return httpx.MockTransport(handler)

    results = await probe("bf", "op", "pw", None, transport_factory=factory)
    by = {(r.backend, r.server): r for r in results}
    assert by[("explorer", "bf")].status == "unavailable"
    assert by[("rest", "bf")].status == "ok"
    assert by[("rest", "bf")].deployment_id == D1
    # Only the first working Web Reports candidate is offered (https first).
    wr = [r for r in results if r.backend == "webreports"]
    assert [(r.server, r.status) for r in wr] == [("bf:8083", "ok")]


async def test_probe_reports_auth_failure() -> None:
    def factory(backend: str, server: str) -> httpx.AsyncBaseTransport:
        return httpx.MockTransport(lambda request: httpx.Response(401, text="no"))

    results = await probe("bf", "op", "bad", None, transport_factory=factory)
    rest = next(r for r in results if r.backend == "rest")
    assert rest.status == "auth"
