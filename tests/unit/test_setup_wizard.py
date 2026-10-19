from __future__ import annotations

import json
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
    is_saas_host,
    probe,
    probe_saas,
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


# -- BigFix SaaS -----------------------------------------------------------------------

SAAS_FIXTURES = Path(__file__).parent.parent / "fixtures" / "saas"
D5 = "5" * 64  # the captured deployment_id.json answer
EMAIL = "operator@example.com"


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        ("login.bigfix.com", True),
        ("eulogin.bigfix.com", True),
        ("https://login.bigfix.com", True),
        ("API.bigfix.com", True),
        ("bf.example.com", False),
        # On-prem hosts that merely start like a SaaS host stay on-prem.
        ("api.example.com", False),
        ("login.example.com", False),
        ("http://login.bigfix.com", False),
    ],
)
def test_is_saas_host(host: str, expected: bool) -> None:
    assert is_saas_host(host) is expected


def _login_body(*server_ids: str) -> str:
    body = json.loads((SAAS_FIXTURES / "shape_login_ok.json").read_text())
    body["data"]["pids"]["bf"] = {i: {"uid": "00000000", "uname": EMAIL} for i in server_ids}
    return json.dumps(body)


def _relevance_answer(value: str) -> httpx.Response:
    body = json.loads((SAAS_FIXTURES / "captured" / "deployment_id.json").read_text())
    body["data"]["answer"] = [value]
    return httpx.Response(200, json=body)


class SaasServer:
    """Routes SaaS requests by path and ``sid``; records every request."""

    def __init__(self, logins: list[httpx.Response], answers: dict[str | None, Any]) -> None:
        self.logins = list(logins)
        self.answers = answers
        self.requests: list[httpx.Request] = []
        self.transport = httpx.MockTransport(self._handle)

    def bodies(self, path: str) -> list[dict[str, Any]]:
        return [json.loads(r.content) for r in self.requests if r.url.path == path]

    def _handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        body = json.loads(request.content)
        if request.url.path == "/auth/v1/user/login":
            return self.logins.pop(0)
        if request.url.path == "/bfproxy/v2/relevance":
            item = self.answers[body.get("sid")]
            return item if isinstance(item, httpx.Response) else _relevance_answer(item)
        raise AssertionError(f"unexpected request {request.url.path}")


def _saas_login_ok(*server_ids: str) -> httpx.Response:
    return httpx.Response(200, text=_login_body(*server_ids))


def _saas_login_fail(signal: str) -> httpx.Response:
    return httpx.Response(
        401, json={"status": 401, "message": "Unauthorized", "data": {"errorMessage": signal}}
    )


def _no_prompt(prompt: str) -> str:
    raise AssertionError(f"unexpected prompt {prompt!r}")


async def test_probe_saas_single_server() -> None:
    server = SaasServer([_saas_login_ok("160001489")], {None: D5})
    results = await probe_saas(
        "login.bigfix.com", EMAIL, "pw", _no_prompt, transport=server.transport
    )
    # One server: no sid needed, the gateway's default is that server.
    assert results == [ProbeResult("saas", "login.bigfix.com", "ok", D5, "", sid=None)]
    assert len(server.bodies("/auth/v1/user/login")) == 1
    assert all(r.url.host == "api.bigfix.com" for r in server.requests)


async def test_probe_saas_one_result_per_server_with_one_login() -> None:
    server = SaasServer(
        [_saas_login_ok("160001489", "160002000")],
        {
            None: httpx.Response(
                400, json={"status": 400, "data": {"errorMessage": "sid required"}}
            ),
            "bf160001489": D5,
            "bf160002000": D1,
        },
    )
    results = await probe_saas(
        "eulogin.bigfix.com", EMAIL, "pw", _no_prompt, transport=server.transport
    )
    assert [(r.sid, r.status, r.deployment_id) for r in results] == [
        ("bf160001489", "ok", D5),
        ("bf160002000", "ok", D1),
    ]
    assert {r.server for r in results} == {"eulogin.bigfix.com"}
    # The session is shared: one login, however many servers.
    assert len(server.bodies("/auth/v1/user/login")) == 1


async def test_probe_saas_answers_totp_challenge_once() -> None:
    server = SaasServer([_saas_login_fail("totp_required"), _saas_login_ok("1")], {None: D5})
    prompts: list[str] = []

    def totp(prompt: str) -> str:
        prompts.append(prompt)
        return "123456"

    (result,) = await probe_saas("login.bigfix.com", EMAIL, "pw", totp, transport=server.transport)
    assert result.status == "ok"
    assert len(prompts) == 1
    first, second = server.bodies("/auth/v1/user/login")
    assert "totp" not in first["data"]
    assert second["data"]["totp"] == "123456"


async def test_probe_saas_never_retries_a_rejected_login() -> None:
    # 100 failed logins lock a SaaS account for good.
    server = SaasServer([_saas_login_fail("Incorrect username or password.")], {})
    (result,) = await probe_saas(
        "login.bigfix.com", EMAIL, "bad", _no_prompt, transport=server.transport
    )
    assert result.status == "auth"
    assert result.sid is None
    assert len(server.requests) == 1


def _fake_saas_probe(results: list[ProbeResult]) -> Any:
    async def fake(host: str, email: str, password: str, totp_prompt: Any) -> list[ProbeResult]:
        assert (host, email, password) == ("login.bigfix.com", EMAIL, "pw")
        return results

    return fake


def _on_prem_probe_not_called(*args: Any) -> Any:
    raise AssertionError("the on-prem probe must not run for a SaaS host")


def test_setup_saas_single_server(tmp_path: Path) -> None:
    path = tmp_path / "c.toml"
    ask = _answers("login.bigfix.com", EMAIL, "f", "y", "")
    code = run_setup(
        path,
        input_fn=ask,
        getpass_fn=lambda p: "pw",
        probe_fn=_on_prem_probe_not_called,
        saas_probe_fn=_fake_saas_probe([ProbeResult("saas", "login.bigfix.com", "ok", D5, "")]),
    )
    assert code == 0
    assert any("email" in p.lower() for p in ask.prompts)
    (conn,) = load_config(path).connections
    assert (conn.name, conn.backend, conn.server) == ("bigfix-saas", "saas", "login.bigfix.com")
    assert conn.username == EMAIL
    assert conn.resolve_password() == "pw"
    assert conn.deployment_id == D5
    assert conn.sid is None
    # A public CA-signed service: never trust-on-first-use a password-bearing host.
    assert conn.verify is True


def test_setup_saas_saves_one_connection_per_server(tmp_path: Path) -> None:
    path = tmp_path / "c.toml"
    results = [
        ProbeResult("saas", "eulogin.bigfix.com", "ok", D5, "", sid="bf160001489"),
        ProbeResult("saas", "eulogin.bigfix.com", "ok", D1, "", sid="bf160002000"),
    ]

    async def fake(host: str, email: str, password: str, totp_prompt: Any) -> list[ProbeResult]:
        return results

    ask = _answers("eulogin.bigfix.com", EMAIL, "e", "", "y", "", "y", "")
    code = run_setup(path, input_fn=ask, getpass_fn=lambda p: "pw", saas_probe_fn=fake)
    assert code == 0
    conns = {c.name: c for c in load_config(path).connections}
    assert set(conns) == {"bigfix-saas-eu-bf160001489", "bigfix-saas-eu-bf160002000"}
    assert conns["bigfix-saas-eu-bf160001489"].sid == "bf160001489"
    assert conns["bigfix-saas-eu-bf160002000"].deployment_id == D1
    assert {c.password_env for c in conns.values()} == {"BFRSR_EULOGIN_BIGFIX_COM_PASSWORD"}


def test_setup_saas_rejected_login_is_not_saved(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # Saving it would send the rejected password again on every run.
    path = tmp_path / "c.toml"
    results = [ProbeResult("saas", "login.bigfix.com", "auth", None, "credentials rejected")]
    code = run_setup(
        path,
        input_fn=_answers("login.bigfix.com", EMAIL),
        getpass_fn=lambda p: "pw",
        saas_probe_fn=_fake_saas_probe(results),
    )
    assert code == 2
    assert not path.exists()
    err = capsys.readouterr().err
    assert "credentials rejected" in err
    assert "lock" in err.lower()


def test_setup_saas_totp_prompt_uses_input(tmp_path: Path) -> None:
    seen: list[str] = []

    async def fake(host: str, email: str, password: str, totp_prompt: Any) -> list[ProbeResult]:
        seen.append(totp_prompt("TOTP code: "))
        return [ProbeResult("saas", host, "ok", D5, "")]

    ask = _answers("login.bigfix.com", EMAIL, "654321", "f", "n")
    assert (
        run_setup(tmp_path / "c.toml", input_fn=ask, getpass_fn=lambda p: "pw", saas_probe_fn=fake)
        == 0
    )
    assert seen == ["654321"]


def test_setup_shows_server_text_without_control_characters(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # The wizard talks to a person: probe messages come from the server.
    results = [ProbeResult("rest", "h", "error", None, "bad\x1b]0;pwned\x07\nfake line")]
    run_setup(
        tmp_path / "c.toml",
        input_fn=_answers("h", "op"),
        getpass_fn=lambda p: "pw",
        probe_fn=_fake_probe(results),
    )
    err = capsys.readouterr().err
    assert "\x1b" not in err
    assert "(bad%1b]0;pwned%07%0afake line)" in err
