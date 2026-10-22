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
from bigfix_remote_session_relevance.render import EXIT_USAGE
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


@pytest.mark.parametrize(
    "host", ["https://bes-root.local:52311", "https://[fe80::1]:8443", "bf:52311/api"]
)
def test_candidates_keep_a_given_https_port(host: str) -> None:
    # Issue #17: "host:52311" became "[host:52311:8083]" and crashed httpx.
    tried = candidates(host)
    assert tried[:3] == [("explorer", host), ("rest", host), ("webreports", host)]
    assert all(server.endswith(host) for _, server in tried)


@pytest.mark.parametrize(
    ("host", "bare"),
    [
        ("https://bf.example.com", "bf.example.com"),
        ("HTTPS://bf.example.com/api", "bf.example.com"),
        ("https://[::1]", "[::1]"),
    ],
)
def test_candidates_given_https_still_tries_the_web_reports_ports(host: str, bare: str) -> None:
    # A scheme alone names no port: each backend's default, and Web Reports'
    # other https port, are still worth trying; http is not.
    assert candidates(host) == [
        ("explorer", host),
        ("rest", host),
        ("webreports", host),
        ("webreports", f"{bare}:8083"),
    ]


def test_candidates_also_try_http_web_reports_on_a_given_port() -> None:
    # Web Reports is often plain http on a non-default port (e.g. 8080).
    assert candidates("wr.example.com:8080") == [
        ("explorer", "wr.example.com:8080"),
        ("rest", "wr.example.com:8080"),
        ("webreports", "wr.example.com:8080"),
        ("webreports", "http://wr.example.com:8080"),
    ]


@pytest.mark.parametrize("host", ["http://wr.example.com", "HTTP://wr:8080", "http://[::1]/api"])
def test_candidates_given_http_is_web_reports_only(host: str) -> None:
    # Like the default candidates, only Web Reports is ever tried over http.
    assert candidates(host) == [("webreports", host)]


def test_candidates_keep_a_bracketed_ipv6_address() -> None:
    assert candidates("[::1]") == [
        ("explorer", "[::1]"),
        ("rest", "[::1]"),
        ("webreports", "[::1]"),
        ("webreports", "[::1]:8083"),
        ("webreports", "http://[::1]"),
        ("webreports", "http://[::1]:8080"),
    ]


def test_candidates_bracket_a_bare_ipv6_address() -> None:
    assert candidates("fe80::1") == [
        ("explorer", "fe80::1"),
        ("rest", "fe80::1"),
        ("webreports", "fe80::1"),
        ("webreports", "[fe80::1]:8083"),
        ("webreports", "http://[fe80::1]"),
        ("webreports", "http://[fe80::1]:8080"),
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


async def test_probe_a_host_with_a_port_tries_only_that_port() -> None:
    # Issue #17: this raised httpx.InvalidURL instead of probing.
    seen: list[str] = []

    def factory(backend: str, server: str) -> httpx.AsyncBaseTransport:
        def handler(request: httpx.Request) -> httpx.Response:
            seen.append(f"{backend} {request.url.scheme}://{request.url.netloc.decode()}")
            return httpx.Response(401, text="no")

        return httpx.MockTransport(handler)

    results = await probe("bes-root.local:52311", "op", "pw", None, transport_factory=factory)
    assert sorted(seen) == [
        "explorer https://bes-root.local:52311",
        "rest https://bes-root.local:52311",
        "webreports http://bes-root.local:52311",
        "webreports https://bes-root.local:52311",
    ]
    # Every backend answered (401), so the https Web Reports is the one offered.
    assert [(r.backend, r.server, r.status) for r in results] == [
        ("explorer", "bes-root.local:52311", "auth"),
        ("rest", "bes-root.local:52311", "auth"),
        ("webreports", "bes-root.local:52311", "auth"),
    ]


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


def test_setup_prompt_names_every_kind_of_host(tmp_path: Path) -> None:
    ask = _answers("")
    run_setup(tmp_path / "c.toml", input_fn=ask, getpass_fn=lambda p: "pw")
    (prompt,) = ask.prompts
    for part in ("root server", "Explorer", "Web Reports", ":port", "login.bigfix.com"):
        assert part in prompt


@pytest.mark.parametrize("host", ["bf:notaport", "bf:99999", "user@bf", "bf/path"])
def test_setup_rejects_an_unusable_host_before_asking_for_credentials(
    tmp_path: Path, host: str, capsys: pytest.CaptureFixture[str]
) -> None:
    ask = _answers(host)
    code = run_setup(
        tmp_path / "c.toml",
        input_fn=ask,
        getpass_fn=lambda p: pytest.fail("asked for a password"),
        probe_fn=_fake_probe([]),
    )
    assert code == EXIT_USAGE
    assert len(ask.prompts) == 1
    assert host in capsys.readouterr().err


@pytest.mark.parametrize(
    ("host", "name", "env"),
    [
        ("bes-root.local:52311", "bes-root-rest", "BFRSR_BES_ROOT_LOCAL_PASSWORD"),
        ("https://BF.example.com", "bf-rest", "BFRSR_BF_EXAMPLE_COM_PASSWORD"),
        ("[fe80::1]:52311", "fe80-1-rest", "BFRSR_FE80_1_PASSWORD"),
    ],
)
def test_setup_default_names_ignore_a_given_scheme_and_port(
    tmp_path: Path, host: str, name: str, env: str
) -> None:
    path = tmp_path / "c.toml"
    results = [ProbeResult("rest", host, "ok", D1, "")]
    ask = _answers(host, "op", "e", "", "y", "")
    assert (
        run_setup(path, input_fn=ask, getpass_fn=lambda p: "pw", probe_fn=_fake_probe(results)) == 0
    )
    (conn,) = load_config(path).connections
    assert (conn.name, conn.server, conn.password_env) == (name, host, env)


def test_setup_saas_env_var_name_ignores_a_given_scheme(tmp_path: Path) -> None:
    path = tmp_path / "c.toml"
    host = "https://eulogin.bigfix.com"

    async def fake(*args: Any) -> list[ProbeResult]:
        return [ProbeResult("saas", host, "ok", D5, "")]

    ask = _answers(host, EMAIL, "e", "", "y", "")
    code = run_setup(
        path,
        input_fn=ask,
        getpass_fn=lambda p: "pw",
        probe_fn=_on_prem_probe_not_called,
        saas_probe_fn=fake,
    )
    assert code == 0
    (conn,) = load_config(path).connections
    assert (conn.name, conn.password_env) == ("bigfix-saas-eu", "BFRSR_EULOGIN_BIGFIX_COM_PASSWORD")


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


def test_run_setup_backends_filter(tmp_path: Path) -> None:
    # Only rest is offered for saving: no prompt for explorer or web reports.
    path = tmp_path / "c.toml"
    ask = _answers("bf.example.com", "op", "f", "y", "")
    code = run_setup(
        path,
        backends=("rest",),
        input_fn=ask,
        getpass_fn=lambda p: "pw",
        probe_fn=_fake_probe(OK_RESULTS),
    )
    assert code == 0
    assert [c.backend for c in load_config(path).connections] == ["rest"]
    assert not any("explorer" in p or "webreports" in p for p in ask.prompts)


def test_run_setup_backends_filter_nothing_left(tmp_path: Path) -> None:
    results = [ProbeResult("explorer", "bf", "ok", D1, "")]
    code = run_setup(
        tmp_path / "c.toml",
        backends=("rest",),
        input_fn=_answers("bf", "op"),
        getpass_fn=lambda p: "pw",
        probe_fn=_fake_probe(results),
    )
    assert code == 2
    assert not (tmp_path / "c.toml").exists()


def test_run_setup_rejects_unknown_backends(tmp_path: Path) -> None:
    for backends in [("rest", "nope"), ()]:
        with pytest.raises(ValueError, match="backends"):
            run_setup(
                tmp_path / "c.toml",
                backends=backends,
                input_fn=_answers(),
                getpass_fn=lambda p: "pw",
            )


def test_run_setup_saas_host_outside_backends_asks_nothing_more(tmp_path: Path) -> None:
    # Checked before the email and password are asked for, so nothing is sent.
    ask = _answers("login.bigfix.com")
    code = run_setup(
        tmp_path / "c.toml",
        backends=("rest",),
        input_fn=ask,
        getpass_fn=lambda p: pytest.fail("no password prompt"),
    )
    assert code == EXIT_USAGE
    assert len(ask.prompts) == 1


def test_run_setup_path_defaults_to_resolved_config_path(_isolated_home: Path) -> None:
    results = [ProbeResult("rest", "bf.example.com", "ok", D1, "")]
    code = run_setup(
        input_fn=_answers("bf.example.com", "op", "f", "y", ""),
        getpass_fn=lambda p: "pw",
        probe_fn=_fake_probe(results),
    )
    assert code == 0
    (conn,) = load_config(
        _isolated_home / ".bigfix" / ".remote_session_connections.toml"
    ).connections
    assert conn.backend == "rest"


async def test_probe_only_tries_requested_backends() -> None:
    tried: list[str] = []

    def factory(backend: str, server: str) -> httpx.AsyncBaseTransport:
        tried.append(backend)
        return httpx.MockTransport(lambda request: httpx.Response(401, text="no"))

    results = await probe("bf", "op", "pw", None, backends=("rest",), transport_factory=factory)
    assert tried == ["rest"]
    assert [r.backend for r in results] == ["rest"]


def test_run_setup_rejects_a_bare_backend_string(tmp_path: Path) -> None:
    with pytest.raises(TypeError, match="backends"):
        run_setup(tmp_path / "c.toml", backends="rest", input_fn=_answers())


def test_run_setup_says_when_only_other_backends_answered(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    results = [ProbeResult("explorer", "bf", "ok", D1, "")]
    code = run_setup(
        tmp_path / "c.toml",
        backends=("rest",),
        input_fn=_answers("bf", "op"),
        getpass_fn=lambda p: "pw",
        probe_fn=_fake_probe(results),
    )
    assert code == 2
    captured = capsys.readouterr()
    out = captured.out + captured.err
    assert "explorer" in out
    assert "none of rest" in out
    assert "Nothing answered" not in out


def test_run_setup_saas_only_rejects_an_on_prem_host(tmp_path: Path) -> None:
    ask = _answers("bf.example.com")
    code = run_setup(
        tmp_path / "c.toml",
        backends=("saas",),
        input_fn=ask,
        getpass_fn=lambda p: pytest.fail("no password prompt"),
    )
    assert code == EXIT_USAGE
    assert len(ask.prompts) == 1


# -- Explorer / Web Reports listed by the root server ----------------------------------

DISCOVERY = Path(__file__).parent.parent / "fixtures" / "rest" / "captured" / "discovery"


def _discovery(key: str) -> httpx.Response:
    meta = json.loads((DISCOVERY / f"{key}.meta.json").read_text())
    headers = {"content-type": meta["content_type"]} if meta["content_type"] else {}
    return httpx.Response(
        meta["status"], text=(DISCOVERY / f"{key}.body").read_text(), headers=headers
    )


def _rest_ok() -> httpx.Response:
    return httpx.Response(200, json={"result": [D1], "plural": False, "type": "string"})


def _lab(
    explorers: str = "via_explorer__explorers",
    webreports: str = "via_explorer__webreports",
    rest: httpx.Response | None = None,
) -> tuple[Any, list[str]]:
    """A root server at bigfix.example.com listing the lab's captured servers.

    Every probe answers 401 except REST (and the discovery GETs it serves);
    ``seen`` records each request as ``backend scheme://host:port path``.
    """
    seen: list[str] = []

    def factory(backend: str, server: str) -> httpx.AsyncBaseTransport:
        def handler(request: httpx.Request) -> httpx.Response:
            where = f"{request.url.scheme}://{request.url.host}:{request.url.port}"
            seen.append(f"{backend} {where} {request.url.path}")
            if backend == "rest" and request.url.path == "/api/explorers":
                return _discovery(explorers)
            if backend == "rest" and request.url.path == "/api/webreports":
                return _discovery(webreports)
            if backend == "rest":
                return rest or _rest_ok()
            return httpx.Response(401, text="no")

        return httpx.MockTransport(handler)

    return factory, seen


@pytest.mark.parametrize("state", ["", "via_explorer__"], ids=["no_explorer", "explorer"])
async def test_probe_adds_the_servers_the_root_server_lists(state: str) -> None:
    factory, seen = _lab(f"{state}explorers", f"{state}webreports")
    results = await probe("bigfix.example.com", "op", "pw", None, transport_factory=factory)
    listed = [(r.backend, r.server, r.status) for r in results if r.listed]
    # bigfix.example.com:9383 is the Explorer candidate already tried: not again.
    assert listed == [
        ("explorer", "rootserver", "auth"),
        ("webreports", "http://bigfix.example.com:888", "auth"),
    ]
    explorer_probes = [s for s in seen if s.startswith("explorer ")]
    assert explorer_probes.count("explorer https://bigfix.example.com:9383 /api/relevance") == 1
    assert "explorer https://rootserver:9383 /api/relevance" in explorer_probes
    # The host's own candidates are unchanged and come first.
    assert [(r.backend, r.server) for r in results if not r.listed][:2] == [
        ("explorer", "bigfix.example.com"),
        ("rest", "bigfix.example.com"),
    ]


async def test_probe_listed_servers_ask_the_same_trust_policy() -> None:
    # Each listed endpoint is built with the trust the wizard passed in, so a
    # self-signed certificate there gets the same pin-it prompt.
    from bigfix_remote_session_relevance.setup_wizard import BACKEND_CLASSES

    trusts: list[tuple[str, Any]] = []
    factory, _ = _lab()
    marker = object()
    real = dict(BACKEND_CLASSES)

    def spy(name: str) -> Any:
        def build(server: str, **kwargs: Any) -> Any:
            trusts.append((server, kwargs["trust"]))
            return real[name](server, **kwargs)

        return build

    try:
        for name in real:
            BACKEND_CLASSES[name] = spy(name)  # type: ignore[assignment]
        await probe("bigfix.example.com", "op", "pw", marker, transport_factory=factory)  # type: ignore[arg-type]
    finally:
        BACKEND_CLASSES.update(real)
    assert ("rootserver", marker) in trusts
    assert ("http://bigfix.example.com:888", marker) in trusts
    assert all(trust is marker for _, trust in trusts)


@pytest.mark.parametrize("state", ["", "via_explorer__"], ids=["no_explorer", "explorer"])
async def test_probe_without_master_operator_says_so_on_the_rest_result(state: str) -> None:
    factory, seen = _lab(f"{state}explorers_403", f"{state}webreports_403")
    results = await probe("bigfix.example.com", "op", "pw", None, transport_factory=factory)
    assert not any(r.listed for r in results)
    rest = next(r for r in results if r.backend == "rest")
    assert rest.status == "ok"
    assert "master operator" in rest.message
    assert not [s for s in seen if "rootserver" in s or ":888" in s]


async def test_probe_does_not_ask_for_lists_when_rest_failed() -> None:
    factory, seen = _lab(rest=httpx.Response(401, text="no"))
    results = await probe("bigfix.example.com", "op", "pw", None, transport_factory=factory)
    assert not any(r.listed for r in results)
    assert not [s for s in seen if s.endswith(("/api/explorers", "/api/webreports"))]


async def test_probe_lists_only_requested_backends() -> None:
    factory, seen = _lab()
    results = await probe(
        "bigfix.example.com",
        "op",
        "pw",
        None,
        backends=("rest", "explorer"),
        transport_factory=factory,
    )
    assert [(r.backend, r.server) for r in results if r.listed] == [("explorer", "rootserver")]
    assert not [s for s in seen if s.startswith("webreports ")]


async def test_probe_rest_only_never_asks_for_lists() -> None:
    factory, seen = _lab()
    await probe(
        "bigfix.example.com", "op", "pw", None, backends=("rest",), transport_factory=factory
    )
    assert not [s for s in seen if s.endswith(("/api/explorers", "/api/webreports"))]


async def test_probe_listed_server_matching_a_given_port_is_not_probed_twice() -> None:
    # The user typed the port of the Web Reports the root server also lists:
    # its http candidate is that same address, so it is probed once.
    factory, seen = _lab()
    results = await probe("bigfix.example.com:888", "op", "pw", None, transport_factory=factory)
    assert "explorer https://rootserver:9383 /api/relevance" in seen  # the lists were read
    assert [s for s in seen if s.startswith("webreports http://")] == [
        "webreports http://bigfix.example.com:888 /webreports/soap"
    ]
    assert not [r for r in results if r.listed and r.backend == "webreports"]


def test_setup_marks_and_saves_a_listed_server(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "c.toml"
    results = [
        ProbeResult("rest", "bf.example.com", "ok", D1, ""),
        ProbeResult("explorer", "explorer2.example.com", "ok", D1, "", listed=True),
    ]
    ask = _answers("bf.example.com", "op", "f", "y", "", "y", "")
    code = run_setup(path, input_fn=ask, getpass_fn=lambda p: "pw", probe_fn=_fake_probe(results))
    assert code == 0
    err = capsys.readouterr().err
    line = next(x for x in err.splitlines() if "explorer2.example.com" in x)
    assert "listed by the root server" in line
    saved = {c.name: c for c in load_config(path).connections}
    assert saved["explorer2-explorer"].server == "explorer2.example.com"


def test_setup_shows_the_note_on_a_working_rest_result(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    note = "listing other Explorer and Web Reports servers needs a master operator"
    results = [ProbeResult("rest", "bf.example.com", "ok", D1, note)]
    ask = _answers("bf.example.com", "op", "f", "n")
    run_setup(
        tmp_path / "c.toml", input_fn=ask, getpass_fn=lambda p: "pw", probe_fn=_fake_probe(results)
    )
    assert note in capsys.readouterr().err
