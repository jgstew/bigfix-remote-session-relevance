from __future__ import annotations

import argparse
import io
import json
import os
import threading
import time
from pathlib import Path
from typing import Any

import httpx
import pytest

from bigfix_remote_session_relevance import cli
from bigfix_remote_session_relevance.config import ConnectionConfig
from bigfix_remote_session_relevance.result import SessionRelevanceResult
from bigfix_remote_session_relevance.trust import CertInfo, KnownCerts

D1 = "1" * 64
D2 = "2" * 64

CONFIG = f"""\
[[connections]]
name = "dev-root"
backend = "rest"
server = "root.example.com"
username = "op"
password_env = "TEST_BFRSR_PW"
deployment_id = "{D1}"
verify = true

[[connections]]
name = "dev-wr"
backend = "webreports"
server = "wr.example.com"
username = "wrop"
password = "inline-secret"
deployment_id = "{D2}"
verify = true
"""


@pytest.fixture
def config_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    path = tmp_path / "c.toml"
    path.write_text(CONFIG)
    os.chmod(path, 0o600)
    monkeypatch.setenv("BFRSR_CONFIG", str(path))
    monkeypatch.setenv("TEST_BFRSR_PW", "pw")
    return path


def _wr(results: str = "<String>a</String>", error: str | None = None) -> httpx.Response:
    inner = (
        f"<error>{error}</error>"
        if error
        else (
            f"<results>{results}</results><plural>false</plural><type>string</type>"
            "<evaltime>1</evaltime>"
        )
    )
    return httpx.Response(
        200,
        headers={"content-type": "text/xml"},
        text=(
            '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">'
            '<soapenv:Body><GetStructuredRelevanceResultResponse xmlns="http://schemas.bigfix.com/'
            f'Relevance"><StructuredRelevanceResult>{inner}</StructuredRelevanceResult>'
            "</GetStructuredRelevanceResultResponse></soapenv:Body></soapenv:Envelope>"
        ),
    )


def _factory(routes: dict[str, Any]) -> Any:
    def make(conn: ConnectionConfig) -> httpx.AsyncBaseTransport:
        def handler(request: httpx.Request) -> httpx.Response:
            item = routes[conn.name]
            if isinstance(item, BaseException):
                raise item
            return item

        return httpx.MockTransport(handler)

    return make


def _run(argv: list[str], routes: dict[str, Any] | None = None, **kw: Any) -> int:
    return cli.main(argv, transport_factory=_factory(routes or {}), **kw)


def test_plain_query_both_deployments(
    config_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code = _run(
        ["names of bes sites"],
        {
            "dev-root": httpx.Response(
                200, json={"result": ["x"], "plural": False, "type": "string"}
            ),
            "dev-wr": _wr(),
        },
    )
    out = capsys.readouterr().out
    assert code == 0
    assert "== dev-root (rest) ==\nx\n" in out
    assert "== dev-wr (webreports) ==\na\n" in out


def test_json_output(config_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code = _run(
        ["--json", "--connection", "dev-root", "1"],
        {"dev-root": httpx.Response(200, json={"result": [1], "plural": False, "type": "integer"})},
    )
    data = json.loads(capsys.readouterr().out)
    assert code == 0
    assert data[0]["answers"] == [1]
    assert "raw" not in data[0]


def test_json_raw_output(config_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    _run(
        ["--json", "--raw", "--backend", "rest", "1"],
        {"dev-root": httpx.Response(200, json={"result": [1], "plural": False, "type": "integer"})},
    )
    data = json.loads(capsys.readouterr().out)
    assert data[0]["raw"]["format"] == "json"


def test_raw_text_output(config_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    _run(["--raw", "--backend", "webreports", "1"], {"dev-wr": _wr()})
    assert "<StructuredRelevanceResult>" in capsys.readouterr().out


def test_relevance_error_exit_1(config_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code = _run(
        ["--backend", "webreports", "foo"],
        {"dev-wr": _wr(error='The operator "foo" is not defined.')},
    )
    assert code == 1
    assert 'relevance error: The operator "foo" is not defined.' in capsys.readouterr().err


def test_partial_exit_3(config_path: Path) -> None:
    code = _run(
        ["1"],
        {"dev-root": httpx.ConnectError("refused"), "dev-wr": _wr()},
    )
    assert code == 3


def test_nothing_reachable_exit_2(config_path: Path) -> None:
    err = httpx.ConnectError("refused")
    assert _run(["1"], {"dev-root": err, "dev-wr": err}) == 2


def test_stdin_relevance(
    config_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    import io

    monkeypatch.setattr("sys.stdin", io.StringIO("names of bes sites\n"))
    _run(
        ["--json", "--backend", "rest", "-"],
        {"dev-root": httpx.Response(200, json={"result": [], "plural": True, "type": "string"})},
    )
    assert json.loads(capsys.readouterr().out)[0]["session_relevance"] == "names of bes sites"


def test_missing_relevance_is_usage_error(
    config_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert _run([]) == 64


def test_no_config_non_tty_hints_setup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("BFRSR_CONFIG", str(tmp_path / "none.toml"))
    code = _run(["1"], interactive=False)
    assert code == 64
    assert "--setup" in capsys.readouterr().err


def test_bad_config_is_64(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "c.toml"
    path.write_text("[[connections]]\nname = 1\n")
    monkeypatch.setenv("BFRSR_CONFIG", str(path))
    assert _run(["1"]) == 64
    assert "config" in capsys.readouterr().err.lower()


def test_unknown_connection_is_64(config_path: Path) -> None:
    assert _run(["--connection", "nope", "1"]) == 64


def test_show_config_is_redacted(config_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert _run(["--show-config"]) == 0
    out = capsys.readouterr().out
    assert "dev-root" in out and "https://root.example.com:52311" in out
    for secret in ("inline-secret", "wrop", "TEST_BFRSR_PW"):
        assert secret not in out


def test_keys_and_filters_use_explorer_extras(
    config_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    seen: list[httpx.Request] = []

    def make(conn: ConnectionConfig) -> httpx.AsyncBaseTransport:
        def handler(request: httpx.Request) -> httpx.Response:
            seen.append(request)
            return httpx.Response(200, json={"result": [{"id": 1}], "plural": True})

        return httpx.MockTransport(handler)

    code = cli.main(
        ["--json", "--connection", "dev-root", "--keys", "id", "--filter", "computers=true", "q"],
        transport_factory=make,
    )
    assert code == 0
    body = json.loads(seen[0].content)
    assert body == {"relevance": "q", "keys": "id", "filters": {"computers": "true"}}


def test_bad_filter_syntax_is_64(config_path: Path) -> None:
    assert _run(["--filter", "nonsense", "q"]) == 64


def test_show_and_forget_certs(_isolated_home: Path, capsys: pytest.CaptureFixture[str]) -> None:
    known = KnownCerts()
    known.pin(CertInfo(host_port="10.0.0.5:52311", sha256="ab" * 32, pem="PEM"), trusted_by="auto")
    assert _run(["--show-certs"]) == 0
    assert "10.0.0.5:52311" in capsys.readouterr().out
    assert _run(["--forget-cert", "10.0.0.5:52311"]) == 0
    assert known.all() == []
    assert _run(["--forget-cert", "10.0.0.5:52311"]) == 1


def test_trust_cert_by_connection_name(
    config_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    async def fake_fetch(host: str, port: int, *, handshake_timeout: float = 10.0) -> CertInfo:
        return CertInfo(host_port=f"{host}:{port}", sha256="cd" * 32, pem="PEM")

    monkeypatch.setattr(cli, "fetch_server_cert", fake_fetch)
    code = cli.main(["--trust-cert", "dev-root"], input_fn=lambda prompt: "y")
    assert code == 0
    pin = KnownCerts().get("root.example.com:52311")
    assert pin is not None
    assert pin.sha256 == "cd" * 32
    assert "CD:CD" in capsys.readouterr().out


def test_trust_cert_declined(config_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_fetch(host: str, port: int, *, handshake_timeout: float = 10.0) -> CertInfo:
        return CertInfo(host_port=f"{host}:{port}", sha256="cd" * 32, pem="PEM")

    monkeypatch.setattr(cli, "fetch_server_cert", fake_fetch)
    assert cli.main(["--trust-cert", "h:443"], input_fn=lambda prompt: "n") == 1
    assert KnownCerts().get("h:443") is None


def test_version(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as info:
        cli.main(["--version"])
    assert info.value.code == 0
    assert capsys.readouterr().out.strip()[0].isdigit()


def test_identical_answers_are_summarized(
    config_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code = _run(
        ["1"],
        {
            "dev-root": httpx.Response(
                200, json={"result": ["a"], "plural": False, "type": "string"}
            ),
            "dev-wr": _wr(),
        },
    )
    out = capsys.readouterr().out
    assert code == 0
    summary = out.split("\n\n", 1)[1]
    assert summary.startswith("== summary: 2 results, 1 distinct answer\n2× a\n    ")
    # Members are listed in arrival order, which the two fakes don't fix.
    assert sorted(summary.splitlines()[2].strip().split(", ")) == [
        "dev-root (rest)",
        "dev-wr (webreports)",
    ]


def test_partial_still_labels_the_answer(
    config_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # Two deployments are expected, so the one that answers is labelled
    # as it streams in, before anyone knows the other is unreachable.
    _run(["1"], {"dev-root": httpx.ConnectError("refused"), "dev-wr": _wr()})
    captured = capsys.readouterr()
    assert captured.out == "== dev-wr (webreports) ==\na\n"
    assert "1 unreachable" in captured.err


@pytest.mark.parametrize("flag", ["--all", "-all", "--all-connections"])
def test_all_is_an_alias_for_all_connections(
    flag: str, config_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    modes: list[str] = []
    original = cli.SessionRelevanceClient.__init__

    def spy(self: Any, *args: Any, **kwargs: Any) -> None:
        modes.append(kwargs["mode"])
        original(self, *args, **kwargs)

    monkeypatch.setattr(cli.SessionRelevanceClient, "__init__", spy)
    _run([flag, "1"], {"dev-root": _wr(), "dev-wr": _wr()})
    assert modes == ["all"]


def test_all_is_a_declared_option_not_an_abbreviation() -> None:
    # argparse would also accept --all as a prefix of --all-connections, but
    # only until some other --all... option exists.
    actions = cli.build_parser()._option_string_actions
    for alias in ("--all", "-all"):
        assert alias in actions
        assert "--all-connections" in actions[alias].option_strings


def test_bad_explorer_keys_rejected_before_any_connection_is_built(config_path: Path) -> None:
    built: list[str] = []

    def factory(conn: ConnectionConfig) -> httpx.AsyncBaseTransport:
        built.append(conn.name)
        raise AssertionError("must not get this far")

    assert cli.main(["--keys", "id {", "1"], transport_factory=factory) == 64
    assert built == []


def test_unexpected_error_while_streaming_is_not_a_usage_error(
    config_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def broken(self: Any, result: Any) -> None:
        raise ValueError("a bug, not bad input")

    monkeypatch.setattr(cli.HumanRenderer, "add", broken)
    with pytest.raises(ValueError, match="a bug"):
        _run(["--backend", "webreports", "1"], {"dev-wr": _wr()})


def test_prompts_hold_the_terminal(config_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("TEST_BFRSR_PW")
    held: list[bool] = []

    def secret(prompt: str) -> str:
        held.append(cli._TERMINAL.locked())
        return "pw"

    routes = {"dev-root": httpx.Response(200, json={"result": ["x"], "plural": False})}
    _run(["--backend", "rest", "1"], routes, getpass_fn=secret, interactive=True)
    assert held == [True]


def test_streamed_output_waits_while_a_prompt_holds_the_terminal(
    capsys: pytest.CaptureFixture[str],
) -> None:
    result = SessionRelevanceResult.from_values("q", ["1"], connection="a", backend="rest")
    args = argparse.Namespace(raw=False, verbose=0)
    with cli._TERMINAL:
        worker = threading.Thread(
            target=cli._print_stream, args=(iter([result]), args), kwargs={"labelled": False}
        )
        worker.start()
        time.sleep(0.1)
        assert capsys.readouterr().out == ""
    worker.join(2)
    assert capsys.readouterr().out == "1\n"


def test_keep_escapes(config_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    routes = {
        "dev-root": httpx.Response(
            200, json={"result": ["a\tb"], "plural": False, "type": "string"}
        ),
        "dev-wr": _wr("<String>a%09b</String>"),
    }
    assert _run(["--json", "q"], routes) == 0
    assert {r["answers"][0] for r in json.loads(capsys.readouterr().out)} == {"a\tb"}
    assert _run(["--json", "--keep-escapes", "q"], routes) == 0
    assert {r["answers"][0] for r in json.loads(capsys.readouterr().out)} == {"a%09b"}


def test_keep_escapes_text_output(config_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    routes = {"dev-wr": _wr("<String>x%0ay</String>")}
    assert _run(["--connection", "dev-wr", "q"], routes) == 0
    assert capsys.readouterr().out == "x\ny\n"  # one answer, two lines
    assert _run(["--connection", "dev-wr", "--keep-escapes", "q"], routes) == 0
    assert capsys.readouterr().out == "x%0ay\n"


def test_keep_escapes_with_keys(config_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    routes = {
        "dev-root": httpx.Response(
            200, json={"result": [{"name": "a\tb"}], "plural": True, "type": "string"}
        )
    }
    argv = ["--json", "--connection", "dev-root", "--keys", "name", "--keep-escapes", "q"]
    assert _run(argv, routes) == 0
    assert json.loads(capsys.readouterr().out)[0]["answers"] == [{"name": "a%09b"}]


def _hostile_routes() -> dict[str, Any]:
    return {
        "dev-root": httpx.Response(
            200, json={"result": ["\x1b[31mred", "one\ntwo"], "plural": True, "type": "string"}
        ),
    }


def test_tty_text_output_escapes_control_characters(
    config_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(cli.sys.stdout, "isatty", lambda: True)
    assert _run(["--connection", "dev-root", "q"], _hostile_routes()) == 0
    assert capsys.readouterr().out == "%1b[31mred\none%0atwo\n"


def test_piped_text_output_is_unchanged(
    config_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert _run(["--connection", "dev-root", "q"], _hostile_routes()) == 0
    assert capsys.readouterr().out == "\x1b[31mred\none\ntwo\n"


@pytest.mark.parametrize("flag", ["--json", "--raw"])
def test_tty_never_changes_json_or_raw(
    flag: str,
    config_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(cli.sys.stdout, "isatty", lambda: True)
    assert _run(["--connection", "dev-root", flag, "q"], _hostile_routes()) == 0
    out = capsys.readouterr().out
    if flag == "--json":
        assert json.loads(out)[0]["answers"] == ["\x1b[31mred", "one\ntwo"]
    else:
        assert '"\\u001b[31mred"' in out  # the server's JSON, as it sent it


def test_tty_raw_mode_error_line_is_escaped(
    config_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(cli.sys.stderr, "isatty", lambda: True)
    # A connection error has no raw response, so --raw prints the error line.
    routes = {"dev-wr": httpx.ConnectError("bad\x1b[2J")}
    _run(["--connection", "dev-wr", "--raw", "q"], routes)
    err = capsys.readouterr().err
    assert "\x1b" not in err
    assert "bad%1b[2J" in err


def test_discover_deployments_rejects_a_bogus_id(
    config_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # No configured id to fall back on, so a rejected answer shows.
    config_path.write_text(CONFIG.replace(f'deployment_id = "{D1}"\n', ""))
    routes = {
        "dev-root": httpx.Response(
            200, json={"result": ["\x1b]0;pwned\x07"], "plural": False, "type": "string"}
        ),
        "dev-wr": _wr(f"<String>{'a' * 64}</String>"),
    }
    assert _run(["--discover-deployments"], routes) == 0
    out = capsys.readouterr().out
    assert "\x1b" not in out
    assert "dev-root: (not discovered)" in out
    assert f"dev-wr: {'a' * 64}" in out
    assert "pwned" not in config_path.read_text()


def test_show_config_escapes_control_characters(
    config_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # e.g. an id cached by an older version, which didn't check it
    config_path.write_text(CONFIG.replace(D1, "\\u001b]0;pwned\\u0007" + "1" * 50))
    assert _run(["--show-config"]) == 0
    out = capsys.readouterr().out
    assert "\x1b" not in out
    assert "%1b]0;pwned" in out


def test_lone_surrogate_in_an_answer_does_not_crash_the_output(
    config_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # Valid JSON (a \ud800 escape) but not encodable as UTF-8.
    routes = {
        "dev-root": httpx.Response(
            200,
            headers={"content-type": "application/json"},
            text='{"result": ["a\\ud800b"], "plural": false, "type": "string"}',
        )
    }
    assert _run(["--connection", "dev-root", "q"], routes) == 0
    assert capsys.readouterr().out == "a\\ud800b\n"
    assert _run(["--connection", "dev-root", "--json", "q"], routes) == 0
    assert json.loads(capsys.readouterr().out)[0]["answers"] == ["a\ud800b"]


def test_discover_deployments_escapes_an_id_cached_before_ids_were_checked(
    config_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    config_path.write_text(CONFIG.replace(D1, "\\u001b]0;pwned\\u0007"))
    monkeypatch.setattr(cli.sys.stdout, "isatty", lambda: True)
    routes = {
        "dev-root": httpx.ConnectError("refused"),
        "dev-wr": _wr(f"<String>{'a' * 64}</String>"),
    }
    _run(["--discover-deployments"], routes)
    out = capsys.readouterr().out
    assert "\x1b" not in out
    assert "dev-root: %1b]0;pwned%07" in out


@pytest.mark.parametrize("errors", ["strict", "surrogateescape"])
def test_tolerate_unencodable_covers_every_handler_that_can_fail(errors: str) -> None:
    # surrogateescape is CPython's stdout default in UTF-8 mode and the C
    # locale, and it refuses \ud800 just as strict does.
    stream = io.TextIOWrapper(io.BytesIO(), encoding="utf-8", errors=errors)
    cli._tolerate_unencodable(stream)
    stream.write("a\ud800b")
    stream.flush()
    assert stream.buffer.getvalue() == b"a\\ud800b"  # type: ignore[attr-defined]


@pytest.mark.parametrize("errors", ["replace", "xmlcharrefreplace"])
def test_tolerate_unencodable_keeps_a_handler_that_cannot_fail(errors: str) -> None:
    stream = io.TextIOWrapper(io.BytesIO(), encoding="utf-8", errors=errors)
    cli._tolerate_unencodable(stream)
    assert stream.errors == errors


def test_tolerate_unencodable_ignores_closed_or_detached_streams() -> None:
    closed = io.TextIOWrapper(io.BytesIO(), encoding="utf-8")
    closed.close()
    cli._tolerate_unencodable(closed)
    detached = io.TextIOWrapper(io.BytesIO(), encoding="utf-8")
    detached.detach()
    cli._tolerate_unencodable(detached)


@pytest.fixture
def built_stores(monkeypatch: pytest.MonkeyPatch) -> list[cli.TrustStore]:
    """Every TrustStore the CLI builds."""
    stores: list[cli.TrustStore] = []

    class Recording(cli.TrustStore):
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            super().__init__(*args, **kwargs)
            stores.append(self)

    monkeypatch.setattr(cli, "TrustStore", Recording)
    return stores


_OK_ROUTES = {
    "dev-root": httpx.Response(200, json={"result": ["x"], "plural": False, "type": "string"}),
    "dev-wr": _wr(),
}


def test_non_interactive_trust_is_explicit_auto(
    config_path: Path, built_stores: list[cli.TrustStore], recwarn: pytest.WarningsRecorder
) -> None:
    assert _run(["1"], _OK_ROUTES, interactive=False) == 0
    (store,) = built_stores
    assert store.trust_on_first_use == "auto"
    assert store.callback is None
    assert not [w for w in recwarn if issubclass(w.category, DeprecationWarning)]


def test_interactive_trust_asks(
    config_path: Path, built_stores: list[cli.TrustStore], recwarn: pytest.WarningsRecorder
) -> None:
    answers: list[str] = []

    def ask(prompt: str) -> str:
        answers.append(prompt)
        return "n"

    assert _run(["1"], _OK_ROUTES, interactive=True, input_fn=ask) == 0
    (store,) = built_stores
    assert store.trust_on_first_use is True
    assert store.callback is not None
    info = CertInfo(host_port="root.example.com:52311", sha256="ab" * 32, pem="PEM")
    assert store.callback(info) is False
    assert answers == ["Trust and pin this certificate? [y/N] "]
    assert not [w for w in recwarn if issubclass(w.category, DeprecationWarning)]


@pytest.mark.parametrize("interactive", [True, False])
def test_no_tofu_refuses(
    config_path: Path, built_stores: list[cli.TrustStore], interactive: bool
) -> None:
    assert _run(["--no-tofu", "1"], _OK_ROUTES, interactive=interactive) == 0
    (store,) = built_stores
    assert store.trust_on_first_use is False
    assert store.callback is None
