from __future__ import annotations

import logging
import os
import stat
import sys
from pathlib import Path

import pytest

from bigfix_remote_session_relevance.config import (
    ConnectionConfig,
    default_config_path,
    load_config,
    redacted_summary,
    resolve_config_path,
    save_connection,
    set_deployment_id,
)
from bigfix_remote_session_relevance.exceptions import ConfigError

SAMPLE = """\
# my connections
schema_version = 1

[defaults]
connect_timeout = 3
verify = "tofu"

[[connections]]
name = "dev-root"   # the root server
backend = "rest"
server = "bigfix.example.com"
username = "operator"
password_env = "TEST_BFRSR_PW"

[[connections]]
name = "dev-wr"
backend = "webreports"
server = "wr.example.com:8083"
username = "wruser"
password = "inline-secret"
verify = false
read_timeout = 30
"""


def _write(path: Path, text: str, mode: int = 0o600) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    os.chmod(path, mode)
    return path


def test_default_path_is_under_home(_isolated_home: Path) -> None:
    assert default_config_path() == _isolated_home / ".bigfix" / ".remote_session_connections.toml"


def test_resolve_order(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    explicit = tmp_path / "x.toml"
    env = tmp_path / "env.toml"
    monkeypatch.setenv("BFRSR_CONFIG", str(env))
    assert resolve_config_path(explicit) == explicit
    assert resolve_config_path() == env
    monkeypatch.delenv("BFRSR_CONFIG")
    assert resolve_config_path() == default_config_path()


def test_load_applies_defaults_and_overrides(tmp_path: Path) -> None:
    cfg = load_config(_write(tmp_path / "c.toml", SAMPLE))
    root, wr = cfg.connections
    assert root.name == "dev-root"
    assert root.backend == "rest"
    assert root.address.base_url == "https://bigfix.example.com:52311"
    assert root.connect_timeout == 3
    assert root.read_timeout == 120
    assert root.verify == "tofu"
    assert wr.address.base_url == "https://wr.example.com:8083"
    assert wr.verify is False
    assert wr.read_timeout == 30
    assert cfg.backend_preference == ("explorer", "rest", "webreports", "saas")


def test_password_resolution(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cfg = load_config(_write(tmp_path / "c.toml", SAMPLE))
    root, wr = cfg.connections
    monkeypatch.setenv("TEST_BFRSR_PW", "from-env")
    assert root.resolve_password() == "from-env"
    monkeypatch.delenv("TEST_BFRSR_PW")
    assert root.resolve_password() is None
    assert root.resolve_password(prompt=lambda msg: "typed") == "typed"
    assert wr.resolve_password() == "inline-secret"


def test_password_never_in_repr(tmp_path: Path) -> None:
    cfg = load_config(_write(tmp_path / "c.toml", SAMPLE))
    assert "inline-secret" not in repr(cfg)
    assert "inline-secret" not in repr(cfg.connections[1])


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permissions")
def test_warns_when_inline_password_file_is_readable(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.WARNING):
        load_config(_write(tmp_path / "c.toml", SAMPLE, mode=0o644))
    assert "readable" in caplog.text
    assert "inline-secret" not in caplog.text


def test_lenient_aliases(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    text = """
[[connections]]
name = "a"
type = "web_reports"
url = "https://wr.example.com"
user = "u"
password_env = "X"
color = "blue"
"""
    with caplog.at_level(logging.WARNING):
        cfg = load_config(_write(tmp_path / "c.toml", text))
    (a,) = cfg.connections
    assert a.backend == "webreports"
    assert a.username == "u"
    assert a.address.base_url == "https://wr.example.com"
    assert "color" in caplog.text


@pytest.mark.parametrize(
    ("text", "match"),
    [
        ('[[connections]]\nbackend = "rest"\nserver = "h"\n', "name"),
        ('[[connections]]\nname = "a"\nserver = "h"\n', "backend"),
        ('[[connections]]\nname = "a"\nbackend = "nope"\nserver = "h"\n', "backend"),
        ('[[connections]]\nname = "a"\nbackend = "rest"\n', "server"),
        ('[[connections]]\nname = "a"\nbackend = "rest"\nserver = "ftp://h"\n', "a"),
        (
            (
                '[[connections]]\nname = "a"\nbackend = "rest"\nserver = "h"\n'
                '[[connections]]\nname = "a"\nbackend = "rest"\nserver = "h2"\n'
            ),
            "duplicate",
        ),
        ('[[connections]]\nname = "a"\nbackend = "rest"\nserver = "h"\nverify = 3\n', "verify"),
        ("not toml = = =", "parse"),
        ("schema_version = 99\n", "schema_version"),
    ],
)
def test_validation_errors(tmp_path: Path, text: str, match: str) -> None:
    with pytest.raises(ConfigError, match=match):
        load_config(_write(tmp_path / "c.toml", text))


def test_missing_file_gives_empty_config(tmp_path: Path) -> None:
    cfg = load_config(tmp_path / "missing.toml")
    assert cfg.connections == ()


def test_besapi_env_compat(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("BES_ROOT_SERVER", "https://root.example.com:52311")
    monkeypatch.setenv("BES_USER_NAME", "op")
    monkeypatch.setenv("BES_PASSWORD", "pw")
    cfg = load_config(tmp_path / "missing.toml")
    (c,) = cfg.connections
    assert (c.name, c.backend, c.username) == ("besapi-env", "rest", "op")
    assert c.resolve_password() == "pw"


def test_besapi_conf_compat(_isolated_home: Path, tmp_path: Path) -> None:
    (_isolated_home / ".besapi.conf").write_text(
        "[besapi]\nBES_ROOT_SERVER = root.example.com\nBES_USER_NAME = op\nBES_PASSWORD = pw\n"
    )
    cfg = load_config(tmp_path / "missing.toml")
    (c,) = cfg.connections
    assert c.name == "besapi-conf"
    assert c.address.base_url == "https://root.example.com:52311"


def test_besapi_compat_not_used_when_config_exists(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("BES_ROOT_SERVER", "root.example.com")
    monkeypatch.setenv("BES_USER_NAME", "op")
    monkeypatch.setenv("BES_PASSWORD", "pw")
    cfg = load_config(_write(tmp_path / "c.toml", SAMPLE))
    assert [c.name for c in cfg.connections] == ["dev-root", "dev-wr"]


def test_save_creates_file_with_0600(_isolated_home: Path) -> None:
    path = default_config_path()
    save_connection(
        path,
        ConnectionConfig(name="n", backend="rest", server="h", username="u", password_env="P"),
    )
    if sys.platform != "win32":
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
    cfg = load_config(path)
    assert [c.name for c in cfg.connections] == ["n"]


def test_save_preserves_comments_and_rejects_duplicates(tmp_path: Path) -> None:
    path = _write(tmp_path / "c.toml", SAMPLE)
    save_connection(path, ConnectionConfig(name="new", backend="explorer", server="ex"))
    text = path.read_text()
    assert "# my connections" in text
    assert "# the root server" in text
    assert [c.name for c in load_config(path).connections] == ["dev-root", "dev-wr", "new"]
    with pytest.raises(ConfigError, match="exists"):
        save_connection(path, ConnectionConfig(name="new", backend="rest", server="h"))
    save_connection(path, ConnectionConfig(name="new", backend="rest", server="h"), replace=True)
    assert load_config(path).connections[2].backend == "rest"


def test_save_omits_defaults(tmp_path: Path) -> None:
    path = tmp_path / "c.toml"
    save_connection(path, ConnectionConfig(name="n", backend="rest", server="h"))
    text = path.read_text()
    assert "verify" not in text
    assert "timeout" not in text


def test_set_deployment_id_preserves_comments(tmp_path: Path) -> None:
    path = _write(tmp_path / "c.toml", SAMPLE)
    set_deployment_id(path, "dev-root", "ab" * 32)
    assert "# the root server" in path.read_text()
    assert load_config(path).connections[0].deployment_id == "ab" * 32


def test_redacted_summary_never_shows_secrets(tmp_path: Path) -> None:
    cfg = load_config(_write(tmp_path / "c.toml", SAMPLE))
    rows = redacted_summary(cfg)
    flat = repr(rows)
    for secret in ("inline-secret", "operator", "wruser", "TEST_BFRSR_PW"):
        assert secret not in flat
    assert rows[0]["name"] == "dev-root"
    assert rows[0]["server"] == "https://bigfix.example.com:52311"
    assert rows[0]["password"] == "env var (unset)"
    assert rows[1]["password"] == "stored in file"
    assert rows[0]["username"] == "set"


AUTH_SAMPLE = """\
[[connections]]
name = "root-token"
backend = "rest"
server = "root.example.com"
token_env = "TEST_BFRSR_TOKEN"

[[connections]]
name = "ex-mtls"
backend = "explorer"
server = "ex.example.com"
client_cert = "~/certs/op.pem"
client_key = "~/certs/op.key"
client_key_password_env = "TEST_BFRSR_KEYPW"

[[connections]]
name = "ex-basic"
backend = "explorer"
server = "ex.example.com"
username = "op"
password_env = "TEST_BFRSR_PW"

[[connections]]
name = "root-apikey-alias"
backend = "rest"
server = "root2.example.com"
api_key = "inline-token"
"""


def test_auth_methods(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, _isolated_home: Path
) -> None:
    cfg = load_config(_write(tmp_path / "c.toml", AUTH_SAMPLE))
    tok, mtls, basic, alias = cfg.connections
    assert tok.auth == "token"
    monkeypatch.setenv("TEST_BFRSR_TOKEN", "t0k")
    assert tok.resolve_token() == "t0k"
    assert mtls.auth == "mtls"
    assert mtls.client_cert == str(_isolated_home / "certs" / "op.pem")
    assert mtls.client_key == str(_isolated_home / "certs" / "op.key")
    monkeypatch.setenv("TEST_BFRSR_KEYPW", "kpw")
    assert mtls.resolve_client_key_password() == "kpw"
    assert basic.auth == "basic"
    assert alias.auth == "token"
    assert alias.resolve_token() == "inline-token"
    assert "inline-token" not in repr(cfg)


def test_basic_plus_mtls_is_allowed(tmp_path: Path) -> None:
    text = (
        '[[connections]]\nname = "a"\nbackend = "explorer"\nserver = "h"\n'
        'username = "u"\npassword_env = "P"\nclient_cert = "/c.pem"\n'
    )
    (a,) = load_config(_write(tmp_path / "c.toml", text)).connections
    assert a.auth == "basic"
    # Paths are normalized with pathlib, so Windows spells this "\\c.pem".
    assert a.client_cert == str(Path("/c.pem"))


@pytest.mark.parametrize(
    ("text", "match"),
    [
        # Web Reports SOAP only has username/password login.
        (
            '[[connections]]\nname = "a"\nbackend = "webreports"\nserver = "h"\ntoken = "t"\n',
            "token",
        ),
        # Token and basic are alternatives, not a combination.
        (
            (
                '[[connections]]\nname = "a"\nbackend = "rest"\nserver = "h"\ntoken = "t"\n'
                'username = "u"\n'
            ),
            "both",
        ),
        (
            '[[connections]]\nname = "a"\nbackend = "explorer"\nserver = "h"\nclient_key = "/k"\n',
            "client_cert",
        ),
        (
            (
                '[[connections]]\nname = "a"\nbackend = "rest"\nserver = "http://h"\n'
                'client_cert = "/c"\n'
            ),
            "https",
        ),
    ],
)
def test_auth_validation(tmp_path: Path, text: str, match: str) -> None:
    with pytest.raises(ConfigError, match=match):
        load_config(_write(tmp_path / "c.toml", text))


def test_redacted_summary_auth_column(tmp_path: Path) -> None:
    rows = redacted_summary(load_config(_write(tmp_path / "c.toml", AUTH_SAMPLE)))
    assert [r["auth"] for r in rows] == ["token", "mtls", "basic", "token"]
    assert "inline-token" not in repr(rows)
    assert "op.key" not in repr(rows)


SAAS_SAMPLE = """\
[[connections]]
name = "tenant"
backend = "saas"
server = "login.bigfix.com"
username = "operator@example.com"
password_env = "TEST_BFRSR_SAAS_PW"
sid = "bf160001489"
"""


def test_saas_connection(tmp_path: Path) -> None:
    (conn,) = load_config(_write(tmp_path / "c.toml", SAAS_SAMPLE)).connections
    assert (conn.backend, conn.sid, conn.auth) == ("saas", "bf160001489", "basic")
    assert conn.address.base_url == "https://login.bigfix.com"


@pytest.mark.parametrize(
    ("extra", "match"),
    [
        ('server = "tenant.example.com"\n', "SaaS"),
        ('server = "http://login.bigfix.com"\n', "SaaS"),
        ('token = "t"\n', "token"),
        ('sid = "160001489"\n', "sid"),
    ],
)
def test_saas_validation(tmp_path: Path, extra: str, match: str) -> None:
    text = '[[connections]]\nname = "t"\nbackend = "saas"\nusername = "u"\n'
    if "server" not in extra:
        text += 'server = "login.bigfix.com"\n'
    if "token" in extra:
        text = text.replace('username = "u"\n', "")
    with pytest.raises(ConfigError, match=match):
        load_config(_write(tmp_path / "c.toml", text + extra))


def test_sid_saved_and_shown(tmp_path: Path) -> None:
    path = tmp_path / "c.toml"
    save_connection(
        path,
        ConnectionConfig(
            name="tenant",
            backend="saas",
            server="login.bigfix.com",
            username="u",
            password_env="P",
            sid="bf1",
        ),
    )
    (conn,) = load_config(path).connections
    assert conn.sid == "bf1"
    assert redacted_summary(load_config(path))[0]["sid"] == "bf1"
