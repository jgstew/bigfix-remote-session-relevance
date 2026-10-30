"""``BFRSR_HOME``: one override for every file the library reads or writes.

A sandboxed app (iOS, Android) sets it once at startup to its own data
directory; the specific overrides (``BFRSR_CONFIG``, a constructor ``path``)
still win.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import bigfix_remote_session_relevance as pkg
from bigfix_remote_session_relevance import config as config_module
from bigfix_remote_session_relevance.config import (
    default_config_path,
    load_config,
    local_deployment_cache_path,
    resolve_config_path,
)
from bigfix_remote_session_relevance.paths import DATA_DIR_ENV, data_dir
from bigfix_remote_session_relevance.trust import CertInfo, KnownCerts, default_known_certs_path

CONFIG = """\
schema_version = 1

[[connections]]
name = "dev-root"
backend = "rest"
server = "bigfix.example.com"
username = "operator"
password_env = "BFRSR_TEST_PASSWORD"
"""


def test_env_name() -> None:
    assert DATA_DIR_ENV == "BFRSR_HOME"


def test_defaults_to_dot_bigfix_under_home(_isolated_home: Path) -> None:
    assert data_dir() == _isolated_home / ".bigfix"


@pytest.mark.parametrize("value", ["", "   "])
def test_blank_is_unset(_isolated_home: Path, monkeypatch: pytest.MonkeyPatch, value: str) -> None:
    monkeypatch.setenv(DATA_DIR_ENV, value)
    assert data_dir() == _isolated_home / ".bigfix"


def test_env_overrides(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(DATA_DIR_ENV, str(tmp_path / "app-support"))
    assert data_dir() == tmp_path / "app-support"


def test_env_expands_user(_isolated_home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(DATA_DIR_ENV, "~/Library/Application Support/bfrsr")
    assert data_dir() == _isolated_home / "Library" / "Application Support" / "bfrsr"


def test_read_on_every_call_not_at_import(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # An app sets it at startup, after the library may already be imported.
    before = default_config_path()
    monkeypatch.setenv(DATA_DIR_ENV, str(tmp_path / "later"))
    assert default_config_path() != before
    assert default_config_path().parent == tmp_path / "later"


def test_every_default_path_is_under_it(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = tmp_path / "app-support"
    monkeypatch.setenv(DATA_DIR_ENV, str(home))
    assert default_config_path() == home / ".remote_session_connections.toml"
    assert resolve_config_path() == home / ".remote_session_connections.toml"
    assert default_known_certs_path() == home / ".remote_session_known_certs.toml"
    assert KnownCerts().path == home / ".remote_session_known_certs.toml"
    assert local_deployment_cache_path() == home / ".remote_session_local_root_server.toml"


def test_bfrsr_config_still_wins(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(DATA_DIR_ENV, str(tmp_path / "app-support"))
    monkeypatch.setenv("BFRSR_CONFIG", str(tmp_path / "elsewhere.toml"))
    assert resolve_config_path() == tmp_path / "elsewhere.toml"
    assert resolve_config_path(tmp_path / "explicit.toml") == tmp_path / "explicit.toml"


def test_explicit_known_certs_path_still_wins(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(DATA_DIR_ENV, str(tmp_path / "app-support"))
    assert KnownCerts(tmp_path / "pins.toml").path == tmp_path / "pins.toml"


def test_load_config_reads_from_it(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = tmp_path / "app-support"
    home.mkdir()
    (home / ".remote_session_connections.toml").write_text(CONFIG)
    (home / ".remote_session_connections.toml").chmod(0o600)
    monkeypatch.setenv(DATA_DIR_ENV, str(home))
    config = load_config()
    assert config.path == home / ".remote_session_connections.toml"
    assert [c.name for c in config.connections] == ["dev-root"]


def test_writes_land_under_it_not_home(
    _isolated_home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "app-support"
    monkeypatch.setenv(DATA_DIR_ENV, str(home))
    config_module.record_local_deployment_id("https://localhost:52311", "d" * 40)
    KnownCerts().pin(CertInfo("bigfix.example.com:52311", "ab" * 32, "PEM"), trusted_by="test")
    assert (home / ".remote_session_local_root_server.toml").is_file()
    assert (home / ".remote_session_known_certs.toml").is_file()
    assert not (_isolated_home / ".bigfix").exists()


def test_tests_never_inherit_it() -> None:
    # tests/conftest.py clears it, so a developer's own BFRSR_HOME cannot
    # send a test's writes into their real data directory.
    import os

    assert DATA_DIR_ENV not in os.environ


def test_exported() -> None:
    assert pkg.data_dir is data_dir
    assert "data_dir" in pkg.__all__
