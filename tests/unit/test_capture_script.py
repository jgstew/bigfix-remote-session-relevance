"""scripts/capture_fixtures.py redaction: what may be committed as a fixture."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "capture_fixtures.py"


def _script() -> ModuleType:
    spec = importlib.util.spec_from_file_location("capture_fixtures", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_preserved_literal_survives_only_in_its_own_case() -> None:
    cf = _script()
    body = '{"result":["11.0.7.48"]}'
    assert cf._redact(body, set(), set(), "version_four_part") == body
    # Any other case's body: an IPv4-shaped value is redacted as usual.
    assert "11.0.7.48" not in cf._redact(body, set(), set(), "singular_string")


def test_preserved_literal_protects_only_the_exact_value() -> None:
    cf = _script()
    text = "111.0.7.48 211.0.7.48 11.0.7.48 10.1.2.3 pw=ab11.0.7.48cd"
    out = cf._redact(text, set(), {"ab11.0.7.48cd"}, "version_four_part")
    assert out.split() == ["192.0.2.1", "192.0.2.2", "11.0.7.48", "192.0.2.3", "pw=REDACTED"]


def test_preserved_literal_equal_to_a_configured_host_is_refused() -> None:
    cf = _script()
    with pytest.raises(SystemExit, match=r"11\.0\.7\.48"):
        cf._redact("x", {"11.0.7.48"}, set(), "version_four_part")


def test_nul_in_a_response_is_refused() -> None:
    cf = _script()
    with pytest.raises(SystemExit, match="NUL"):
        cf._redact("a\x00b", set(), set(), "version_four_part")
