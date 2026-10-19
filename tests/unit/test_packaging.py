"""Package metadata claims only what CI checks."""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _classifiers() -> list[str]:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]
    return list(project["classifiers"])


def test_python_classifiers_are_the_versions_ci_tests() -> None:
    workflow = (ROOT / ".github" / "workflows" / "test.yaml").read_text()
    matrix = re.search(r"python-version: \[([^\]]*)\]", workflow)
    assert matrix is not None
    tested = {v.strip().strip("\"'") for v in matrix.group(1).split(",")}
    claimed = {
        c.removeprefix("Programming Language :: Python :: ")
        for c in _classifiers()
        if re.fullmatch(r"Programming Language :: Python :: 3\.\d+", c)
    }
    assert claimed == tested


def test_python_classifiers_start_at_requires_python() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]
    lowest = project["requires-python"].removeprefix(">=")
    assert f"Programming Language :: Python :: {lowest}" in _classifiers()


def test_development_status_is_stable() -> None:
    assert "Development Status :: 5 - Production/Stable" in _classifiers()
