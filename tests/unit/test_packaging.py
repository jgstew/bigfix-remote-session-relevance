"""Package metadata claims only what CI checks."""

from __future__ import annotations

import re
import tomllib
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]


def _project() -> dict[str, Any]:
    return tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]


def _claimed_versions() -> set[str]:
    prefix = "Programming Language :: Python :: "
    return {
        c.removeprefix(prefix)
        for c in _project()["classifiers"]
        if re.fullmatch(re.escape(prefix) + r"3\.\d+", c)
    }


def test_python_classifiers_are_the_versions_ci_tests() -> None:
    workflow = (ROOT / ".github" / "workflows" / "test.yaml").read_text()
    # Comments dropped first, so a commented-out matrix can't be the one read.
    live = "\n".join(line.split("#", 1)[0] for line in workflow.splitlines())
    matrices = re.findall(r"python-version:\s*\[([^\]]*)\]", live)
    assert len(matrices) == 1, "expected one flow-style python-version list in test.yaml"
    tested = {v.strip().strip("\"'") for v in matrices[0].split(",") if v.strip()}
    assert _claimed_versions() == tested


def test_python_classifiers_start_at_requires_python() -> None:
    match = re.fullmatch(r">=\s*(3\.\d+)", _project()["requires-python"].strip())
    assert match, "requires-python is expected to be a plain lower bound"
    assert min(_claimed_versions(), key=lambda v: int(v.split(".")[1])) == match.group(1)


def test_development_status_is_stable() -> None:
    assert "Development Status :: 5 - Production/Stable" in _project()["classifiers"]
