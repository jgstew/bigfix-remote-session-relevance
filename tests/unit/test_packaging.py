"""Package metadata claims only what CI checks."""

from __future__ import annotations

import re
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import Any

import pytest

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


def test_version_is_the_installed_distributions() -> None:
    from importlib.metadata import version

    import bigfix_remote_session_relevance as pkg

    assert pkg.__version__ == version("bigfix-remote-session-relevance")
    assert pkg.__version__ == _project()["version"]
    assert "__version__" in pkg.__all__


def test_version_is_unknown_from_a_bare_source_tree(monkeypatch: pytest.MonkeyPatch) -> None:
    import importlib.metadata

    import bigfix_remote_session_relevance as pkg

    def missing(name: str) -> str:
        raise importlib.metadata.PackageNotFoundError(name)

    monkeypatch.setattr(importlib.metadata, "version", missing)
    monkeypatch.delitem(pkg.__dict__, "__version__", raising=False)
    assert pkg.__version__ == "0+unknown"


def test_import_does_not_read_package_metadata() -> None:
    # importlib.metadata is not otherwise imported, and loading it (and
    # scanning sys.path for the distribution) costs several ms: a GUI or CLI
    # that never asks for __version__ should not pay for it.
    # If Python itself (or a dependency) already loaded it, only check that
    # the lookup waits for the first access.
    code = (
        "import sys; preloaded = 'importlib.metadata' in sys.modules; "
        "import bigfix_remote_session_relevance as p; "
        "assert '__version__' not in vars(p), 'read eagerly'; "
        "assert preloaded or 'importlib.metadata' not in sys.modules, 'imported eagerly'; "
        "p.__version__; assert 'importlib.metadata' in sys.modules"
    )
    subprocess.run([sys.executable, "-c", code], check=True)  # noqa: S603
