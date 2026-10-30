"""Where this library keeps its files: ``$BFRSR_HOME``, else ``~/.bigfix``.

Every default path (connections, pinned certificates, the local root
server's cached deployment id) is built on `data_dir`, so a sandboxed app
points them all at its own container by setting one variable at startup.
The specific overrides (``BFRSR_CONFIG``, a constructor's ``path``) still
win. Read on every call, not at import, so it can be set after importing.
"""

from __future__ import annotations

import os
from pathlib import Path

DATA_DIR_ENV = "BFRSR_HOME"


def data_dir() -> Path:
    """``$BFRSR_HOME`` (``~`` expanded), else ``~/.bigfix``; blank counts as unset."""
    env = os.environ.get(DATA_DIR_ENV, "").strip()
    return Path(env).expanduser() if env else Path.home() / ".bigfix"


__all__ = ["DATA_DIR_ENV", "data_dir"]
