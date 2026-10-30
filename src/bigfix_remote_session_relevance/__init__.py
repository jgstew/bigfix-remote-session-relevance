"""Evaluate BigFix session relevance through any reachable interface.

The REST API, the Web Reports SOAP API and BigFix Explorer all return the
same `SessionRelevanceResult`; callers never see whether the wire format was
JSON or XML. By default every configured deployment is queried concurrently.

    from bigfix_remote_session_relevance import evaluate_session_relevance

    for result in evaluate_session_relevance("number of bes computers"):
        print(result.connection, result.answers if result.ok else result.error)
"""

from __future__ import annotations

from .backends.base import Backend, TrustPolicy
from .backends.client_query import (
    ClientQueryExtras,
    ClientQueryResponse,
    ClientQueryRow,
    client_query_max_targets,
    supports_client_query,
)
from .backends.explorer import ExplorerBackend
from .backends.explorer_extras import ExplorerExtras, supports_explorer_extras
from .backends.registry import backend_from_config
from .backends.rest import RestBackend
from .backends.saas import SaasBackend, SaasSessionPool
from .backends.webreports import WebReportsBackend
from .client import AsyncSessionRelevanceClient
from .config import Config, ConnectionConfig, default_config_path, load_config
from .escapes import escape_answer, escape_result, unescape_answer
from .exceptions import (
    AuthenticationError,
    BackendConnectionError,
    BackendTimeoutError,
    ConfigError,
    HTTPStatusError,
    ResponseFormatError,
    SessionRelevanceError,
    SessionRelevanceEvaluationError,
    TLSError,
    UnsupportedFeatureError,
)
from .paths import data_dir
from .result import ERROR_KINDS, RawResponse, ResultError, SessionRelevanceResult
from .results import SessionRelevanceResults
from .server_address import ServerAddress
from .setup_wizard import run_setup
from .sync import (
    SessionRelevanceClient,
    async_evaluate_session_relevance,
    evaluate_session_relevance,
)
from .trust import CertInfo, KnownCerts, TrustStore

# Read on first access, not at import: importlib.metadata is otherwise never
# loaded, and loading it (plus the distribution lookup) is a few ms.
__version__: str


def __getattr__(name: str) -> str:
    if name != "__version__":
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    import importlib.metadata

    try:
        found = importlib.metadata.version("bigfix-remote-session-relevance")
    except importlib.metadata.PackageNotFoundError:  # a source tree, not installed
        found = "0+unknown"
    globals()["__version__"] = found
    return found


__all__ = [
    "ERROR_KINDS",
    "AsyncSessionRelevanceClient",
    "AuthenticationError",
    "Backend",
    "BackendConnectionError",
    "BackendTimeoutError",
    "CertInfo",
    "ClientQueryExtras",
    "ClientQueryResponse",
    "ClientQueryRow",
    "Config",
    "ConfigError",
    "ConnectionConfig",
    "ExplorerBackend",
    "ExplorerExtras",
    "HTTPStatusError",
    "KnownCerts",
    "RawResponse",
    "ResponseFormatError",
    "RestBackend",
    "ResultError",
    "SaasBackend",
    "SaasSessionPool",
    "ServerAddress",
    "SessionRelevanceClient",
    "SessionRelevanceError",
    "SessionRelevanceEvaluationError",
    "SessionRelevanceResult",
    "SessionRelevanceResults",
    "TLSError",
    "TrustPolicy",
    "TrustStore",
    "UnsupportedFeatureError",
    "WebReportsBackend",
    "__version__",
    "async_evaluate_session_relevance",
    "backend_from_config",
    "client_query_max_targets",
    "data_dir",
    "default_config_path",
    "escape_answer",
    "escape_result",
    "evaluate_session_relevance",
    "load_config",
    "run_setup",
    "supports_client_query",
    "supports_explorer_extras",
    "unescape_answer",
]
