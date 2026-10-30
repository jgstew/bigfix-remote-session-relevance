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
    supports_client_query,
)
from .backends.explorer import ExplorerBackend
from .backends.explorer_extras import ExplorerExtras, supports_explorer_extras
from .backends.rest import RestBackend
from .backends.saas import SaasBackend
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
    "async_evaluate_session_relevance",
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
