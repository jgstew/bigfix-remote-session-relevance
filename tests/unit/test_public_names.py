"""The public API names session relevance explicitly, never bare ``relevance``.

Session and client relevance are different dialects; callers (and the sibling
bigfix-remote-client-relevance) must never have to guess which one a
parameter takes.
"""

from __future__ import annotations

import inspect
from collections.abc import Callable
from typing import Any

import pytest

import bigfix_remote_session_relevance as pkg
from bigfix_remote_session_relevance.backends.base import Backend
from bigfix_remote_session_relevance.backends.explorer_extras import ExplorerExtras

SINGLE: list[Callable[..., Any]] = [
    pkg.AsyncSessionRelevanceClient.evaluate,
    pkg.AsyncSessionRelevanceClient.evaluate_stream,
    pkg.AsyncSessionRelevanceClient.evaluate_explorer,
    pkg.AsyncSessionRelevanceClient.evaluate_explorer_stream,
    pkg.SessionRelevanceClient.evaluate,
    pkg.SessionRelevanceClient.evaluate_stream,
    pkg.SessionRelevanceClient.evaluate_explorer,
    pkg.SessionRelevanceClient.evaluate_explorer_stream,
    pkg.evaluate_session_relevance,
    pkg.async_evaluate_session_relevance,
    pkg.SessionRelevanceResult.from_values,
    pkg.SessionRelevanceResult.failure,
    Backend.evaluate,
    ExplorerExtras.evaluate_explorer,
    pkg.ExplorerBackend.evaluate_explorer,
    pkg.RestBackend.evaluate_explorer,
]

MANY: list[Callable[..., Any]] = [
    pkg.AsyncSessionRelevanceClient.evaluate_many,
    pkg.SessionRelevanceClient.evaluate_many,
]


# BigFix Query sends client relevance: the other dialect, named as such.
CLIENT: list[Callable[..., Any]] = [
    pkg.ClientQueryExtras.submit_client_query,
    pkg.RestBackend.submit_client_query,
]


def _params(func: Callable[..., Any]) -> list[str]:
    return [p for p in inspect.signature(func).parameters if p not in ("self", "cls")]


@pytest.mark.parametrize("func", SINGLE, ids=lambda f: f.__qualname__)
def test_takes_session_relevance(func: Callable[..., Any]) -> None:
    params = _params(func)
    assert params[0] == "session_relevance"
    assert "relevance" not in params


@pytest.mark.parametrize("func", MANY, ids=lambda f: f.__qualname__)
def test_takes_session_relevances(func: Callable[..., Any]) -> None:
    params = _params(func)
    assert params[0] == "session_relevances"
    assert "relevances" not in params


@pytest.mark.parametrize("func", CLIENT, ids=lambda f: f.__qualname__)
def test_client_query_takes_client_relevance(func: Callable[..., Any]) -> None:
    params = _params(func)
    assert params[:2] == ["client_relevance", "computer_ids"]
    assert "relevance" not in params
    assert "session_relevance" not in params


def _public_callables() -> list[Callable[..., Any]]:
    """Every public function and public method reachable from the package."""
    from bigfix_remote_session_relevance.backends import explorer_extras

    found: list[Callable[..., Any]] = [explorer_extras.explorer_body]
    for name in pkg.__all__:
        obj = getattr(pkg, name)
        if inspect.isfunction(obj):
            found.append(obj)
        elif inspect.isclass(obj):
            for attr, member in inspect.getmembers(obj):
                if attr.startswith("_") and attr != "__init__":
                    continue
                func = getattr(member, "__func__", member)
                if inspect.isfunction(func) and func.__module__.startswith(pkg.__name__):
                    found.append(func)
    return found


def test_no_public_parameter_is_bare_relevance() -> None:
    offenders = [
        f"{f.__module__}.{f.__qualname__}({p})"
        for f in _public_callables()
        for p in inspect.signature(f).parameters
        if p in ("relevance", "relevances")
    ]
    assert offenders == []


def test_guard_sees_the_known_entry_points() -> None:
    names = {f.__qualname__ for f in _public_callables()}
    assert {"SessionRelevanceClient.evaluate_many", "Backend.evaluate", "explorer_body"} <= names


def test_backend_not_implemented_error_is_not_exported() -> None:
    assert "BackendNotImplementedError" not in pkg.__all__
    assert not hasattr(pkg, "BackendNotImplementedError")


# The public names 1.0 freezes (README § Compatibility). Removing one is a
# major version; adding one means adding it here, on purpose.
PUBLIC_NAMES = [
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
    "ERROR_KINDS",
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


def test_all_is_the_designed_public_surface() -> None:
    assert sorted(pkg.__all__) == PUBLIC_NAMES


# Public, but may change in a minor release (README § Compatibility).
PROVISIONAL = {
    "Backend",
    "ExplorerBackend",
    "RestBackend",
    "SaasBackend",
    "WebReportsBackend",
    "CertInfo",
    "KnownCerts",
    "TrustStore",
    # 1.1.0: for bigfix-remote-client-relevance's Fast Query (issue #15).
    "ClientQueryExtras",
    "ClientQueryResponse",
    "ClientQueryRow",
    "supports_client_query",
    "run_setup",
    # 1.4.0: so callers can type their own trust policies (issue #30).
    "ServerAddress",
    "TrustPolicy",
}


def test_provisional_names_are_public_names() -> None:
    assert PROVISIONAL.issubset(PUBLIC_NAMES)
