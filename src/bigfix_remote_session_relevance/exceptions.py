"""Exceptions.

Per-query failures are *results*, not exceptions: ``evaluate()`` returns a
`SessionRelevanceResult` with ``error`` set. These classes exist so a caller
can opt into exceptions with ``result.raise_for_error()`` (or
``raise_errors=True``) and still branch on the kind of failure. Only
programmer and configuration mistakes raise directly (`ConfigError`).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .result import SessionRelevanceResult


class SessionRelevanceError(Exception):
    """Base class. ``result`` is the failed result, when there is one."""

    def __init__(self, message: str, result: SessionRelevanceResult | None = None) -> None:
        super().__init__(message)
        self.result = result


class SessionRelevanceEvaluationError(SessionRelevanceError):
    """The server evaluated the session relevance and reported an error."""


class AuthenticationError(SessionRelevanceError):
    """Credentials were rejected (HTTP 401/403, SOAP login failure)."""


class BackendConnectionError(SessionRelevanceError):
    """The server could not be reached."""


class BackendTimeoutError(SessionRelevanceError):
    """The server did not answer in time."""


class TLSError(SessionRelevanceError):
    """Certificate validation failed, or a pinned certificate changed."""


class HTTPStatusError(SessionRelevanceError):
    """An unexpected HTTP status that is not an auth failure."""


class ResponseFormatError(SessionRelevanceError):
    """The body was not the JSON/XML the backend expects (e.g. a login page)."""


class UnsupportedFeatureError(SessionRelevanceError):
    """An Explorer extra was requested from a backend that cannot provide it."""


class ConfigError(SessionRelevanceError):
    """The connection configuration is invalid."""


EXCEPTION_FOR_KIND: dict[str, type[SessionRelevanceError]] = {
    "session_relevance": SessionRelevanceEvaluationError,
    "authentication": AuthenticationError,
    "connection": BackendConnectionError,
    "timeout": BackendTimeoutError,
    "tls": TLSError,
    "http": HTTPStatusError,
    "response_format": ResponseFormatError,
    "unsupported_feature": UnsupportedFeatureError,
}
