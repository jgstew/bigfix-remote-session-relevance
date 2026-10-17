from __future__ import annotations

import pytest

from bigfix_remote_session_relevance import exceptions
from bigfix_remote_session_relevance.result import ResultError, SessionRelevanceResult
from bigfix_remote_session_relevance.results import SessionRelevanceResults


def _ok(name: str, dep: str | None = None) -> SessionRelevanceResult:
    return SessionRelevanceResult.from_values(
        "1", [1], type="integer", connection=name, deployment_id=dep
    )


def _bad(name: str, kind: str, dep: str | None = None) -> SessionRelevanceResult:
    return SessionRelevanceResult.failure(
        "1", ResultError(kind=kind, message=kind), connection=name, deployment_id=dep
    )


def test_sequence_behaviour() -> None:
    results = SessionRelevanceResults([_ok("a"), _bad("b", "connection")])
    assert len(results) == 2
    assert results[0].connection == "a"
    assert [r.connection for r in results] == ["a", "b"]


def test_partitions() -> None:
    results = SessionRelevanceResults(
        [_ok("a"), _bad("b", "connection"), _bad("c", "timeout"), _bad("d", "relevance")]
    )
    assert not results.ok
    assert [r.connection for r in results.successful] == ["a"]
    assert [r.connection for r in results.failed] == ["b", "c", "d"]
    assert [r.connection for r in results.unreachable] == ["b", "c"]
    assert results.first_ok() is results[0]


def test_ok_requires_at_least_one_result() -> None:
    assert not SessionRelevanceResults([]).ok
    assert SessionRelevanceResults([_ok("a")]).ok


def test_by_connection_and_by_deployment() -> None:
    results = SessionRelevanceResults([_ok("a", "d1"), _ok("b")])
    assert set(results.by_connection()) == {"a", "b"}
    # Deployment key falls back to the connection name when the id is unknown.
    assert set(results.by_deployment()) == {"d1", "b"}


def test_raise_for_error_raises_first_failure() -> None:
    results = SessionRelevanceResults([_ok("a"), _bad("b", "authentication")])
    with pytest.raises(exceptions.AuthenticationError):
        results.raise_for_error()
    assert SessionRelevanceResults([_ok("a")]).raise_for_error().ok


def test_to_dict_is_list_of_result_dicts() -> None:
    results = SessionRelevanceResults([_ok("a")])
    assert results.to_dict() == [results[0].to_dict()]


def test_first_ok_none_when_all_failed() -> None:
    assert SessionRelevanceResults([_bad("a", "tls")]).first_ok() is None
