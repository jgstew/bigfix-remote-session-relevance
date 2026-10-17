from __future__ import annotations

import io

from bigfix_remote_session_relevance.render import exit_code, render_human
from bigfix_remote_session_relevance.result import ResultError, SessionRelevanceResult
from bigfix_remote_session_relevance.results import SessionRelevanceResults


def _ok(name: str, values: list[object], type_: str = "string") -> SessionRelevanceResult:
    return SessionRelevanceResult.from_values(
        "q",
        values,
        type=type_,
        plural=len(values) != 1,
        connection=name,
        backend="rest",
        evaluation_time_ms=1.5,
        server="https://h:52311",
    )


def _bad(name: str, kind: str, message: str = "boom") -> SessionRelevanceResult:
    return SessionRelevanceResult.failure(
        "q", ResultError(kind=kind, message=message), connection=name, backend="rest"
    )


def _render(results: list[SessionRelevanceResult], verbose: int = 0) -> tuple[str, str]:
    out, err = io.StringIO(), io.StringIO()
    render_human(SessionRelevanceResults(results), out=out, err=err, verbose=verbose)
    return out.getvalue(), err.getvalue()


def test_single_result_is_bare_answers() -> None:
    out, err = _render([_ok("a", [(1, "x"), (2, "y")], "( integer, string )")])
    assert out == "1, x\n2, y\n"
    assert err == ""


def test_multiple_results_get_headers() -> None:
    out, _ = _render([_ok("a", ["1"]), _ok("b", ["2"])])
    assert out == "== a (rest) ==\n1\n== b (rest) ==\n2\n"


def test_errors_go_to_stderr() -> None:
    out, err = _render([_bad("a", "relevance", 'The operator "foo" is not defined.')])
    assert out == ""
    assert 'a: relevance error: The operator "foo" is not defined.' in err


def test_unreachable_hidden_unless_verbose() -> None:
    out, err = _render([_ok("a", ["1"]), _bad("b", "connection", "refused")])
    assert out == "1\n"
    assert "1 unreachable" in err
    assert "refused" not in err
    _, err_v = _render([_ok("a", ["1"]), _bad("b", "connection", "refused")], verbose=1)
    assert "b: connection error: refused" in err_v


def test_verbose_metadata_on_stderr() -> None:
    out, err = _render([_ok("a", ["1"])], verbose=1)
    assert out == "1\n"
    assert "type=string" in err
    assert "plural=False" in err
    assert "time=1.5ms" in err
    assert "connection=a" in err


def test_exit_codes() -> None:
    S = SessionRelevanceResults
    assert exit_code(S([_ok("a", [1])])) == 0
    assert exit_code(S([_ok("a", [1]), _bad("b", "relevance")])) == 1
    assert exit_code(S([_bad("a", "connection"), _bad("b", "authentication")])) == 2
    assert exit_code(S([_ok("a", [1]), _bad("b", "connection")])) == 3
    assert exit_code(S([])) == 64
