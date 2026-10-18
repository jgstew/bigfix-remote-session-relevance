from __future__ import annotations

import io

from bigfix_remote_session_relevance.render import HumanRenderer, exit_code, format_error
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
    # labelled=None: decided by how many results end up shown, as for a batch.
    out, err = io.StringIO(), io.StringIO()
    renderer = HumanRenderer(out=out, err=err, verbose=verbose, labelled=None)
    for r in results:
        renderer.add(r)
    renderer.close()
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


def test_streaming_renderer_writes_each_result_as_it_arrives() -> None:
    out, err = io.StringIO(), io.StringIO()
    renderer = HumanRenderer(out=out, err=err, labelled=True)
    renderer.add(_ok("b", ["2"]))
    assert out.getvalue() == "== b (rest) ==\n2\n"
    renderer.add(_bad("c", "relevance", "nope"))
    assert err.getvalue() == "c: relevance error: nope\n"
    renderer.add(_ok("a", ["1"]))
    assert out.getvalue() == "== b (rest) ==\n2\n== a (rest) ==\n1\n"
    renderer.close()


def test_streaming_renderer_defers_unreachable_until_it_knows_whether_any_answered() -> None:
    out, err = io.StringIO(), io.StringIO()
    renderer = HumanRenderer(out=out, err=err, labelled=True)
    renderer.add(_bad("b", "connection", "refused"))
    assert err.getvalue() == ""
    renderer.add(_bad("c", "timeout", "slow"))
    renderer.close()
    assert "b: connection error: refused" in err.getvalue()
    assert "c: timeout error: slow" in err.getvalue()


def test_summary_collapses_identical_answers_majority_first() -> None:
    out, _ = _render(
        [
            _ok("a", ["1"]),
            _ok("b", ["2", "3"]),
            _ok("c", ["2", "3"]),
            _bad("d", "relevance", "nope"),
            _bad("e", "relevance", "nope"),
            _bad("f", "relevance", "nope"),
        ]
    )
    summary = out.split("\n\n", 1)[1]
    assert summary == (
        "== summary: 6 results, 3 distinct answers\n"
        "3× !! relevance: nope\n"
        "    d (rest), e (rest), f (rest)\n"
        "2× 2 | 3\n"
        "    b (rest), c (rest)\n"
        "1× 1\n"
        "    a (rest)\n"
    )


def test_summary_all_agree() -> None:
    out, _ = _render([_ok("a", ["1"]), _ok("b", ["1"])])
    assert out.endswith(
        "\n\n== summary: 2 results, 1 distinct answer\n2× 1\n    a (rest), b (rest)\n"
    )


def test_summary_tells_answer_types_apart() -> None:
    out, _ = _render([_ok("a", ["1"], "integer"), _ok("b", ["1"], "string")])
    assert "summary" not in out


def test_no_summary_when_nothing_collapses_or_single() -> None:
    out, _ = _render([_ok("a", ["1"]), _ok("b", ["2"])])
    assert "summary" not in out
    out, _ = _render([_ok("a", ["1"])])
    assert "summary" not in out


def test_summary_truncates_long_answers_and_marks_empty() -> None:
    long = "x" * 200
    out, _ = _render([_ok("a", [long]), _ok("b", [long]), _ok("c", []), _ok("d", [])])
    assert "2× " + "x" * 119 + "…\n" in out
    assert "2× (no answers)\n" in out


def test_undecided_labelling_holds_only_the_first_answer() -> None:
    out, err = io.StringIO(), io.StringIO()
    renderer = HumanRenderer(out=out, err=err, labelled=None)
    renderer.add(_ok("a", ["1"]))
    assert out.getvalue() == ""  # one section or several? not known yet
    renderer.add(_ok("b", ["2"]))
    assert out.getvalue() == "== a (rest) ==\n1\n== b (rest) ==\n2\n"
    renderer.close()


def test_summary_collapses_errors_that_differ_only_in_connections_tried() -> None:
    out, _ = _render(
        [
            _ok("x", ["1"]),
            _bad("a", "authentication", "rejected (tried a: authentication, b: authentication)"),
            _bad("c", "authentication", "rejected (tried c: authentication)"),
        ]
    )
    assert "2× !! authentication: rejected\n    a (rest), c (rest)\n" in out


def test_format_error() -> None:
    assert format_error(_bad("a", "relevance", "nope")) == "a: relevance error: nope"
