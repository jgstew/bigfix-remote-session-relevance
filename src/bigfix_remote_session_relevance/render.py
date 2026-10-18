"""Human-readable output and CLI exit codes.

Answers go to stdout and nothing else does, so output pipes cleanly;
errors, metadata (``-v``) and notices go to stderr.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import TextIO

from .client import without_attempts
from .result import SessionRelevanceResult
from .results import UNREACHABLE_KINDS, SessionRelevanceResults

EXIT_OK = 0
EXIT_RELEVANCE_ERROR = 1
EXIT_NOTHING_REACHABLE = 2
EXIT_PARTIAL = 3
EXIT_USAGE = 64


class HumanRenderer:
    """Writes each result the moment it is added, then a summary on `close`.

    ``labelled`` (section headers) is best decided up front, from how many
    results are expected, so the first section looks the same as the rest.
    ``None`` means not known yet: the first answer is held back until a
    second result shows (labelled) or the run ends (bare answers).
    Unreachable errors are held back too: with no ``-v`` they are hidden
    when another deployment answered, which is only known once all are in.
    """

    def __init__(
        self, *, out: TextIO, err: TextIO, verbose: int = 0, labelled: bool | None = False
    ) -> None:
        self._out = out
        self._err = err
        self._verbose = verbose
        self._labelled = labelled
        self._held: SessionRelevanceResult | None = None
        self._shown: list[SessionRelevanceResult] = []
        self._deferred: list[SessionRelevanceResult] = []
        self._any_ok = False

    def add(self, result: SessionRelevanceResult) -> None:
        self._any_ok = self._any_ok or result.ok
        if _unreachable(result) and not self._verbose:
            self._deferred.append(result)
            return
        self._show(result)

    def close(self) -> None:
        hidden = 0
        if self._any_ok:
            hidden = len(self._deferred)
        else:
            for r in self._deferred:
                self._show(r)
        self._deferred = []
        if self._labelled is None:
            self._labelled = False  # never got past one shown result
            self._release()
        if self._labelled:
            summary = render_summary(self._shown)
            if summary:
                self._out.write(f"\n{summary}")
                self._out.flush()
        if hidden:
            self._err.write(f"({hidden} unreachable; use -v for details)\n")
            self._err.flush()

    def _show(self, r: SessionRelevanceResult) -> None:
        self._shown.append(r)
        if self._labelled is None and len(self._shown) > 1:
            self._labelled = True
            self._release()
        if self._labelled is None and r.ok:
            self._held = r
            return
        self._write(r)

    def _release(self) -> None:
        held, self._held = self._held, None
        if held is not None:
            self._write(held)

    def _write(self, r: SessionRelevanceResult) -> None:
        if r.ok:
            if self._labelled:
                self._out.write(f"== {_label(r)} ==\n")
            self._out.writelines(f"{line}\n" for line in r.answer_strings)
            # Flushed per result: piped stdout is block-buffered, which would
            # hold every answer back until the slowest deployment is done.
            self._out.flush()
            if self._verbose:
                time = "?" if r.evaluation_time_ms is None else f"{r.evaluation_time_ms:g}"
                self._err.write(
                    f"# connection={r.connection} backend={r.backend} type={r.type} "
                    f"plural={r.plural} count={r.count} time={time}ms\n"
                )
        elif r.error is not None:
            self._err.write(f"{format_error(r)}\n")
        self._err.flush()


def format_error(r: SessionRelevanceResult) -> str:
    """The one-line stderr form of a failed result."""
    kind, message = (r.error.kind, r.error.message) if r.error else ("unknown", "")
    return f"{r.connection}: {kind} error: {message}"


# Long enough for a typical error message, short enough that the recap stays
# a recap; the full text is in that result's own section above it.
_SUMMARY_ANSWER_CHARS = 120


def _summary_key(r: SessionRelevanceResult) -> tuple[object, ...]:
    # The answer type counts: 1 as an integer and "1" as a string are the
    # kind of difference worth seeing. Timing, server and backend do not.
    error = (r.error.kind, without_attempts(r.error.message)) if r.error is not None else None
    return (error, r.answer_strings, r.type)


def _summary_answer(r: SessionRelevanceResult) -> str:
    """One line standing for a group's shared answer."""
    if r.error is not None:
        text = f"!! {r.error.kind}: {' '.join(without_attempts(r.error.message).split())}"
    else:
        text = " | ".join(r.answer_strings) or "(no answers)"
    if len(text) > _SUMMARY_ANSWER_CHARS:
        text = text[: _SUMMARY_ANSWER_CHARS - 1] + "…"
    return text


def render_summary(results: Sequence[SessionRelevanceResult]) -> str:
    """Identical answers collapsed, most common first, ties in arrival order.

    Empty when nothing collapses: every group would hold one result and the
    recap would only repeat the sections already printed above it.
    """
    groups: dict[tuple[object, ...], list[SessionRelevanceResult]] = {}
    for r in results:
        groups.setdefault(_summary_key(r), []).append(r)
    if len(groups) == len(results):
        return ""
    order = sorted(groups.values(), key=lambda members: -len(members))  # stable
    distinct = "answer" if len(groups) == 1 else "answers"
    lines = [f"== summary: {_plural(len(results), 'result')}, {len(groups)} distinct {distinct}"]
    for members in order:
        lines.append(f"{len(members)}× {_summary_answer(members[0])}")
        lines.append("    " + ", ".join(_label(m) for m in members))
    return "".join(f"{line}\n" for line in lines)


def _label(r: SessionRelevanceResult) -> str:
    return f"{r.connection} ({r.backend})"


def _plural(count: int, noun: str) -> str:
    return f"{count} {noun}" if count == 1 else f"{count} {noun}s"


def _unreachable(r: SessionRelevanceResult) -> bool:
    return r.error is not None and r.error.kind in UNREACHABLE_KINDS


def exit_code(results: SessionRelevanceResults) -> int:
    if not results:
        return EXIT_USAGE
    if any(r.error is not None and r.error.kind == "relevance" for r in results):
        return EXIT_RELEVANCE_ERROR
    if all(r.ok for r in results):
        return EXIT_OK
    if not any(r.ok for r in results):
        return EXIT_NOTHING_REACHABLE
    return EXIT_PARTIAL
