"""Human-readable output and CLI exit codes.

Answers go to stdout and nothing else does, so output pipes cleanly;
errors, metadata (``-v``) and notices go to stderr.
"""

from __future__ import annotations

from typing import TextIO

from .result import SessionRelevanceResult
from .results import UNREACHABLE_KINDS, SessionRelevanceResults

EXIT_OK = 0
EXIT_RELEVANCE_ERROR = 1
EXIT_NOTHING_REACHABLE = 2
EXIT_PARTIAL = 3
EXIT_USAGE = 64


def render_human(
    results: SessionRelevanceResults, *, out: TextIO, err: TextIO, verbose: int = 0
) -> None:
    any_ok = any(r.ok for r in results)

    def _hidden(r: SessionRelevanceResult) -> bool:
        return r.error is not None and r.error.kind in UNREACHABLE_KINDS and any_ok and not verbose

    shown = [r for r in results if not _hidden(r)]
    hidden = len(results) - len(shown)
    multiple = len(shown) > 1
    for r in shown:
        if r.ok:
            if multiple:
                out.write(f"== {r.connection} ({r.backend}) ==\n")
            out.writelines(f"{line}\n" for line in r.answer_strings)
            if verbose:
                time = "?" if r.evaluation_time_ms is None else f"{r.evaluation_time_ms:g}"
                err.write(
                    f"# connection={r.connection} backend={r.backend} type={r.type} "
                    f"plural={r.plural} count={r.count} time={time}ms\n"
                )
            continue
        if r.error is not None:
            err.write(f"{r.connection}: {r.error.kind} error: {r.error.message}\n")
    if hidden:
        err.write(f"({hidden} unreachable; use -v for details)\n")


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
