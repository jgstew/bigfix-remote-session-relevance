"""`Prompt`: how the library asks the user for a password or a TOTP code.

A prompt may answer at once (a terminal's ``getpass``) or return an awaitable
(a GUI dialog on the event loop: NiceGUI, Toga, a SwiftUI host through a
bridge), as `TrustCallback` already may. None, or an empty answer, declines:
nothing is sent. Whatever the prompt raises (a cancelled dialog) propagates.
"""

from __future__ import annotations

import inspect
from collections.abc import Awaitable, Callable

Prompt = Callable[[str], str | Awaitable[str | None] | None]
"""Ask the user. Return the answer, or None to decline (nothing is sent)."""


async def ask(prompt: Prompt | None, message: str) -> str | None:
    """Call a sync or async prompt; None when there's no prompt or it declined."""
    if prompt is None:
        return None
    answer = prompt(message)
    if inspect.isawaitable(answer):
        answer = await answer
    return answer


def answer_now(prompt: Prompt, message: str, *, use: str) -> str | None:
    """Call a prompt where nothing can be awaited; an async prompt is refused.

    The awaitable is closed first, so it never warns "never awaited".
    """
    answer = prompt(message)
    if inspect.isawaitable(answer):
        close = getattr(answer, "close", None)
        if callable(close):
            close()
        raise TypeError(f"an async prompt needs {use}")
    return answer


__all__ = ["Prompt", "answer_now", "ask"]
