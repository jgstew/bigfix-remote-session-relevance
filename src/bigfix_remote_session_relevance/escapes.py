"""The ``%XX`` escapes Web Reports (like the client's qna) puts in answer text.

Web Reports sends ``%`` as ``%25`` and the control characters 0x00-0x1F and
0x7F as ``%xx`` (lowercase hex); everything else, non-ASCII included, is sent
as is. The REST API and Explorer send the text itself. Observed live on
11.0.7 (issue #5).
"""

from __future__ import annotations

import re

_ESCAPE_RE = re.compile(r"%([0-9A-Fa-f]{2})")


def unescape_answer(text: str) -> str:
    """Decode the ``%XX`` escapes Web Reports puts in answer text.

    One pass, so ``a%2541`` is ``a%41``, not ``aA``. A ``%`` not followed by
    two hex digits is left as is. Every escaped character is ASCII, so
    ``chr()`` of the byte is the character.
    """
    return _ESCAPE_RE.sub(lambda m: chr(int(m.group(1), 16)), text)
