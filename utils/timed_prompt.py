"""Timed yes/no confirmation prompt.

Used for prompts that must not stall an otherwise-automatic run: if the
operator does not answer within the timeout, the prompt resolves to a default
(typically "no") so auto mode keeps going. Linux/TTY oriented (the project's
supported attacker host) — it falls back to the default immediately when stdin
is not an interactive terminal.
"""

from __future__ import annotations

import select
import sys
from typing import TextIO

_YES = {"y", "yes", "o", "oui"}
_NO = {"n", "no", "non"}


def confirm_with_timeout(
    message: str,
    timeout: float = 30.0,
    default: bool = False,
    stream: TextIO | None = None,
) -> bool:
    """Ask a yes/no question, auto-resolving to ``default`` after ``timeout``.

    Returns ``True``/``False``. An empty line uses ``default``; Ctrl+C, EOF, a
    non-interactive stdin, or the timeout elapsing also return ``default``.
    """
    stream = stream or sys.stdin

    # No interactive terminal: do not block, take the default straight away.
    if not hasattr(stream, "isatty") or not stream.isatty():
        return default

    hint = "Y/n" if default else "y/N"
    sys.stdout.write(f"{message} [{hint}] (auto in {int(timeout)}s): ")
    sys.stdout.flush()

    try:
        ready, _, _ = select.select([stream], [], [], timeout)
    except (OSError, ValueError):
        return default

    if not ready:
        sys.stdout.write(f"\n[*] No answer in {int(timeout)}s - "
                         f"continuing with default ({'yes' if default else 'no'}).\n")
        sys.stdout.flush()
        return default

    try:
        line = stream.readline()
    except (KeyboardInterrupt, EOFError, OSError):
        return default

    if not line:  # EOF
        return default
    answer = line.strip().lower()
    if not answer:
        return default
    if answer in _YES:
        return True
    if answer in _NO:
        return False
    # Anything unrecognised: be conservative and take the default.
    return default
