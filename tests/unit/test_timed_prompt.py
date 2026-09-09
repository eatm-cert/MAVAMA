"""Unit tests for ``utils.timed_prompt.confirm_with_timeout``."""

from __future__ import annotations

import io
from unittest.mock import MagicMock

import pytest

from utils import timed_prompt as tp


def _tty_stream(line: str) -> MagicMock:
    s = MagicMock()
    s.isatty.return_value = True
    s.readline.return_value = line
    return s


def test_non_tty_returns_default_immediately():
    # A non-interactive stream must not block; it takes the default.
    assert tp.confirm_with_timeout("x?", 5, default=False, stream=io.StringIO()) is False
    assert tp.confirm_with_timeout("x?", 5, default=True, stream=io.StringIO()) is True


def test_timeout_returns_default(monkeypatch):
    # select reports "nothing ready" -> the timeout path returns the default.
    monkeypatch.setattr(tp.select, "select", lambda r, w, x, t: ([], [], []))
    s = _tty_stream("ignored\n")
    assert tp.confirm_with_timeout("x?", 1, default=False, stream=s) is False
    assert tp.confirm_with_timeout("x?", 1, default=True, stream=s) is True
    s.readline.assert_not_called()  # never read, since nothing was ready


@pytest.mark.parametrize(
    "line,default,expected",
    [
        ("y\n", False, True),
        ("yes\n", False, True),
        ("o\n", False, True),       # French "oui"
        ("n\n", True, False),
        ("no\n", True, False),
        ("non\n", True, False),
        ("\n", False, False),       # empty -> default
        ("\n", True, True),
        ("garbage\n", False, False),  # unrecognised -> conservative default
        ("", False, False),         # EOF -> default
    ],
)
def test_answer_parsing(monkeypatch, line, default, expected):
    # select reports the stream as ready -> the answer is read and parsed.
    monkeypatch.setattr(tp.select, "select", lambda r, w, x, t: ([object()], [], []))
    s = _tty_stream(line)
    assert tp.confirm_with_timeout("x?", 1, default=default, stream=s) is expected
