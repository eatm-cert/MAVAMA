"""Centralized logger with console (rich) and timestamped file output.

Every action performed by the tool goes through this logger so that the
final report has a complete, auditable timeline."""

from __future__ import annotations

import logging
from datetime import datetime
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.logging import RichHandler
from rich.theme import Theme

_THEME = Theme(
    {
        "info": "cyan",
        "success": "bold green",
        "warn": "yellow",
        "err": "bold red",
        "action": "magenta",
        "target": "bold blue",
    }
)

_console = Console(theme=_THEME)


# Per-severity presentation, shared by the live finding log, the Phase 1
# summary table and the authenticated-recon recap so the terminal mirrors the
# colour coding of the HTML report. Each entry is
# ``(badge_style, marker_colour, glyph)`` — the glyph keeps severities
# distinguishable even when colour is stripped (piped output, no-colour
# terminals). ``badge_style`` is a coloured background (table cells), while
# ``marker_colour`` is a foreground colour for compact inline markers.
_SEVERITY_STYLE: dict[str, tuple[str, str, str]] = {
    "critical": ("bold white on red", "bold red", "[X]"),
    "high":     ("bold white on dark_orange3", "bold dark_orange3", "[!]"),
    "medium":   ("bold black on yellow", "yellow", "[>]"),
    "low":      ("bold white on green4", "green", "[-]"),
    "info":     ("bold white on grey42", "grey62", "[i]"),
}


def severity_badge(severity: str) -> str:
    """Return a rich-markup, colour-coded badge for a finding severity.

    Example: ``severity_badge("high")`` -> ``"[bold white on dark_orange3] [!] HIGH [/]"``.
    Unknown severities fall back to the ``info`` style.
    """
    sev = (severity or "info").lower()
    badge_style, _marker, glyph = _SEVERITY_STYLE.get(sev, _SEVERITY_STYLE["info"])
    return f"[{badge_style}] {glyph} {sev.upper()} [/]"


def severity_marker(severity: str) -> str:
    """Return a compact, foreground-coloured ``glyph SEVERITY`` marker.

    Used inline in single log lines where a full badge would be too heavy.
    """
    sev = (severity or "info").lower()
    _badge, marker_colour, glyph = _SEVERITY_STYLE.get(sev, _SEVERITY_STYLE["info"])
    return f"[{marker_colour}]{glyph} {sev.upper()}[/]"


class AuditLogger:
    """Single application-wide logger.

    Emits simultaneously to the console (via rich) and to an
    ``audit_<timestamp>.log`` file in the configured log directory."""

    _instance: Optional["AuditLogger"] = None

    def __init__(self, log_dir: str = "./logs", level: str = "INFO"):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.log_file = self.log_dir / f"audit_{ts}.log"

        self._logger = logging.getLogger("Mavama")
        self._logger.setLevel(getattr(logging, level.upper(), logging.INFO))
        self._logger.handlers.clear()

        file_handler = logging.FileHandler(self.log_file, encoding="utf-8")
        file_handler.setFormatter(
            logging.Formatter(
                "%(asctime)s [%(levelname)s] %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            )
        )
        self._logger.addHandler(file_handler)

        console_handler = RichHandler(
            console=_console,
            rich_tracebacks=True,
            show_time=True,
            show_path=False,
            markup=True,
        )
        console_handler.setFormatter(logging.Formatter("%(message)s"))
        self._logger.addHandler(console_handler)

        self.console = _console

    @classmethod
    def init(cls, log_dir: str = "./logs", level: str = "INFO") -> "AuditLogger":
        cls._instance = cls(log_dir=log_dir, level=level)
        return cls._instance

    @classmethod
    def get(cls) -> "AuditLogger":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def debug(self, msg: str) -> None:
        self._logger.debug(msg)

    def info(self, msg: str) -> None:
        self._logger.info(msg)

    def warn(self, msg: str) -> None:
        self._logger.warning(msg)

    def error(self, msg: str) -> None:
        self._logger.error(msg)

    def success(self, msg: str) -> None:
        self._logger.info(f"[success][+][/success] {msg}")

    def action(self, msg: str) -> None:
        self._logger.info(f"[action][*][/action] {msg}")

    def finding(self, msg: str) -> None:
        """Notable finding that will be surfaced in the final report."""
        self._logger.info(f"[warn][!][/warn] FINDING: {msg}")

    # [MODIF] – "no vulnerability found" marker: cyan checkmark, distinct from findings.
    def no_result(self, msg: str) -> None:
        """Log a 'no result / system resistant to this test' notice in cyan."""
        self._logger.info(f"[cyan][✓][/cyan] {msg}")

    def banner(self, title: str) -> None:
        _console.rule(f"[bold magenta]{title}[/bold magenta]")


def get_logger() -> AuditLogger:
    return AuditLogger.get()
