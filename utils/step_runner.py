"""Step-by-step execution controller for phase modules.

Two execution modes are supported:

* ``auto`` - run every step back-to-back without interaction. This is the
  historical behaviour and the only sensible choice for non-interactive runs
  (cron jobs, CI, piped stdin).
* ``step`` - semi-automatic: run a step, show the operator what it found,
  then let them decide whether to continue to the next step, skip it, or stop.
  When the operator stops, they are offered to persist the engagement state to
  a file of their choice (so a long phase can be resumed later).

The controller is phase-agnostic: a phase builds a list of :class:`Step`
objects - each wrapping a callable that performs the work and returns a list
of human-readable summary lines - and hands them to :meth:`StepRunner.run`.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from core.logger import get_logger
from core.target_manager import TargetManager

# A step callable runs the work and returns the lines to show the operator.
SummaryFn = Callable[[], "list[str] | None"]

# Aliases accepted for the step-by-step mode in configuration/CLI.
_STEP_ALIASES = {"step", "steps", "semi", "semi-auto", "semiauto", "interactive", "manual"}


@dataclass
class Step:
    """A single reviewable unit of work inside a phase.

    ``name`` is a short title, ``description`` is a one-liner shown in the
    pause prompt before the step runs (so the operator knows what comes next),
    and ``fn`` performs the work and returns summary lines to display.
    """

    name: str
    description: str
    fn: SummaryFn


def normalize_mode(value: object) -> str:
    """Map a free-form config/CLI value onto ``"step"`` or ``"auto"``."""
    return "step" if str(value).strip().lower() in _STEP_ALIASES else "auto"


class StepRunner:
    """Drive a list of :class:`Step` objects in auto or step-by-step mode."""

    def __init__(self, mode: str, tm: TargetManager, log=None):
        self.mode = normalize_mode(mode)
        self.tm = tm
        self.log = log or get_logger()

    # ------------------------------------------------------------------

    def run(self, steps: list[Step]) -> bool:
        """Execute ``steps``.

        Returns ``True`` when the phase ran to completion (every step was run
        or explicitly skipped) and ``False`` when the operator stopped early.
        In auto mode it always returns ``True``.
        """
        interactive = self._interactive_available()
        if self.mode != "step" or not interactive:
            if self.mode == "step" and not interactive:
                self.log.warn(
                    "Step-by-step mode requested but no interactive terminal "
                    "is available - falling back to auto mode"
                )
            for idx, step in enumerate(steps):
                self._run_one(step, idx, len(steps))
            return True

        import questionary  # noqa: PLC0415 - optional, only needed interactively

        total = len(steps)
        for idx, step in enumerate(steps):
            # The very first step runs immediately; subsequent ones are gated
            # by a pause so the operator can review the previous results first.
            if idx > 0:
                action = self._pause(questionary, step, idx, total)
                if action == "skip":
                    self.log.info(f"Step skipped by operator: {step.name}")
                    continue
                if action == "stop_save":
                    self._save_progress(questionary)
                    self.log.warn("Phase stopped early by operator")
                    return False
                if action == "stop":
                    self.log.warn(
                        "Phase stopped early by operator (state not saved)"
                    )
                    return False
            self._run_one(step, idx, total)
        return True

    # ------------------------------------------------------------------

    def _interactive_available(self) -> bool:
        """True only when we can actually prompt the operator."""
        try:
            if not sys.stdin.isatty():
                return False
        except (ValueError, OSError):
            return False
        try:
            import questionary  # noqa: F401, PLC0415
        except ImportError:
            return False
        return True

    def _run_one(self, step: Step, index: int, total: int) -> None:
        self.log.console.rule(
            f"[bold cyan]Step {index + 1}/{total}: {step.name}[/bold cyan]"
        )
        summary = step.fn() or []
        for line in summary:
            self.log.console.print(f"  [green]>[/green] {line}")
            self.log.info(f"[step:{step.name}] {line}")

    def _pause(self, questionary, next_step: Step, index: int, total: int) -> str:
        self.log.console.print(
            f"\n[bold yellow]Next[/bold yellow] "
            f"([dim]{index + 1}/{total}[/dim]) "
            f"[bold]{next_step.name}[/bold] - {next_step.description}"
        )
        action = questionary.select(
            "What do you want to do?",
            choices=[
                questionary.Choice("Run this step", value="run"),
                questionary.Choice("Skip this step", value="skip"),
                questionary.Choice("Stop here and save progress", value="stop_save"),
                questionary.Choice("Stop here without saving", value="stop"),
            ],
        ).ask()
        # Ctrl+C / ESC returns None: offer to save rather than silently losing
        # whatever was discovered so far.
        return action or "stop_save"

    def _save_progress(self, questionary) -> None:
        do_save = questionary.confirm(
            "Save engagement progress before stopping?", default=True
        ).ask()
        if not do_save:
            return
        default_path = str((self.tm.loot_dir / "state.json"))
        raw = questionary.text(
            "Save state to file (downstream phases read loot/state.json):",
            default=default_path,
        ).ask()
        target = (raw or default_path).strip() or default_path
        try:
            saved = self.tm.save(Path(target))
            self.log.success(f"Progress saved to {saved}")
        except OSError as exc:
            self.log.error(f"Could not save progress to {target}: {exc}")
