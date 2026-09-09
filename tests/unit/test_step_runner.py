"""Unit tests for ``utils.step_runner``.

The runner is phase-agnostic, so these tests exercise it with synthetic
steps and a mocked ``questionary`` module rather than a real recon phase.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from utils.step_runner import Step, StepRunner, normalize_mode


# ---------------------------------------------------------------------------
# normalize_mode
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "value,expected",
    [
        ("auto", "auto"),
        ("AUTO", "auto"),
        ("", "auto"),
        (None, "auto"),
        ("whatever", "auto"),
        ("step", "step"),
        ("Step-by-step".lower(), "auto"),  # exact tokens only
        ("semi-auto", "step"),
        ("interactive", "step"),
        ("manual", "step"),
    ],
)
def test_normalize_mode(value, expected):
    assert normalize_mode(value) == expected


# ---------------------------------------------------------------------------
# auto mode / non-interactive fallback
# ---------------------------------------------------------------------------

def _counting_step(name: str, calls: list[str]) -> Step:
    def _fn():
        calls.append(name)
        return [f"{name} done"]
    return Step(name, f"run {name}", _fn)


def test_auto_mode_runs_every_step(tm):
    calls: list[str] = []
    steps = [_counting_step(n, calls) for n in ("a", "b", "c")]
    runner = StepRunner(mode="auto", tm=tm)

    assert runner.run(steps) is True
    assert calls == ["a", "b", "c"]


def test_step_mode_without_tty_falls_back_to_auto(tm, monkeypatch):
    # No interactive terminal -> step mode degrades to auto, all steps run.
    fake_stdin = MagicMock()
    fake_stdin.isatty.return_value = False
    monkeypatch.setattr("sys.stdin", fake_stdin)

    calls: list[str] = []
    steps = [_counting_step(n, calls) for n in ("a", "b")]
    runner = StepRunner(mode="step", tm=tm)

    assert runner.run(steps) is True
    assert calls == ["a", "b"]


# ---------------------------------------------------------------------------
# interactive step mode
# ---------------------------------------------------------------------------

def _install_fake_questionary(monkeypatch, *, select_actions, confirm=True, text=None):
    """Inject a fake ``questionary`` module driving the runner's prompts."""
    fake = MagicMock(name="questionary")
    fake.select.return_value.ask.side_effect = list(select_actions)
    fake.confirm.return_value.ask.return_value = confirm
    fake.text.return_value.ask.return_value = text
    fake.Choice.side_effect = lambda *a, **k: (a, k)
    monkeypatch.setitem(__import__("sys").modules, "questionary", fake)

    fake_stdin = MagicMock()
    fake_stdin.isatty.return_value = True
    monkeypatch.setattr("sys.stdin", fake_stdin)
    return fake


def test_step_mode_skip_then_stop_without_save(tm, monkeypatch):
    _install_fake_questionary(monkeypatch, select_actions=["skip", "stop"])

    calls: list[str] = []
    steps = [_counting_step(n, calls) for n in ("a", "b", "c")]
    runner = StepRunner(mode="step", tm=tm)
    runner.tm = MagicMock(wraps=tm)  # spy on save()

    completed = runner.run(steps)

    assert completed is False
    # first step always runs; second is skipped; third is gated by "stop"
    assert calls == ["a"]
    runner.tm.save.assert_not_called()


def test_step_mode_stop_and_save_uses_chosen_path(tm, tmp_path, monkeypatch):
    save_target = tmp_path / "my_progress.json"
    _install_fake_questionary(
        monkeypatch,
        select_actions=["stop_save"],
        confirm=True,
        text=str(save_target),
    )

    calls: list[str] = []
    steps = [_counting_step(n, calls) for n in ("a", "b")]
    runner = StepRunner(mode="step", tm=tm)

    completed = runner.run(steps)

    assert completed is False
    assert calls == ["a"]              # stopped before the second step
    assert save_target.is_file()        # progress persisted to the chosen path


def test_step_mode_run_all_steps_completes(tm, monkeypatch):
    _install_fake_questionary(monkeypatch, select_actions=["run", "run"])

    calls: list[str] = []
    steps = [_counting_step(n, calls) for n in ("a", "b", "c")]
    runner = StepRunner(mode="step", tm=tm)

    assert runner.run(steps) is True
    assert calls == ["a", "b", "c"]
