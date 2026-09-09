"""Unit tests for ``utils.tool_preflight`` (prune-then-verify tool check)."""

from __future__ import annotations

import sys
from unittest.mock import MagicMock

from utils import tool_preflight as tp


# ---------------------------------------------------------------------------
# verify_tools
# ---------------------------------------------------------------------------

def _fake_which(present: dict[str, str]):
    """Return a shutil.which stand-in resolving only the given candidates."""
    return lambda cand: present.get(cand)


def test_verify_tools_reports_present_missing_and_disabled(monkeypatch, tmp_path):
    # Neutralise _resolve's venv/home/pipx filesystem search so only the mocked
    # which() resolves a path - otherwise a real /bin/nmap on the test host is
    # picked up and the assertion on the resolved path becomes host-dependent.
    monkeypatch.setattr("sys.executable", str(tmp_path / "python"))
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.delenv("SUDO_USER", raising=False)
    monkeypatch.setenv("PIPX_BIN_DIR", str(tmp_path / "pipx"))
    monkeypatch.setattr(tp.shutil, "which", _fake_which({"nmap": "/usr/bin/nmap"}))

    statuses = tp.verify_tools(disabled={"secretsdump"})
    by_key = {s.spec.key: s for s in statuses}

    assert by_key["nmap"].present is True
    assert by_key["nmap"].resolved == "/usr/bin/nmap"
    assert by_key["certipy"].present is False          # not on PATH
    assert by_key["secretsdump"].disabled is True      # removed
    assert by_key["secretsdump"].present is False
    # A disabled tool is never probed.
    assert by_key["secretsdump"].resolved is None


def test_verify_tools_prefers_first_candidate(monkeypatch, tmp_path):
    # NetExec resolves via the second candidate ("netexec") when "nxc" is absent.
    # Neutralise _resolve's venv/home/pipx filesystem search first, otherwise a
    # real /usr/bin/nxc on the test host is picked up before the mocked which().
    monkeypatch.setattr("sys.executable", str(tmp_path / "python"))
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.delenv("SUDO_USER", raising=False)
    monkeypatch.setenv("PIPX_BIN_DIR", str(tmp_path / "pipx"))
    monkeypatch.setattr(
        tp.shutil, "which", _fake_which({"netexec": "/usr/bin/netexec"})
    )
    statuses = {s.spec.key: s for s in tp.verify_tools()}
    assert statuses["netexec"].resolved == "/usr/bin/netexec"


# ---------------------------------------------------------------------------
# _set_config_path
# ---------------------------------------------------------------------------

def test_set_config_path_creates_nested_keys():
    cfg: dict = {}
    tp._set_config_path(cfg, "section.flag", False)
    assert cfg == {"section": {"flag": False}}


def test_set_config_path_overwrites_non_dict_node():
    cfg = {"section": "oops"}
    tp._set_config_path(cfg, "section.flag", False)
    assert cfg["section"] == {"flag": False}


# ---------------------------------------------------------------------------
# select_disabled_tools
# ---------------------------------------------------------------------------

def test_select_disabled_tools_non_tty_returns_preselected(monkeypatch):
    fake_stdin = MagicMock()
    fake_stdin.isatty.return_value = False
    monkeypatch.setattr(sys, "stdin", fake_stdin)

    result = tp.select_disabled_tools(preselected={"secretsdump"})
    assert result == {"secretsdump"}


def test_select_disabled_tools_interactive(monkeypatch):
    fake_stdin = MagicMock()
    fake_stdin.isatty.return_value = True
    monkeypatch.setattr(sys, "stdin", fake_stdin)

    fake_q = MagicMock(name="questionary")
    fake_q.checkbox.return_value.ask.return_value = ["secretsdump", "certipy"]
    fake_q.Choice.side_effect = lambda *a, **k: (a, k)
    monkeypatch.setitem(sys.modules, "questionary", fake_q)

    result = tp.select_disabled_tools(preselected=set())
    assert result == {"secretsdump", "certipy"}


def test_select_disabled_tools_cancel_keeps_preselected(monkeypatch):
    fake_stdin = MagicMock()
    fake_stdin.isatty.return_value = True
    monkeypatch.setattr(sys, "stdin", fake_stdin)

    fake_q = MagicMock(name="questionary")
    fake_q.checkbox.return_value.ask.return_value = None  # Ctrl+C
    fake_q.Choice.side_effect = lambda *a, **k: (a, k)
    monkeypatch.setitem(sys.modules, "questionary", fake_q)

    result = tp.select_disabled_tools(preselected={"secretsdump"})
    assert result == {"secretsdump"}


# ---------------------------------------------------------------------------
# run_tool_preflight
# ---------------------------------------------------------------------------

def test_run_preflight_non_interactive_normalizes_and_drops_unknown(
    monkeypatch, capsys
):
    monkeypatch.setattr(tp.shutil, "which", _fake_which({}))
    cfg = {
        "tools": {"disabled": ["secretsdump", "bogus-key"]},
    }

    out = tp.run_tool_preflight(cfg, interactive=False)

    # Unknown key dropped, list normalized/sorted; known key retained.
    assert out["tools"]["disabled"] == ["secretsdump"]

    printed = capsys.readouterr().out
    assert "Tool availability check" in printed
    assert "removed by operator" in printed


def test_run_preflight_creates_tools_section_when_absent(monkeypatch, capsys):
    monkeypatch.setattr(tp.shutil, "which", _fake_which({"nmap": "/usr/bin/nmap"}))
    cfg: dict = {}
    out = tp.run_tool_preflight(cfg, interactive=False)
    assert out["tools"]["disabled"] == []
    assert "[+]" in capsys.readouterr().out
