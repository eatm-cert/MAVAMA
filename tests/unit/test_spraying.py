"""Unit tests for ``modules.credentials.spraying``."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

import modules.credentials.spraying as mod
from core.target_manager import Credential
from modules.credentials.spraying import PasswordSprayer


def _make(tm, **overrides):
    defaults = dict(
        domain="sevenkingdoms.local",
        targets=["192.168.56.10"],
        passwords=["Password1"],
        users=["jon.snow", "robb.stark"],
        binary="/usr/bin/netexec",
        # Write the materialised user list into the test's throwaway loot dir
        # (the shared ./loot root may be root-owned from a prior sudo run).
        loot_dir=str(tm.loot_dir),
    )
    defaults.update(overrides)
    return PasswordSprayer(tm=tm, **defaults)


# ---------------------------------------------------------------------
# Safe-mode and prerequisite gates
# ---------------------------------------------------------------------


def test_safe_mode_blocks_spraying(tm):
    s = _make(tm, safe_mode=True)
    ok, reason = s.check_prerequisites()
    assert not ok
    assert "safe mode" in reason


def test_no_users_skips(tm):
    s = _make(tm, users=[])
    ok, reason = s.check_prerequisites()
    assert not ok
    assert "users" in reason


def test_no_passwords_skips(tm):
    s = _make(tm, passwords=[])
    ok, reason = s.check_prerequisites()
    assert not ok
    assert "passwords" in reason


# ---------------------------------------------------------------------
# Lockout-aware throttling
# ---------------------------------------------------------------------


def test_effective_cap_uses_default_threshold(tm):
    s = _make(tm)
    # default threshold 5 - safety_margin 2 = 3
    assert s.effective_cap() == 3


def test_effective_cap_respects_explicit_threshold(tm):
    s = _make(tm, lockout_threshold=10, safety_margin=3)
    assert s.effective_cap() == 7


def test_effective_cap_floor_when_threshold_too_low(tm):
    s = _make(tm, lockout_threshold=2, safety_margin=5)
    assert s.effective_cap() == 1


def test_effective_cap_disabled_lockout_unlimited(tm):
    s = _make(tm, lockout_threshold=0, passwords=["a", "b", "c", "d"])
    assert s.effective_cap() == 4


# ---------------------------------------------------------------------
# Command builder
# ---------------------------------------------------------------------


def test_build_command_uses_userlist_and_single_password(tm, tmp_path, monkeypatch):
    s = _make(tm)
    cmd = s.build_command("192.168.56.10", "Password1")
    assert cmd[0] == "/usr/bin/netexec"
    assert cmd[1] == "smb"
    assert "192.168.56.10" in cmd
    assert "-u" in cmd and "-p" in cmd
    # Single password argument; no list expansion.
    assert cmd[cmd.index("-p") + 1] == "Password1"
    assert "--continue-on-success" in cmd
    assert "--no-bruteforce" in cmd


# ---------------------------------------------------------------------
# Output parsing & persistence
# ---------------------------------------------------------------------


def test_probe_lockout_skips_roast_blob(tm, monkeypatch):
    """The policy probe must not pick a roast-blob credential: its $krb5 blob
    cannot bind and must never be passed to ``-H``. With only a blob in state
    the probe returns None without spawning nxc."""
    tm.add_credential(Credential(
        username="svc", domain="d",
        nt_hash="$krb5tgs$23$*svc$D$abcdef", source="kerberoast",
    ))
    called: list = []
    monkeypatch.setattr(
        mod.subprocess, "run",
        lambda *a, **k: called.append(a) or MagicMock(returncode=0, stdout="", stderr=""),
    )
    s = _make(tm)
    assert s.probe_lockout_threshold() is None
    assert called == []   # no nxc call fired with a blob in -H


def test_parse_success_lines_extracts_user_password_admin(tm):
    s = _make(tm)
    blob = (
        "SMB  192.168.56.10  445  DC01  [-] sevenkingdoms.local\\jon.snow:Password1 STATUS_LOGON_FAILURE\n"
        "SMB  192.168.56.10  445  DC01  [+] sevenkingdoms.local\\eddard.stark:Password1\n"
        "SMB  192.168.56.10  445  DC01  [+] sevenkingdoms.local\\admin:Password1 (Pwn3d!)\n"
    )
    hits = s._parse_success_lines(blob)
    assert len(hits) == 2
    assert {h["user"] for h in hits} == {"eddard.stark", "admin"}
    pwn = next(h for h in hits if h["user"] == "admin")
    assert "Pwn3d" in pwn["flag"]


def test_run_persists_credentials_and_findings(tm, monkeypatch):
    canned = (
        "SMB 192.168.56.10 445 DC01 [+] sevenkingdoms.local\\eddard.stark:Pwd1\n"
        "SMB 192.168.56.10 445 DC01 [+] sevenkingdoms.local\\admin:Pwd1 (Pwn3d!)\n"
    )
    monkeypatch.setattr(
        mod.subprocess, "run",
        lambda *a, **kw: MagicMock(returncode=0, stdout=canned, stderr=""),
    )
    s = _make(tm, probe_password_policy=False)
    result = s.run()
    assert result.status == "completed"
    assert len(result.valid) == 2
    # Persisted as Credential entries.
    sprayed = [c for c in tm.credentials if c.source == "spray"]
    assert {c.username for c in sprayed} == {"eddard.stark", "admin"}
    # Admin hit gets the critical-severity finding.
    severities = {f.severity for f in tm.findings if f.id.startswith("SPRAY-HIT-")}
    assert "critical" in severities


def test_run_caps_password_count_to_threshold(tm, monkeypatch):
    """Regression: more passwords than the lockout cap allows."""
    captured: list[list[str]] = []
    monkeypatch.setattr(
        mod.subprocess, "run",
        lambda cmd, **kw: captured.append(cmd) or MagicMock(
            returncode=0, stdout="", stderr=""
        ),
    )
    s = _make(
        tm,
        passwords=["a", "b", "c", "d", "e", "f"],   # 6 passwords
        lockout_threshold=5,                         # cap = 5 - 2 = 3
        safety_margin=2,
        probe_password_policy=False,
    )
    result = s.run()
    assert result.status == "completed"
    assert result.capped_passwords == 3
    # subprocess.run should be invoked exactly 3 times (1 target * 3 pwds).
    assert len(captured) == 3
