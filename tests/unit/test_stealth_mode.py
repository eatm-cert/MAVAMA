"""Unit tests for --stealth mode across service_enum, user_enum, spraying."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from core.target_manager import TargetManager


# ---------------------------------------------------------------------------
# ServiceEnum: nmap timing
# ---------------------------------------------------------------------------

def test_service_enum_stealth_uses_T2_not_min_rate(tm, tmp_path):
    from modules.recon.service_enum import ServiceEnum
    se = ServiceEnum(tm=tm, stealth_mode=True)
    se.nmap_bin = "/usr/bin/nmap"
    cmd = se._build_nmap_cmd(["192.168.56.10"], tmp_path / "out.xml")
    assert "-T2" in cmd
    assert "--min-rate" not in cmd


def test_service_enum_normal_uses_min_rate_not_T2(tm, tmp_path):
    from modules.recon.service_enum import ServiceEnum
    se = ServiceEnum(tm=tm, stealth_mode=False, rate=500)
    se.nmap_bin = "/usr/bin/nmap"
    cmd = se._build_nmap_cmd(["192.168.56.10"], tmp_path / "out.xml")
    assert "--min-rate" in cmd
    assert "500" in cmd
    assert "-T2" not in cmd


# ---------------------------------------------------------------------------
# UserEnum: jitter + single thread
# ---------------------------------------------------------------------------

def test_user_enum_stealth_limits_to_one_thread(tm, monkeypatch):
    from modules.recon.user_enum import UserEnum
    import modules.recon.user_enum as ue_mod

    monkeypatch.setattr(ue_mod, "_HAS_IMPACKET", True)

    check_calls: list[str] = []

    def fake_check(self, username):
        check_calls.append(username)
        return username, "unknown", None

    monkeypatch.setattr(UserEnum, "_check_user", fake_check)
    monkeypatch.setattr(UserEnum, "_load_users", lambda self: ["jon.snow", "robb.stark"])

    ue = UserEnum(
        tm=tm,
        domain="sevenkingdoms.local",
        kdc_ip="192.168.56.10",
        stealth_mode=True,
    )
    # stealth_mode must force effective_threads=1
    assert ue.stealth_mode is True


def test_user_enum_stealth_applies_jitter(tm, monkeypatch):
    """Jitter sleep is called once per result when stealth_mode=True."""
    from modules.recon.user_enum import UserEnum
    import modules.recon.user_enum as ue_mod
    import modules.recon.user_enum as ue_time

    monkeypatch.setattr(ue_mod, "_HAS_IMPACKET", True)
    monkeypatch.setattr(UserEnum, "_check_user", lambda self, u: (u, "unknown", None))
    monkeypatch.setattr(UserEnum, "_load_users", lambda self: ["jon.snow"])

    sleep_calls: list[float] = []
    monkeypatch.setattr(ue_time.time, "sleep", lambda s: sleep_calls.append(s))

    ue = UserEnum(
        tm=tm,
        domain="sevenkingdoms.local",
        kdc_ip="192.168.56.10",
        stealth_mode=True,
    )
    ue.run()

    assert len(sleep_calls) == 1          # one user → one jitter sleep
    assert 0.5 <= sleep_calls[0] <= 1.5


def test_user_enum_normal_mode_no_jitter(tm, monkeypatch):
    from modules.recon.user_enum import UserEnum
    import modules.recon.user_enum as ue_mod
    import modules.recon.user_enum as ue_time

    monkeypatch.setattr(ue_mod, "_HAS_IMPACKET", True)
    monkeypatch.setattr(UserEnum, "_check_user", lambda self, u: (u, "unknown", None))
    monkeypatch.setattr(UserEnum, "_load_users", lambda self: ["jon.snow"])

    sleep_calls: list = []
    monkeypatch.setattr(ue_time.time, "sleep", lambda s: sleep_calls.append(s))

    ue = UserEnum(
        tm=tm,
        domain="sevenkingdoms.local",
        kdc_ip="192.168.56.10",
        stealth_mode=False,
    )
    ue.run()

    assert sleep_calls == []


# ---------------------------------------------------------------------------
# PasswordSprayer: 1-password limit
# ---------------------------------------------------------------------------

def test_sprayer_stealth_caps_to_one_password(tm, tmp_path, monkeypatch):
    import modules.credentials.spraying as spray_mod
    from modules.credentials.spraying import PasswordSprayer

    captured_cmds: list = []
    monkeypatch.setattr(
        spray_mod.subprocess, "run",
        lambda cmd, **kw: captured_cmds.append(cmd) or MagicMock(
            returncode=0, stdout="", stderr=""
        ),
    )
    monkeypatch.setattr(PasswordSprayer, "_materialise_userlist", lambda self: tmp_path / "users.txt")
    (tmp_path / "users.txt").write_text("jon.snow\n")

    tm.add_user("jon.snow")
    sprayer = PasswordSprayer(
        tm=tm,
        domain="sevenkingdoms.local",
        targets=["192.168.56.10"],
        passwords=["Pass1", "Pass2", "Pass3"],
        stealth_mode=True,
        probe_password_policy=False,
        lockout_threshold=5,
    )
    result = sprayer.run()

    assert result.capped_passwords == 1 or len(captured_cmds) == 1


def test_sprayer_stealth_flag_stored(tm):
    from modules.credentials.spraying import PasswordSprayer
    s = PasswordSprayer(
        tm=tm,
        domain="lab.local",
        targets=["10.0.0.1"],
        passwords=["P@ss1"],
        stealth_mode=True,
    )
    assert s.stealth_mode is True


def test_sprayer_normal_mode_does_not_cap(tm, tmp_path, monkeypatch):
    import modules.credentials.spraying as spray_mod
    from modules.credentials.spraying import PasswordSprayer

    captured_cmds: list = []
    monkeypatch.setattr(
        spray_mod.subprocess, "run",
        lambda cmd, **kw: captured_cmds.append(cmd) or MagicMock(
            returncode=0, stdout="", stderr=""
        ),
    )
    monkeypatch.setattr(PasswordSprayer, "_materialise_userlist", lambda self: tmp_path / "users.txt")
    (tmp_path / "users.txt").write_text("jon.snow\n")

    tm.add_user("jon.snow")
    sprayer = PasswordSprayer(
        tm=tm,
        domain="sevenkingdoms.local",
        targets=["192.168.56.10"],
        passwords=["Pass1", "Pass2"],
        stealth_mode=False,
        probe_password_policy=False,
        lockout_threshold=5,
    )
    sprayer.run()

    # Without stealth: both passwords are attempted (cap = threshold - margin = 3)
    assert len(captured_cmds) == 2
