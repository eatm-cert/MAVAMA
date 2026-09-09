"""Unit tests for ``modules.credentials.dumping``."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

import modules.credentials.dumping as mod
from modules.credentials.dumping import DumpMode, SecretsDumper


def _make(tm, tmp_path, **overrides):
    defaults = dict(
        mode=DumpMode.LOCAL,
        target="192.168.56.20",
        domain="sevenkingdoms.local",
        username="Administrator",
        nthash="aabbccddeeff00112233445566778899",
        loot_dir=str(tmp_path),
        binary="/usr/local/bin/secretsdump.py",
    )
    defaults.update(overrides)
    return SecretsDumper(tm=tm, **defaults)


# ---------------------------------------------------------------------
# Safe mode
# ---------------------------------------------------------------------


def test_safe_mode_blocks_dumping(tm, tmp_path):
    d = _make(tm, tmp_path, safe_mode=True)
    ok, reason = d.check_prerequisites()
    assert not ok
    assert "safe mode" in reason


# ---------------------------------------------------------------------
# Prerequisite gates
# ---------------------------------------------------------------------


def test_local_mode_requires_target_and_creds(tm, tmp_path):
    d = _make(tm, tmp_path, target="", username="", password="", nthash="")
    ok, reason = d.check_prerequisites()
    assert not ok


def test_offline_mode_requires_existing_files(tm, tmp_path):
    d = _make(
        tm, tmp_path,
        mode=DumpMode.NTDS_OFFLINE,
        target="",
        username="",
        nthash="",
        ntds_file=str(tmp_path / "missing.dit"),
        system_hive=str(tmp_path / "missing.hive"),
    )
    ok, reason = d.check_prerequisites()
    assert not ok
    assert "ntds" in reason.lower() or "system" in reason.lower()


def test_offline_mode_passes_with_real_files(tm, tmp_path):
    ntds = tmp_path / "ntds.dit"
    syst = tmp_path / "SYSTEM"
    ntds.write_text("x")
    syst.write_text("x")
    d = _make(
        tm, tmp_path,
        mode=DumpMode.NTDS_OFFLINE,
        target="",
        username="",
        nthash="",
        ntds_file=str(ntds),
        system_hive=str(syst),
    )
    ok, _ = d.check_prerequisites()
    assert ok


# ---------------------------------------------------------------------
# Command builder
# ---------------------------------------------------------------------


def test_build_command_local_mode_pads_lm_for_nt_only(tm, tmp_path):
    d = _make(tm, tmp_path)
    cmd = d.build_command()
    assert cmd[0] == "/usr/local/bin/secretsdump.py"
    # principal@target trailing
    assert any("@192.168.56.20" in c for c in cmd)
    idx = cmd.index("-hashes")
    # Empty-LM hash padded by the wrapper.
    assert cmd[idx + 1].startswith("aad3b435b51404eeaad3b435b51404ee:")


def test_build_command_dcsync_uses_just_dc_ntlm(tm, tmp_path):
    d = _make(tm, tmp_path, mode=DumpMode.DCSYNC, target="192.168.56.10")
    cmd = d.build_command()
    assert "-just-dc-ntlm" in cmd


def test_build_command_offline_uses_local_token(tm, tmp_path):
    ntds = tmp_path / "ntds.dit"
    syst = tmp_path / "SYSTEM"
    ntds.write_text("x")
    syst.write_text("x")
    d = _make(
        tm, tmp_path,
        mode=DumpMode.NTDS_OFFLINE,
        target="", username="", nthash="",
        ntds_file=str(ntds),
        system_hive=str(syst),
    )
    cmd = d.build_command()
    assert "-ntds" in cmd
    assert "-system" in cmd
    # Impacket accepts the positional ``LOCAL`` token anywhere in argv;
    # the wrapper places it after the hive flags and before -outputfile.
    assert "LOCAL" in cmd
    # Sanity: no spurious authentication string was added.
    assert not any("@" in token for token in cmd)


# ---------------------------------------------------------------------
# Output parsing & persistence
# ---------------------------------------------------------------------


def test_parse_secretsdump_extracts_ntds_lines(tm, tmp_path):
    d = _make(tm, tmp_path)
    blob = (
        "[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)\n"
        "Administrator:500:aad3b435b51404eeaad3b435b51404ee:"
        "31d6cfe0d16ae931b73c59d7e0c089c0:::\n"
        "Guest:501:aad3b435b51404eeaad3b435b51404ee:"
        "31d6cfe0d16ae931b73c59d7e0c089c0:::\n"
    )
    creds = d._parse_secretsdump_output(blob)
    assert len(creds) == 2
    assert {c["user"] for c in creds} == {"Administrator", "Guest"}
    assert creds[0]["rid"] == 500


def test_run_persists_credentials_and_emits_finding(tm, tmp_path, monkeypatch):
    blob = (
        "Administrator:500:aad3b435b51404eeaad3b435b51404ee:"
        "31d6cfe0d16ae931b73c59d7e0c089c0:::\n"
    )
    monkeypatch.setattr(
        mod.subprocess, "run",
        lambda *a, **kw: MagicMock(returncode=0, stdout=blob, stderr=""),
    )
    d = _make(tm, tmp_path)
    result = d.run()
    assert result.status == "completed"
    assert len(result.credentials) == 1
    assert any(
        c.source.startswith("secretsdump/") and c.username == "Administrator"
        for c in tm.credentials
    )
    ids = {f.id for f in tm.findings}
    assert any(i.startswith("DUMP-LOCAL-") for i in ids)
