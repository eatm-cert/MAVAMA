"""Unit tests for ``modules.credentials.roasting``."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

import modules.credentials.roasting as mod
from modules.credentials.roasting import ASREPRoaster, Kerberoaster


# ---------------------------------------------------------------------
# ASREPRoaster
# ---------------------------------------------------------------------


def _asrep(tm, tmp_path, **overrides):
    defaults = dict(
        domain="sevenkingdoms.local",
        kdc_ip="192.168.56.10",
        loot_dir=str(tmp_path),
        binary="/usr/local/bin/GetNPUsers.py",
    )
    defaults.update(overrides)
    return ASREPRoaster(tm=tm, **defaults)


def test_asreproast_skips_without_users_or_creds(tm, tmp_path):
    r = _asrep(tm, tmp_path)
    ok, reason = r.check_prerequisites()
    assert not ok
    assert "user list" in reason


def test_asreproast_runs_with_discovered_userlist(tm, tmp_path):
    tm.add_user("jon.snow")
    tm.add_user("robb.stark")
    r = _asrep(tm, tmp_path)
    ok, _ = r.check_prerequisites()
    assert ok


def test_asreproast_command_includes_no_pass_when_anonymous(tm, tmp_path):
    tm.add_user("jon.snow")
    r = _asrep(tm, tmp_path)
    users_file = r._materialise_userlist()
    cmd = r.build_command(users_file)
    assert "-no-pass" in cmd
    assert "-dc-ip" in cmd and "192.168.56.10" in cmd
    assert "-usersfile" in cmd
    assert "-format" in cmd and "hashcat" in cmd


def test_asreproast_command_inlines_password_when_authenticated(tm, tmp_path):
    tm.add_user("jon.snow")
    r = _asrep(tm, tmp_path, username="robb.stark", password="winter")
    cmd = r.build_command(r._materialise_userlist())
    assert "-no-pass" not in cmd
    # principal in the form ``DOMAIN/user:pass``
    assert "sevenkingdoms.local/robb.stark:winter" in cmd


def test_asreproast_parses_hashes_from_stdout(tm, tmp_path, monkeypatch):
    monkeypatch.setattr(mod, "_HAS_IMPACKET", False)
    tm.add_user("jon.snow")
    canned = (
        "Impacket v0.11.0\n"
        "$krb5asrep$23$jon.snow@SEVENKINGDOMS.LOCAL:abcd1234$ef5678\n"
    )
    monkeypatch.setattr(
        mod.subprocess, "run",
        lambda *a, **kw: MagicMock(returncode=0, stdout=canned, stderr=""),
    )
    result = _asrep(tm, tmp_path).run()
    assert result.status == "completed"
    assert len(result.hashes) == 1
    assert "jon.snow" in result.users_with_hashes
    # Persisted in TargetManager as a Credential.
    assert any(
        c.source == "asreproast" and c.username == "jon.snow"
        for c in tm.credentials
    )


def test_asreproast_command_uses_anonymous_principal_when_no_creds(tm, tmp_path):
    """Regression: when we have no credential the principal must be
    ``DOMAIN/`` (empty user). A populated username without auth would
    make impacket attempt a bind, prompt for a password, and hang."""
    tm.add_user("jon.snow")
    r = _asrep(tm, tmp_path, username="leftover.user")  # carry-over
    cmd = r.build_command(r._materialise_userlist())
    assert "sevenkingdoms.local/" in cmd
    assert "sevenkingdoms.local/leftover.user" not in cmd
    assert "-no-pass" in cmd


def test_asreproast_command_includes_request_flag(tm, tmp_path):
    """Regression: the ``-request`` flag must be explicit so the LDAP
    fallback path actually sends AS-REQs instead of just listing
    accounts."""
    tm.add_user("jon.snow")
    cmd = _asrep(tm, tmp_path).build_command(
        _asrep(tm, tmp_path)._materialise_userlist()
    )
    assert "-request" in cmd


def test_asreproast_subprocess_uses_devnull_stdin(tm, tmp_path, monkeypatch):
    """Regression for the 120 s timeout: impacket calls getpass on
    missing creds and would block forever waiting for terminal input.
    The wrapper must hand stdin to /dev/null."""
    monkeypatch.setattr(mod, "_HAS_IMPACKET", False)
    tm.add_user("jon.snow")
    captured: dict = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        captured["kwargs"] = kwargs
        return MagicMock(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(mod.subprocess, "run", fake_run)
    _asrep(tm, tmp_path).run()
    assert captured["kwargs"].get("stdin") == mod.subprocess.DEVNULL


def test_asreproast_records_finding_when_hashes_seen(tm, tmp_path, monkeypatch):
    monkeypatch.setattr(mod, "_HAS_IMPACKET", False)
    tm.add_user("jon.snow")
    canned = "$krb5asrep$23$jon.snow@SEVENKINGDOMS.LOCAL:aaaa$bbbb\n"
    monkeypatch.setattr(
        mod.subprocess, "run",
        lambda *a, **kw: MagicMock(returncode=0, stdout=canned, stderr=""),
    )
    _asrep(tm, tmp_path).run()
    ids = {f.id for f in tm.findings}
    assert "ASREPROAST-sevenkingdoms.local" in ids


# ---------------------------------------------------------------------
# ASREPRoaster - native Impacket path
# ---------------------------------------------------------------------


def test_asreproast_native_no_binary_needed(tm, tmp_path, monkeypatch):
    """When Impacket is available, check_prerequisites passes without a binary."""
    monkeypatch.setattr(mod, "_HAS_IMPACKET", True)
    tm.add_user("jon.snow")
    r = ASREPRoaster(
        tm=tm,
        domain="sevenkingdoms.local",
        kdc_ip="192.168.56.10",
        loot_dir=str(tmp_path),
        binary=None,
    )
    ok, reason = r.check_prerequisites()
    assert ok, reason


def test_asreproast_native_captures_hash(tm, tmp_path, monkeypatch):
    """Native path: sendReceive returns AS-REP bytes → hash extracted and persisted."""
    monkeypatch.setattr(mod, "_HAS_IMPACKET", True)
    tm.add_user("jon.snow")

    fake_hash = "$krb5asrep$23$jon.snow@SEVENKINGDOMS.LOCAL:aabb1122$ccdd3344"
    monkeypatch.setattr(mod, "sendReceive", lambda msg, domain, ip: b"fake-reply")
    monkeypatch.setattr(ASREPRoaster, "_build_as_req", lambda self, u: b"fake-req")
    monkeypatch.setattr(ASREPRoaster, "_is_as_rep", lambda self, b: True)
    monkeypatch.setattr(ASREPRoaster, "_format_asrep_hash", lambda self, u, b: fake_hash)

    result = _asrep(tm, tmp_path).run()

    assert result.status == "completed"
    assert result.hashes == [fake_hash]
    assert "jon.snow" in result.users_with_hashes
    assert any(c.source == "asreproast" for c in tm.credentials)
    assert any(f.id == "ASREPROAST-sevenkingdoms.local" for f in tm.findings)


def test_asreproast_native_skips_preauth_required_users(tm, tmp_path, monkeypatch):
    """Native path: users that require pre-auth are not in the hash list."""
    monkeypatch.setattr(mod, "_HAS_IMPACKET", True)
    tm.add_user("robb.stark")

    monkeypatch.setattr(mod, "sendReceive", lambda msg, domain, ip: b"fake-reply")
    monkeypatch.setattr(ASREPRoaster, "_build_as_req", lambda self, u: b"fake-req")
    monkeypatch.setattr(ASREPRoaster, "_is_as_rep", lambda self, b: False)  # pre-auth required

    result = _asrep(tm, tmp_path).run()

    assert result.status == "completed"
    assert result.hashes == []
    assert result.users_with_hashes == []


def test_asreproast_native_skips_unknown_users(tm, tmp_path, monkeypatch):
    """Native path: KDC_ERR_C_PRINCIPAL_UNKNOWN is silently skipped."""
    monkeypatch.setattr(mod, "_HAS_IMPACKET", True)
    tm.add_user("nobody")

    def fake_send(msg, domain, ip):
        err = mod.KerberosError()
        err["error-code"] = mod._krb5_constants.ErrorCodes.KDC_ERR_C_PRINCIPAL_UNKNOWN.value
        raise err

    monkeypatch.setattr(mod, "sendReceive", fake_send)
    monkeypatch.setattr(ASREPRoaster, "_build_as_req", lambda self, u: b"fake-req")

    result = _asrep(tm, tmp_path).run()
    assert result.status == "completed"
    assert result.hashes == []


def test_asreproast_native_no_users_returns_skipped(tm, tmp_path, monkeypatch):
    """Native path: empty user list yields status=skipped."""
    monkeypatch.setattr(mod, "_HAS_IMPACKET", True)
    # tm.users is empty (no add_user calls)
    result = _asrep(tm, tmp_path).run()
    assert result.status == "skipped"


# ---------------------------------------------------------------------
# Kerberoaster
# ---------------------------------------------------------------------


def _kerb(tm, tmp_path, **overrides):
    defaults = dict(
        domain="sevenkingdoms.local",
        kdc_ip="192.168.56.10",
        loot_dir=str(tmp_path),
        username="robb.stark",
        password="winter",
        binary="/usr/local/bin/GetUserSPNs.py",
    )
    defaults.update(overrides)
    return Kerberoaster(tm=tm, **defaults)


def test_kerberoast_requires_credentials(tm, tmp_path):
    k = _kerb(tm, tmp_path, username="", password="", nthash="")
    ok, reason = k.check_prerequisites()
    assert not ok
    assert "username" in reason or "password" in reason


def test_kerberoast_skipped_in_safe_mode(tm, tmp_path):
    k = _kerb(tm, tmp_path, safe_mode=True)
    ok, reason = k.check_prerequisites()
    assert not ok
    assert "safe mode" in reason


def test_kerberoast_command_uses_request_flag(tm, tmp_path):
    cmd = _kerb(tm, tmp_path).build_command()
    assert "-request" in cmd
    assert any("sevenkingdoms.local/robb.stark:winter" in c for c in cmd)
    assert "-dc-ip" in cmd


def test_kerberoast_parses_tgs_hashes(tm, tmp_path, monkeypatch):
    canned = (
        "Impacket\n"
        "$krb5tgs$23$*sql_svc$SEVENKINGDOMS.LOCAL$MSSQLSvc/db.lab*$abc$def\n"
    )
    monkeypatch.setattr(
        mod.subprocess, "run",
        lambda *a, **kw: MagicMock(returncode=0, stdout=canned, stderr=""),
    )
    result = _kerb(tm, tmp_path).run()
    assert result.status == "completed"
    assert len(result.hashes) == 1
    assert result.users_with_hashes == ["sql_svc"]
