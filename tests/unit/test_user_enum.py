"""Tests for ``modules.recon.user_enum``."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

import modules.recon.user_enum as ue_mod
from modules.recon.user_enum import DEFAULT_USERS, UserEnum


def test_domain_is_uppercased(tm):
    u = UserEnum(tm=tm, domain="sevenkingdoms.local", kdc_ip="192.168.56.10")
    assert u.domain == "SEVENKINGDOMS.LOCAL"


def test_load_users_from_file(tm, tmp_path: Path):
    wl = tmp_path / "users.txt"
    wl.write_text("# header\nalice\nBOB\n\nalice\n# commented\n")
    u = UserEnum(tm=tm, domain="d.local", kdc_ip="1.1.1.1", userlist=wl)
    users = u._load_users()
    # Dedup (case-insensitive) preserves first-seen casing; comments/blank lines skipped.
    assert "alice" in users
    assert "BOB" in users
    assert users.count("alice") == 1


def test_load_users_fallback_when_wordlist_missing(tm, tmp_path: Path):
    u = UserEnum(tm=tm, domain="d.local", kdc_ip="1.1.1.1", userlist=tmp_path / "does_not_exist.txt")
    users = u._load_users()
    assert set(DEFAULT_USERS).issubset(set(users))


def test_load_users_merges_discovered(tm, tmp_path: Path):
    tm.add_user("discovered_user")
    u = UserEnum(tm=tm, domain="d.local", kdc_ip="1.1.1.1", userlist=None)
    users = u._load_users()
    assert "discovered_user" in users


# ---------------------------------------------------------------------
# _check_user status mapping
# ---------------------------------------------------------------------

class _FakeKrbError(Exception):
    def __init__(self, code):
        self._code = code

    def getErrorCode(self):
        return self._code


def _patch_constants(monkeypatch):
    """Ensure _check_user uses predictable error-code constants."""
    # The real constants module exposes .value; we substitute trivial ints.
    class _EC:
        class KDC_ERR_C_PRINCIPAL_UNKNOWN:
            value = 6
        class KDC_ERR_PREAUTH_REQUIRED:
            value = 25
        class KDC_ERR_CLIENT_REVOKED:
            value = 18
    monkeypatch.setattr(ue_mod.constants, "ErrorCodes", _EC)


def test_check_user_valid(tm, monkeypatch):
    _patch_constants(monkeypatch)
    monkeypatch.setattr(ue_mod, "KerberosError", _FakeKrbError)
    u = UserEnum(tm=tm, domain="d.local", kdc_ip="1.1.1.1")
    with patch.object(UserEnum, "_build_as_req", return_value=b"\x00"), \
         patch.object(ue_mod, "sendReceive", side_effect=_FakeKrbError(25)):
        assert u._check_user("alice") == ("alice", "valid", None)


def test_check_user_unknown(tm, monkeypatch):
    _patch_constants(monkeypatch)
    monkeypatch.setattr(ue_mod, "KerberosError", _FakeKrbError)
    u = UserEnum(tm=tm, domain="d.local", kdc_ip="1.1.1.1")
    with patch.object(UserEnum, "_build_as_req", return_value=b"\x00"), \
         patch.object(ue_mod, "sendReceive", side_effect=_FakeKrbError(6)):
        assert u._check_user("ghost") == ("ghost", "unknown", None)


def test_check_user_disabled(tm, monkeypatch):
    _patch_constants(monkeypatch)
    monkeypatch.setattr(ue_mod, "KerberosError", _FakeKrbError)
    u = UserEnum(tm=tm, domain="d.local", kdc_ip="1.1.1.1")
    with patch.object(UserEnum, "_build_as_req", return_value=b"\x00"), \
         patch.object(ue_mod, "sendReceive", side_effect=_FakeKrbError(18)):
        assert u._check_user("revoked")[1] == "disabled"


def test_check_user_asreproastable(tm, monkeypatch):
    """Reply bytes decode as AS-REP → user flagged ASREProastable and hash
    captured."""
    _patch_constants(monkeypatch)
    monkeypatch.setattr(ue_mod, "KerberosError", _FakeKrbError)
    u = UserEnum(tm=tm, domain="d.local", kdc_ip="1.1.1.1")
    with patch.object(UserEnum, "_build_as_req", return_value=b"\x00"), \
         patch.object(ue_mod, "sendReceive", return_value=b"\x01"), \
         patch.object(UserEnum, "_is_as_rep", return_value=True), \
         patch.object(UserEnum, "_format_asrep_hash",
                      return_value="$krb5asrep$23$preauthless@D.LOCAL:aa$bb"):
        username, status, detail = u._check_user("preauthless")
    assert status == "asreproastable"
    assert detail.startswith("$krb5asrep$23$preauthless@")


def test_check_user_valid_when_reply_is_krb_error_preauth(tm, monkeypatch):
    """impacket.sendReceive returns raw bytes for KRB-ERROR/PREAUTH_REQUIRED
    too. Those bytes do NOT decode as AS-REP → user must be flagged 'valid',
    never 'asreproastable'. This guards against a real regression where
    every valid user was mis-tagged as ASREProastable."""
    _patch_constants(monkeypatch)
    monkeypatch.setattr(ue_mod, "KerberosError", _FakeKrbError)
    u = UserEnum(tm=tm, domain="d.local", kdc_ip="1.1.1.1")
    with patch.object(UserEnum, "_build_as_req", return_value=b"\x00"), \
         patch.object(ue_mod, "sendReceive", return_value=b"\x7e\x00"), \
         patch.object(UserEnum, "_is_as_rep", return_value=False):
        username, status, detail = u._check_user("normal_user")
    assert status == "valid"
    assert detail is None


# ---------------------------------------------------------------------
# Regression: AS-REP response is decoded into a $krb5asrep$ hash.
# ---------------------------------------------------------------------

def _fake_as_rep_rc4() -> bytes:
    """Build a minimal AS_REP whose enc-part has etype=23 and a known cipher."""
    from impacket.krb5.asn1 import AS_REP
    from impacket.krb5 import constants as krb_constants
    from pyasn1.codec.der import encoder as der_encoder

    # 40-byte RC4 ciphertext so the hashcat format is non-trivially split.
    cipher = bytes(range(40))

    as_rep = AS_REP()
    as_rep["pvno"] = 5
    as_rep["msg-type"] = int(krb_constants.ApplicationTagNumbers.AS_REP.value)
    # crealm / cname / ticket are mandatory in the ASN.1 structure;
    # populate the bare minimum that impacket's decoder will accept.
    as_rep["crealm"] = "D.LOCAL"
    as_rep["cname"]["name-type"] = 1
    as_rep["cname"]["name-string"][0] = "alice"
    as_rep["ticket"]["tkt-vno"] = 5
    as_rep["ticket"]["realm"] = "D.LOCAL"
    as_rep["ticket"]["sname"]["name-type"] = 2
    as_rep["ticket"]["sname"]["name-string"][0] = "krbtgt"
    as_rep["ticket"]["sname"]["name-string"][1] = "D.LOCAL"
    as_rep["ticket"]["enc-part"]["etype"] = 23
    as_rep["ticket"]["enc-part"]["cipher"] = b"\x00"
    as_rep["enc-part"]["etype"] = 23
    as_rep["enc-part"]["cipher"] = cipher
    return der_encoder.encode(as_rep)


def test_format_asrep_hash_rc4(tm):
    as_rep_bytes = _fake_as_rep_rc4()
    u = UserEnum(tm=tm, domain="d.local", kdc_ip="1.1.1.1")
    hashval = u._format_asrep_hash("alice", as_rep_bytes)

    cipher_hex = bytes(range(40)).hex()
    expected = (
        f"$krb5asrep$23$alice@D.LOCAL:"
        f"{cipher_hex[:32]}${cipher_hex[32:]}"
    )
    assert hashval == expected


def test_format_asrep_hash_handles_garbage(tm):
    u = UserEnum(tm=tm, domain="d.local", kdc_ip="1.1.1.1")
    assert u._format_asrep_hash("alice", b"\xde\xad\xbe\xef") is None


def test_run_stores_asrep_hash_in_credential(tm, monkeypatch):
    """When user enum returns an ASREProastable, the Credential stored in
    TargetManager must carry the ``$krb5asrep$`` hash in its ``ticket``.
    """
    _patch_constants(monkeypatch)
    monkeypatch.setattr(ue_mod, "KerberosError", _FakeKrbError)
    monkeypatch.setattr(ue_mod, "_HAS_IMPACKET", True)

    hash_str = "$krb5asrep$23$preauthless@D.LOCAL:deadbeef$cafebabe"

    def fake_check(self, username):
        if username == "preauthless":
            return (username, "asreproastable", hash_str)
        return (username, "unknown", None)

    monkeypatch.setattr(UserEnum, "_check_user", fake_check)
    monkeypatch.setattr(UserEnum, "_load_users", lambda self: ["preauthless"])

    u = UserEnum(tm=tm, domain="d.local", kdc_ip="1.1.1.1", threads=1)
    u.run()

    creds = [c for c in tm.credentials if c.username == "preauthless"]
    assert creds, "credential must be stored for ASREProastable user"
    assert creds[0].ticket == hash_str
    assert creds[0].source == "as-rep-roast-candidate"

    finding = next(f for f in tm.findings if f.id == "ASREP-preauthless")
    assert hash_str[:80] in finding.evidence or finding.evidence == hash_str
    # The finding carries a copyable GetNPUsers command (domain uppercased).
    assert finding.command == (
        "GetNPUsers.py D.LOCAL/preauthless -no-pass -dc-ip 1.1.1.1 -format hashcat"
    )


# ---------------------------------------------------------------------
# run() wiring
# ---------------------------------------------------------------------

def test_run_populates_findings_and_creds(tm, monkeypatch):
    _patch_constants(monkeypatch)
    monkeypatch.setattr(ue_mod, "KerberosError", _FakeKrbError)
    monkeypatch.setattr(ue_mod, "_HAS_IMPACKET", True)

    def fake_check(self, username):
        mapping = {
            "alice": ("alice", "valid", None),
            "asrep_user": ("asrep_user", "asreproastable", None),
            "ghost": ("ghost", "unknown", None),
            "revoked": ("revoked", "disabled", None),
        }
        return mapping.get(username, (username, "unknown", None))

    monkeypatch.setattr(UserEnum, "_check_user", fake_check)
    monkeypatch.setattr(UserEnum, "_load_users",
                        lambda self: ["alice", "asrep_user", "ghost", "revoked"])

    u = UserEnum(tm=tm, domain="d.local", kdc_ip="1.1.1.1", threads=2)
    result = u.run()

    assert "alice" in result["valid"]
    assert "asrep_user" in result["asreproastable"]
    assert "revoked" in result["disabled"]
    assert "alice" in tm.users and "asrep_user" in tm.users
    assert any(f.id == "ASREP-asrep_user" for f in tm.findings)
    assert any(c.username == "asrep_user" for c in tm.credentials)


def test_run_noop_without_impacket(tm, monkeypatch):
    monkeypatch.setattr(ue_mod, "_HAS_IMPACKET", False)
    u = UserEnum(tm=tm, domain="d.local", kdc_ip="1.1.1.1")
    assert u.run() == {}
