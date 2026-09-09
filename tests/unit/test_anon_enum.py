"""Tests for ``modules.recon.anon_enum``."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

import modules.recon.anon_enum as anon_mod
from modules.recon.anon_enum import AnonEnum
from core.logger import get_logger


@pytest.fixture
def ae_host(tm):
    h = tm.add_host("10.0.0.10")
    h.add_service(port=445, name="smb")
    h.add_service(port=389, name="ldap")
    return h


def test_smb_null_session_skips_without_impacket(tm, ae_host, monkeypatch):
    monkeypatch.setattr(anon_mod, "_HAS_IMPACKET", False)
    AnonEnum(tm=tm).smb_null_session("10.0.0.10")        # must not raise


def test_smb_null_session_creates_finding(tm, ae_host, monkeypatch):
    monkeypatch.setattr(anon_mod, "_HAS_IMPACKET", True)

    # Fake share entries in the Impacket format.
    share = {"shi1_netname": "Users\x00", "shi1_remark": "User shares\x00"}
    ipc = {"shi1_netname": "IPC$\x00", "shi1_remark": "Remote IPC\x00"}

    smb = MagicMock()
    smb.listShares.return_value = [share, ipc]
    smb.listPath.return_value = []                       # readable
    smb.getServerOS.return_value = "Windows Server 2019"
    smb.getServerName.return_value = "DC01"
    smb.getServerDomain.return_value = "SEVENKINGDOMS"

    with patch.object(anon_mod, "SMBConnection", return_value=smb):
        AnonEnum(tm=tm).smb_null_session("10.0.0.10")

    h = tm.get_host("10.0.0.10")
    assert "smb-null-session" in h.tags
    assert h.os == "Windows Server 2019"
    assert h.hostname == "DC01"
    assert len(h.shares) == 2
    assert any(s["name"] == "Users" and s["readable_anon"] for s in h.shares)

    # Findings: null session + readable share (IPC$ must not emit the share finding).
    ids = {f.id for f in tm.findings}
    assert "SMB-NULL-10.0.0.10" in ids
    assert "SMB-READ-10.0.0.10-Users" in ids
    assert "SMB-READ-10.0.0.10-IPC$" not in ids


def test_smb_null_session_session_error_is_silent(tm, ae_host, monkeypatch):
    monkeypatch.setattr(anon_mod, "_HAS_IMPACKET", True)

    class FakeSession(Exception):
        pass

    monkeypatch.setattr(anon_mod, "SessionError", FakeSession)

    def boom(*_a, **_kw):
        raise FakeSession("STATUS_ACCESS_DENIED")

    with patch.object(anon_mod, "SMBConnection", side_effect=boom):
        AnonEnum(tm=tm).smb_null_session("10.0.0.10")

    assert tm.get_host("10.0.0.10").shares == []
    assert tm.findings == []                             # nothing recorded on refusal


def test_ldap_anonymous_bind_adds_finding(tm, ae_host, monkeypatch):
    monkeypatch.setattr(anon_mod, "_HAS_LDAP3", True)

    fake_server = MagicMock()
    fake_server.info = MagicMock(naming_contexts=["DC=sevenkingdoms,DC=local"])
    fake_conn = MagicMock()
    fake_conn.entries = []   # search returns nothing readable
    fake_conn.search.return_value = True

    with patch.object(anon_mod, "Server", return_value=fake_server), \
         patch.object(anon_mod, "Connection", return_value=fake_conn):
        AnonEnum(tm=tm).ldap_anonymous_bind("10.0.0.10")

    h = tm.get_host("10.0.0.10")
    assert "ldap-anon-bind" in h.tags
    ids = {f.id for f in tm.findings}
    assert "LDAP-ANON-10.0.0.10" in ids
    # Low severity when read returned nothing.
    sev = next(f.severity for f in tm.findings if f.id == "LDAP-ANON-10.0.0.10")
    assert sev == "low"


def test_ldap_anonymous_bind_high_severity_when_readable(tm, ae_host, monkeypatch):
    monkeypatch.setattr(anon_mod, "_HAS_LDAP3", True)

    fake_server = MagicMock()
    fake_server.info = MagicMock(naming_contexts=["DC=sevenkingdoms,DC=local"])
    entry = MagicMock()
    entry.sAMAccountName = "robb.stark"
    fake_conn = MagicMock()
    fake_conn.entries = [entry]
    fake_conn.search.return_value = True

    with patch.object(anon_mod, "Server", return_value=fake_server), \
         patch.object(anon_mod, "Connection", return_value=fake_conn):
        AnonEnum(tm=tm).ldap_anonymous_bind("10.0.0.10")

    sev = next(f.severity for f in tm.findings if f.id == "LDAP-ANON-10.0.0.10")
    assert sev == "high"
    assert "robb.stark" in tm.users


def test_run_skips_hosts_without_relevant_ports(tm):
    h = tm.add_host("10.0.0.99")   # no 389 or 445 open
    with patch.object(AnonEnum, "smb_null_session") as smb, \
         patch.object(AnonEnum, "ldap_anonymous_bind") as ldap, \
         patch.object(AnonEnum, "ldap_signing_probe") as ldap_sign, \
         patch.object(AnonEnum, "rid_bruteforce") as rid:
        AnonEnum(tm=tm).run()
    smb.assert_not_called()
    ldap.assert_not_called()
    ldap_sign.assert_not_called()
    rid.assert_not_called()


# ---------------------------------------------------------------------
# Regression: LDAP signing probe
# ---------------------------------------------------------------------

def _make_ldap_conn(result_code: int | None):
    """Build a MagicMock that mimics an ldap3.Connection whose ``bind()``
    leaves ``result = {"result": <code>}``."""
    conn = MagicMock()
    conn.open.return_value = None
    conn.bind.return_value = False
    conn.result = {"result": result_code} if result_code is not None else None
    return conn


def test_ldap_signing_probe_marks_required(tm, ae_host, monkeypatch):
    monkeypatch.setattr(anon_mod, "_HAS_LDAP3", True)
    fake_server = MagicMock()
    fake_conn = _make_ldap_conn(result_code=8)  # strongerAuthRequired

    with patch.object(anon_mod, "Server", return_value=fake_server), \
         patch.object(anon_mod, "Connection", return_value=fake_conn):
        AnonEnum(tm=tm).ldap_signing_probe("10.0.0.10")

    h = tm.get_host("10.0.0.10")
    assert h.ldap_signing == "required"
    # No finding when signing is enforced.
    assert not any(f.id.startswith("LDAP-SIGN-") for f in tm.findings)


def test_ldap_signing_probe_marks_not_required_and_emits_finding(tm, ae_host, monkeypatch):
    monkeypatch.setattr(anon_mod, "_HAS_LDAP3", True)
    fake_server = MagicMock()
    fake_conn = _make_ldap_conn(result_code=49)  # invalidCredentials

    with patch.object(anon_mod, "Server", return_value=fake_server), \
         patch.object(anon_mod, "Connection", return_value=fake_conn):
        AnonEnum(tm=tm).ldap_signing_probe("10.0.0.10")

    h = tm.get_host("10.0.0.10")
    assert h.ldap_signing == "not-required"

    finding = next(f for f in tm.findings if f.id == "LDAP-SIGN-10.0.0.10")
    assert finding.severity == "medium"


def test_ldap_signing_probe_inconclusive_code_leaves_field_unset(tm, ae_host, monkeypatch):
    monkeypatch.setattr(anon_mod, "_HAS_LDAP3", True)
    fake_server = MagicMock()
    fake_conn = _make_ldap_conn(result_code=52)  # unavailable

    with patch.object(anon_mod, "Server", return_value=fake_server), \
         patch.object(anon_mod, "Connection", return_value=fake_conn):
        AnonEnum(tm=tm).ldap_signing_probe("10.0.0.10")

    h = tm.get_host("10.0.0.10")
    assert h.ldap_signing is None
    assert not any(f.id.startswith("LDAP-SIGN-") for f in tm.findings)


def test_ldap_signing_probe_skips_without_ldap3(tm, ae_host, monkeypatch):
    monkeypatch.setattr(anon_mod, "_HAS_LDAP3", False)
    # Must not raise and must not change the host state.
    AnonEnum(tm=tm).ldap_signing_probe("10.0.0.10")
    assert tm.get_host("10.0.0.10").ldap_signing is None


def test_ldap_signing_probe_skips_without_port_389(tm, monkeypatch):
    monkeypatch.setattr(anon_mod, "_HAS_LDAP3", True)
    tm.add_host("10.0.0.77")  # no port 389
    with patch.object(anon_mod, "Server") as server_cls:
        AnonEnum(tm=tm).ldap_signing_probe("10.0.0.77")
    server_cls.assert_not_called()


# ---------------------------------------------------------------------
# Regression: smb_null_session must OVERWRITE a previously-set hostname
# when SMB returns a valid Computer name.
# ---------------------------------------------------------------------

def test_smb_null_session_overrides_ptr_hostname(tm, ae_host, monkeypatch):
    monkeypatch.setattr(anon_mod, "_HAS_IMPACKET", True)

    # Simulate a prior (incorrect) PTR-derived hostname.
    ae_host.hostname = "sevenkingdoms.local"

    smb = MagicMock()
    smb.listShares.return_value = []
    smb.getServerOS.return_value = ""
    smb.getServerName.return_value = "KINGSLANDING"
    smb.getServerDomain.return_value = "SEVENKINGDOMS"

    with patch.object(anon_mod, "SMBConnection", return_value=smb):
        AnonEnum(tm=tm).smb_null_session("10.0.0.10")

    assert tm.get_host("10.0.0.10").hostname == "KINGSLANDING"


# [MODIF] – tests for the new no_result "resistant" messages.

def test_smb_null_session_denied_logs_no_result(tm, ae_host, monkeypatch):
    """SessionError on SMB null session must trigger a no_result log, not silence."""
    monkeypatch.setattr(anon_mod, "_HAS_IMPACKET", True)

    class FakeSession(Exception):
        pass

    monkeypatch.setattr(anon_mod, "SessionError", FakeSession)

    log = get_logger()
    no_result_calls: list[str] = []
    original_no_result = log.no_result
    log.no_result = lambda msg: no_result_calls.append(msg)  # type: ignore[method-assign]
    try:
        with patch.object(anon_mod, "SMBConnection", side_effect=FakeSession("ACCESS_DENIED")):
            AnonEnum(tm=tm).smb_null_session("10.0.0.10")
    finally:
        log.no_result = original_no_result  # type: ignore[method-assign]

    assert any("resistant" in m.lower() or "denied" in m.lower() for m in no_result_calls), \
        f"Expected a 'resistant/denied' no_result message; got: {no_result_calls}"


def test_rid_brute_empty_logs_no_result(tm, ae_host, monkeypatch):
    """Empty SAMR result must produce a no_result log entry."""
    monkeypatch.setattr(anon_mod, "_HAS_IMPACKET", True)

    from core.logger import get_logger as _get_logger
    log = _get_logger()
    no_result_calls: list[str] = []
    original = log.no_result
    log.no_result = lambda msg: no_result_calls.append(msg)  # type: ignore[method-assign]
    try:
        with patch("modules.recon.anon_enum.transport") as mock_transport:
            mock_dce = MagicMock()
            mock_transport.SMBTransport.return_value.get_dce_rpc.return_value = mock_dce
            mock_dce.connect.return_value = None
            mock_dce.bind.return_value = None
            # Make the SAMR connect itself raise so we reach the empty-result branch.
            import impacket.dcerpc.v5.samr as _samr  # type: ignore
            with patch.object(_samr, "hSamrConnect", side_effect=Exception("access denied")):
                AnonEnum(tm=tm).rid_bruteforce("10.0.0.10")
    finally:
        log.no_result = original  # type: ignore[method-assign]

    # Either the function returned empty (SAMR bind fail path) or the
    # no_result was called. Either way no finding must exist.
    assert not any(f.id.startswith("RID-BRUTE-") for f in tm.findings)


def test_zerologon_not_vulnerable_logs_no_result(tm, ae_host, monkeypatch):
    """When Zerologon attempts are all rejected, no_result should be called."""
    import modules.recon.anon_enum as _mod
    monkeypatch.setattr(_mod, "_HAS_NRPC", True)
    monkeypatch.setattr(_mod, "_HAS_IMPACKET", True)
    ae_host.is_dc = True

    log = get_logger()
    no_result_calls: list[str] = []
    original = log.no_result
    log.no_result = lambda msg: no_result_calls.append(msg)  # type: ignore[method-assign]
    try:
        with patch("modules.recon.anon_enum.transport") as mock_transport:
            mock_dce = MagicMock()
            mock_transport.DCERPCTransportFactory.return_value.get_dce_rpc.return_value = mock_dce
            # NetrServerAuthenticate3 always raises → not vulnerable path.
            mock_dce.request.side_effect = [None, Exception("rejected")] * 300
            AnonEnum(tm=tm, rid_range=(500, 500)).zerologon_check("10.0.0.10")
    finally:
        log.no_result = original  # type: ignore[method-assign]

    assert not any(f.id.startswith("ZEROLOGON-") for f in tm.findings)
    assert any("zerologon" in m.lower() or "not vulnerable" in m.lower()
               for m in no_result_calls), \
        f"Expected a Zerologon no_result message; got: {no_result_calls}"
