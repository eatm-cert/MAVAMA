"""Tests for ``modules.recon.dc_finder``."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

import modules.recon.dc_finder as dcf
from modules.recon.dc_finder import DCFinder


@pytest.fixture
def host_with_ldap(tm):
    host = tm.add_host("192.168.56.10")
    host.add_service(port=389, name="ldap")
    host.add_service(port=445, name="smb")
    return host


# ---------------------------------------------------------------------
# ldap_rootdse domain selection (regression: DNS application partitions
# must never be mistaken for the DC's own domain, which produced a bogus
# realm and broke Kerberos user enum with KDC_ERR_WRONG_REALM).
# ---------------------------------------------------------------------

class _FakeInfo:
    def __init__(self, naming_contexts, other):
        self.naming_contexts = naming_contexts
        self.other = other


def _patch_ldap(monkeypatch, naming_contexts, other):
    monkeypatch.setattr(dcf, "_HAS_LDAP3", True)
    monkeypatch.setattr(
        dcf, "Server",
        lambda *a, **k: MagicMock(info=_FakeInfo(naming_contexts, other)),
    )

    class _FakeConn:
        def __init__(self, *a, **k):
            pass

        def unbind(self):
            pass

    monkeypatch.setattr(dcf, "Connection", _FakeConn)


def test_rootdse_prefers_default_naming_context(tm, monkeypatch):
    """defaultNamingContext wins even when a DNS partition is listed first."""
    _patch_ldap(
        monkeypatch,
        naming_contexts=[
            "DC=ForestDnsZones,DC=north,DC=sevenkingdoms,DC=local",
            "DC=DomainDnsZones,DC=north,DC=sevenkingdoms,DC=local",
            "DC=north,DC=sevenkingdoms,DC=local",
            "CN=Configuration,DC=sevenkingdoms,DC=local",
        ],
        other={"defaultNamingContext": ["DC=north,DC=sevenkingdoms,DC=local"]},
    )
    data = DCFinder(tm).ldap_rootdse("192.168.56.11")
    assert data["domain"] == "north.sevenkingdoms.local"


def test_rootdse_skips_dnszones_when_no_default_nc(tm, monkeypatch):
    """No defaultNamingContext -> fall back to the first real domain NC,
    never a ForestDnsZones/DomainDnsZones application partition."""
    _patch_ldap(
        monkeypatch,
        naming_contexts=[
            "DC=ForestDnsZones,DC=north,DC=sevenkingdoms,DC=local",
            "DC=north,DC=sevenkingdoms,DC=local",
        ],
        other={},
    )
    data = DCFinder(tm).ldap_rootdse("192.168.56.11")
    assert data["domain"] == "north.sevenkingdoms.local"


# ---------------------------------------------------------------------
# identify_dc_by_ldap
# ---------------------------------------------------------------------

def test_identify_dc_by_ldap_tags_host(tm, host_with_ldap):
    dcf = DCFinder(tm=tm)
    fake = {
        "domain": "sevenkingdoms.local",
        "naming_contexts": ["DC=sevenkingdoms,DC=local"],
        "dns_host": "dc01.sevenkingdoms.local",
    }
    with patch.object(DCFinder, "ldap_rootdse", return_value=fake):
        ok = dcf.identify_dc_by_ldap("192.168.56.10")
    assert ok is True
    h = tm.get_host("192.168.56.10")
    assert h.is_dc is True
    assert h.domain == "sevenkingdoms.local"
    assert h.hostname == "dc01.sevenkingdoms.local"
    assert "dc" in h.tags
    # Domain must be registered and finder must remember it for later SRV.
    assert "sevenkingdoms.local" in tm.domains
    assert dcf.domain == "sevenkingdoms.local"


def test_identify_dc_by_ldap_skipped_when_no_ldap_port(tm):
    tm.add_host("10.0.0.99")    # no port 389/636
    dcf = DCFinder(tm=tm)
    assert dcf.identify_dc_by_ldap("10.0.0.99") is False


def test_identify_dc_by_ldap_handles_none(tm, host_with_ldap):
    dcf = DCFinder(tm=tm)
    with patch.object(DCFinder, "ldap_rootdse", return_value=None):
        assert dcf.identify_dc_by_ldap("192.168.56.10") is False


# ---------------------------------------------------------------------
# netbios_lookup
# ---------------------------------------------------------------------

NMBLOOKUP_DC_OUTPUT = """\
Looking up status of 192.168.56.10
        DC01            <00> -         B <ACTIVE>
        SEVENKINGDOMS   <00> - <GROUP> B <ACTIVE>
        SEVENKINGDOMS   <1C> - <GROUP> B <ACTIVE>
        DC01            <20> -         B <ACTIVE>
        SEVENKINGDOMS   <1B> -         B <ACTIVE>

        MAC Address = 08-00-27-aa-bb-cc
"""


def test_netbios_lookup_detects_dc(tm, host_with_ldap):
    dcf = DCFinder(tm=tm)
    with patch("modules.recon.dc_finder.shutil.which", return_value="/usr/bin/nmblookup"), \
         patch("modules.recon.dc_finder.subprocess.run") as run:
        run.return_value = MagicMock(stdout=NMBLOOKUP_DC_OUTPUT, returncode=0)
        assert dcf.netbios_lookup("192.168.56.10") is True
    h = tm.get_host("192.168.56.10")
    assert h.is_dc is True
    assert h.domain == "sevenkingdoms"   # NetBIOS short name
    assert "dc" in h.tags


def test_netbios_lookup_no_dc_role(tm, host_with_ldap):
    # Output without <1C> entry (regular workstation).
    out = """
        WS01            <00> -         B <ACTIVE>
        WORKGROUP       <00> - <GROUP> B <ACTIVE>
    """
    dcf = DCFinder(tm=tm)
    with patch("modules.recon.dc_finder.shutil.which", return_value="/usr/bin/nmblookup"), \
         patch("modules.recon.dc_finder.subprocess.run") as run:
        run.return_value = MagicMock(stdout=out, returncode=0)
        assert dcf.netbios_lookup("192.168.56.10") is False


def test_netbios_lookup_missing_tool(tm, host_with_ldap):
    dcf = DCFinder(tm=tm)
    with patch("modules.recon.dc_finder.shutil.which", return_value=None):
        assert dcf.netbios_lookup("192.168.56.10") is False


# ---------------------------------------------------------------------
# run() orchestration
# ---------------------------------------------------------------------

def test_run_prefers_ldap_then_netbios(tm):
    # One host with LDAP (confirmed via LDAP), one with only SMB (falls back to NetBIOS).
    h1 = tm.add_host("10.0.0.1")
    h1.add_service(port=389, name="ldap")
    h2 = tm.add_host("10.0.0.2")
    h2.add_service(port=445, name="smb")

    dcf = DCFinder(tm=tm)
    with patch.object(DCFinder, "dns_srv_lookup", return_value=[]), \
         patch.object(DCFinder, "identify_dc_by_ldap", side_effect=lambda ip: ip == "10.0.0.1"), \
         patch.object(DCFinder, "netbios_lookup", side_effect=lambda ip: ip == "10.0.0.2"):
        result = dcf.run()
    assert set(result) == {"10.0.0.1", "10.0.0.2"}
