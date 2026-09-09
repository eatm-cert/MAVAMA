"""Tests for ``modules.recon.service_enum``."""

from __future__ import annotations

import urllib.error
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from modules.recon.service_enum import ServiceEnum


# ---------------------------------------------------------------------
# ADCS web ports are always scanned (ESC8 needs the CA HTTP endpoint), and
# ADCS is detected reliably by probing /certsrv rather than the IIS root.
# ---------------------------------------------------------------------

def test_adcs_web_ports_always_scanned_even_if_config_omits_them(tm):
    # A config port list without 80/443 (the exact list that broke ESC8).
    se = ServiceEnum(tm=tm, ports=[135, 389, 445, 8080, 8443])
    assert 80 in se.ports
    assert 443 in se.ports


def test_probe_adcs_web_true_on_401_ntlm():
    err = urllib.error.HTTPError(
        "http://x/certsrv/certfnsh.asp", 401, "Unauthorized",
        {"WWW-Authenticate": "Negotiate"}, None,
    )
    with patch("urllib.request.urlopen", side_effect=err):
        assert ServiceEnum._probe_adcs_web("10.0.0.23", 80) is True


def test_probe_adcs_web_false_on_plain_iis():
    err = urllib.error.HTTPError(
        "http://x/certsrv/certfnsh.asp", 404, "Not Found", {}, None,
    )
    with patch("urllib.request.urlopen", side_effect=err):
        assert ServiceEnum._probe_adcs_web("10.0.0.50", 80) is False


def test_probe_adcs_web_true_on_200_body():
    resp = MagicMock()
    resp.read.return_value = b"<title>Microsoft Active Directory Certificate Services</title>"
    with patch("urllib.request.urlopen", return_value=resp):
        assert ServiceEnum._probe_adcs_web("10.0.0.23", 443) is True


def test_detect_adcs_web_marks_host_with_certsrv(tm):
    host = tm.add_host("10.0.0.23")
    host.add_service(port=80, name="http")
    se = ServiceEnum(tm=tm)
    with patch.object(ServiceEnum, "_probe_adcs_web", return_value=True):
        se._detect_adcs_web()
    assert host.is_adcs is True


def test_detect_adcs_web_ignores_non_ca_http(tm):
    host = tm.add_host("10.0.0.50")
    host.add_service(port=80, name="http")
    se = ServiceEnum(tm=tm)
    with patch.object(ServiceEnum, "_probe_adcs_web", return_value=False):
        se._detect_adcs_web()
    assert host.is_adcs is False


# ---------------------------------------------------------------------
# Pure parsers
# ---------------------------------------------------------------------

@pytest.mark.parametrize(
    "output,expected",
    [
        ("  Message signing enabled and required", "required"),
        ("Message signing: Required", "required"),
        ("  Message signing enabled but not required", "enabled"),
        ("Message signing: Enabled", "enabled"),
        ("  Message signing: disabled", "disabled"),
        ("Signing disabled", "disabled"),
        ("totally unrelated", None),
    ],
)
def test_parse_smb_signing(output, expected):
    assert ServiceEnum._parse_smb_signing(output) == expected


def test_parse_rootdse_extracts_domain():
    sample = """
LDAP Results
  <ROOT>
    defaultNamingContext: DC=sevenkingdoms,DC=local
    dnsHostName: dc01.sevenkingdoms.local
    rootDomainNamingContext: DC=sevenkingdoms,DC=local
"""
    domain, dns = ServiceEnum._parse_rootdse(sample)
    assert domain == "sevenkingdoms.local"
    assert dns == "dc01.sevenkingdoms.local"


def test_parse_rootdse_without_dns_host():
    sample = "defaultNamingContext: DC=corp,DC=internal,DC=example,DC=com"
    domain, dns = ServiceEnum._parse_rootdse(sample)
    assert domain == "corp.internal.example.com"
    assert dns == ""


def test_parse_rootdse_empty():
    domain, dns = ServiceEnum._parse_rootdse("")
    assert domain == ""
    assert dns == ""


# ---------------------------------------------------------------------
# XML ingestion against an nmap fixture
# ---------------------------------------------------------------------

def test_parse_nmap_xml_dc_sample(tm, fixtures_dir: Path):
    se = ServiceEnum(tm=tm)
    se._parse_nmap_xml(fixtures_dir / "nmap" / "dc_sample.xml")

    host = tm.get_host("192.168.56.10")
    assert host is not None, "host must be created from the XML"
    # Core AD ports should all be present.
    for port in (53, 88, 135, 139, 389, 445, 464, 593, 636, 3268, 3269, 3389):
        assert host.has_port(port), f"port {port} missing"
    # NSE-driven enrichment.
    assert host.is_dc is True
    assert host.domain == "sevenkingdoms.local"
    assert host.smb_signing == "required"
    assert host.hostname in ("dc01.sevenkingdoms.local", "DC01")


def test_parse_nmap_xml_unsigned_member_raises_finding(tm, fixtures_dir: Path):
    se = ServiceEnum(tm=tm)
    se._parse_nmap_xml(fixtures_dir / "nmap" / "member_server_unsigned.xml")

    host = tm.get_host("192.168.56.22")
    assert host is not None
    assert host.smb_signing == "disabled"
    assert "relay-target-smb" in host.tags

    ids = {f.id for f in tm.findings}
    assert f"SMB-SIGN-{host.ip}" in ids
    sev = {f.severity for f in tm.findings}
    assert "high" in sev


def test_run_noop_when_no_hosts(tm, caplog):
    se = ServiceEnum(tm=tm)
    se.run([])   # must not raise


# ---------------------------------------------------------------------
# Regression: SMB Computer name must override PTR-derived hostname
# (e.g. on AD-integrated DNS where PTR returns the domain FQDN).
# ---------------------------------------------------------------------

def test_smb_computer_name_overrides_ptr_hostname(tm, tmp_path: Path):
    """PTR returns the domain FQDN; smb-os-discovery returns the short
    Computer name. After parsing, ``host.hostname`` must be the shortname.
    """
    xml = tmp_path / "ptr_is_domain.xml"
    xml.write_text(
        '<?xml version="1.0"?>\n'
        '<nmaprun>\n'
        ' <host>\n'
        '  <status state="up"/>\n'
        '  <address addr="192.168.56.10" addrtype="ipv4"/>\n'
        '  <hostnames>\n'
        # Misleading PTR: just the domain.
        '   <hostname name="sevenkingdoms.local" type="PTR"/>\n'
        '  </hostnames>\n'
        '  <ports>\n'
        '   <port protocol="tcp" portid="445">\n'
        '    <state state="open"/>\n'
        '    <service name="microsoft-ds"/>\n'
        '    <script id="smb-os-discovery" '
        'output="&#xa;  OS: Windows Server 2019 Standard 17763&#xa;  '
        'Computer name: kingslanding&#xa;  '
        'Domain name: sevenkingdoms.local"/>\n'
        '   </port>\n'
        '  </ports>\n'
        ' </host>\n'
        '</nmaprun>\n'
    )

    se = ServiceEnum(tm=tm)
    se._parse_nmap_xml(xml)

    host = tm.get_host("192.168.56.10")
    assert host is not None
    assert host.hostname == "kingslanding", (
        f"hostname should be the SMB short name, not the PTR FQDN "
        f"(got {host.hostname!r})"
    )
    assert host.hostname != host.domain
