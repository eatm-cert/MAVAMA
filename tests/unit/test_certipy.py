"""Unit tests for ADCS detection (service_enum) and certipy.py skeleton."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from core.target_manager import CertificateAuthority, TargetManager


# ---------------------------------------------------------------------------
# ServiceEnum: ADCS detection via ssl-cert and http-title
# ---------------------------------------------------------------------------

def _make_script_el(sid: str, output: str) -> ET.Element:
    el = ET.Element("script")
    el.set("id", sid)
    el.set("output", output)
    return el


def _se(tm):
    from modules.recon.service_enum import ServiceEnum
    return ServiceEnum(tm=tm)


def test_service_enum_detects_adcs_via_ssl_cert(tm):
    se = _se(tm)
    tm.add_host("192.168.56.20")
    host = tm.get_host("192.168.56.20")
    host.add_service(443)
    el = _make_script_el("ssl-cert", "Subject: OU=AD Certificate Services, CN=lab-CA")
    se._consume_script(host, port=443, script=el)
    assert host.is_adcs is True
    assert "adcs-web" in host.tags
    assert any(c.ip == "192.168.56.20" for c in tm.certificate_authorities)


def test_service_enum_detects_adcs_via_http_title(tm):
    se = _se(tm)
    tm.add_host("192.168.56.20")
    host = tm.get_host("192.168.56.20")
    host.add_service(80)
    el = _make_script_el("http-title", "Active Directory Certificate Services")
    se._consume_script(host, port=80, script=el)
    assert host.is_adcs is True
    assert any(c.web_enrollment_url.startswith("http://") for c in tm.certificate_authorities)


def test_service_enum_adcs_emits_finding(tm):
    se = _se(tm)
    tm.add_host("192.168.56.20")
    host = tm.get_host("192.168.56.20")
    el = _make_script_el("ssl-cert", "Certificate Services")
    se._consume_script(host, port=443, script=el)
    ids = {f.id for f in tm.findings}
    assert "ADCS-WEB-192.168.56.20" in ids


def test_service_enum_adcs_not_triggered_by_unrelated_title(tm):
    se = _se(tm)
    tm.add_host("192.168.56.20")
    host = tm.get_host("192.168.56.20")
    el = _make_script_el("http-title", "IIS Welcome Page")
    se._consume_script(host, port=80, script=el)
    assert host.is_adcs is False
    assert tm.certificate_authorities == []


def test_service_enum_adcs_registered_only_once(tm):
    se = _se(tm)
    tm.add_host("192.168.56.20")
    host = tm.get_host("192.168.56.20")
    el = _make_script_el("ssl-cert", "Certificate Services")
    se._consume_script(host, port=443, script=el)
    se._consume_script(host, port=443, script=el)   # duplicate
    assert sum(1 for c in tm.certificate_authorities if c.ip == "192.168.56.20") == 1


# ---------------------------------------------------------------------------
# TargetManager: CertificateAuthority persistence
# ---------------------------------------------------------------------------

def test_ca_round_trips_through_json(tm, tmp_path):
    tm.add_ca(CertificateAuthority(ip="10.0.0.1", ca_name="lab-CA", web_enrollment_url="https://10.0.0.1/certsrv"))
    path = tm.save(tmp_path / "state.json")

    from core.target_manager import TargetManager as TM2
    tm2 = TM2(loot_dir=str(tmp_path))
    tm2.load_from_json(path)
    assert len(tm2.certificate_authorities) == 1
    assert tm2.certificate_authorities[0].ca_name == "lab-CA"


# ---------------------------------------------------------------------------
# CertipyRunner skeleton
# ---------------------------------------------------------------------------

from modules.exploitation.certipy import CertipyRunner, CertipyResult  # noqa: E402


def _make_certipy(tm, **overrides) -> CertipyRunner:
    defaults = dict(
        domain="sevenkingdoms.local",
        dc_ip="192.168.56.10",
        username="Administrator",
        password="s3cret",
        loot_dir="/tmp/certipy_test",
        binary="/usr/bin/certipy",
    )
    defaults.update(overrides)
    return CertipyRunner(tm=tm, **defaults)


def test_certipy_check_prerequisites_fails_without_binary(tm):
    r = _make_certipy(tm, binary=None)
    ok, reason = r.check_prerequisites()
    # _resolve_binary returns None when certipy is not installed
    # Just ensure binary=None → prereq fails
    assert not ok or r.binary is not None


def test_certipy_check_prerequisites_fails_without_credentials(tm):
    r = _make_certipy(tm, password="", nthash="")
    ok, reason = r.check_prerequisites()
    assert not ok
    assert "password" in reason or "hash" in reason


def test_certipy_resolves_from_fallback_dir_when_not_on_path(tm, tmp_path, monkeypatch):
    """Under sudo, $PATH drops ~/.local/bin so shutil.which misses certipy.
    _resolve_binary must still find it via the pipx/home fallback dirs."""
    import modules.exploitation.certipy as mod
    fake_bin = tmp_path / "certipy"
    fake_bin.write_text("#!/bin/sh\n")
    fake_bin.chmod(0o755)
    # certipy is NOT on PATH...
    monkeypatch.setattr(mod.shutil, "which", lambda _c: None)
    # ...isolate HOME so the real ~/.local/bin/certipy on the test host is not
    # picked up, then expose the fake one via the pipx bin dir.
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.delenv("SUDO_USER", raising=False)
    monkeypatch.setenv("PIPX_BIN_DIR", str(tmp_path))
    r = _make_certipy(tm, binary=None)
    assert r.binary == str(fake_bin)
    ok, _reason = r.check_prerequisites()
    assert ok


def test_certipy_find_parses_esc1(tm, monkeypatch, tmp_path):
    import modules.exploitation.certipy as cert_mod

    output = (
        "Template Name    : UserTemplate\n"
        "[!] ESC1 - Enrollee Supplies Subject\n"
        "CA Name          : sevenkingdoms-CA\n"
    )
    monkeypatch.setattr(
        cert_mod.subprocess, "run",
        lambda *a, **kw: MagicMock(returncode=0, stdout=output, stderr=""),
    )
    r = _make_certipy(tm, loot_dir=str(tmp_path))
    result = r.find_vulnerable_templates()

    assert result.status == "completed"
    assert any(v["esc"] == "ESC1" for v in result.vulnerable_templates)
    assert any(f.id.startswith("ADCS-ESC1") for f in tm.findings)
    assert any(c.ca_name == "sevenkingdoms-CA" for c in tm.certificate_authorities)


def test_certipy_find_writes_into_loot_dir_not_project_root(tm, monkeypatch, tmp_path):
    """Regression: certipy's ``-output`` is a filename stem written to CWD, so
    it must run FROM the loot dir with a bare stem - otherwise its loot files
    (``loot_<slug>_certipy_<CA>.json``) land in the project root."""
    import modules.exploitation.certipy as cert_mod

    captured = {}

    def _fake_run(cmd, *a, **kw):
        captured["cmd"] = cmd
        captured["cwd"] = kw.get("cwd")
        return MagicMock(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(cert_mod.subprocess, "run", _fake_run)
    r = _make_certipy(tm, loot_dir=str(tmp_path))
    r.find_vulnerable_templates()

    # -output must be a bare stem (no path separators)...
    idx = captured["cmd"].index("-output")
    assert captured["cmd"][idx + 1] == "certipy"
    # ...and certipy must run from the loot dir so the files land there.
    assert str(captured["cwd"]) == str(tmp_path)


def test_certipy_find_returns_skipped_when_no_binary(tm, monkeypatch):
    r = _make_certipy(tm, binary=None)
    # Force _resolve_binary to also return None
    monkeypatch.setattr(r, "binary", None)
    result = r.find_vulnerable_templates()
    assert result.status == "skipped"


def test_certipy_request_skipped_in_safe_mode(tm, monkeypatch, tmp_path):
    r = _make_certipy(tm, loot_dir=str(tmp_path), safe_mode=True)
    result = r.request_certificate("sevenkingdoms-CA", "UserTemplate")
    assert result.status == "skipped"
    assert "safe mode" in result.stderr


def test_certipy_request_parses_pfx_path(tm, monkeypatch, tmp_path):
    import modules.exploitation.certipy as cert_mod

    output = "Saved certificate and key to Administrator.pfx\n"
    monkeypatch.setattr(
        cert_mod.subprocess, "run",
        lambda *a, **kw: MagicMock(returncode=0, stdout=output, stderr=""),
    )
    r = _make_certipy(tm, loot_dir=str(tmp_path))
    result = r.request_certificate("sevenkingdoms-CA", "UserTemplate")
    assert result.status == "completed"
    # certipy writes the .pfx into its CWD (the loot dir); the bare filename it
    # prints is resolved back to the real location inside loot_dir.
    assert result.certificate_path == str(tmp_path / "Administrator.pfx")
