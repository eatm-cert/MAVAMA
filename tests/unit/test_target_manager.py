"""Tests for ``core.target_manager``."""

from __future__ import annotations

import json
from pathlib import Path

from core.target_manager import Credential, Finding, TargetManager


def test_add_host_creates_and_updates(tm: TargetManager):
    host = tm.add_host("10.0.0.1", hostname="dc01")
    assert host.ip == "10.0.0.1"
    assert host.hostname == "dc01"

    # Second call must update in place, not duplicate.
    again = tm.add_host("10.0.0.1", os="Windows Server 2019")
    assert again is host
    assert len(tm.alive_hosts()) == 1
    assert again.os == "Windows Server 2019"
    assert again.hostname == "dc01"  # preserved


def test_add_host_ignores_empty_overrides(tm: TargetManager):
    host = tm.add_host("10.0.0.1", hostname="dc01")
    tm.add_host("10.0.0.1", hostname="")         # blank must not erase
    tm.add_host("10.0.0.1", hostname=None)       # None must not erase
    assert host.hostname == "dc01"


def test_host_add_service_is_idempotent(tm: TargetManager):
    host = tm.add_host("10.0.0.1")
    host.add_service(port=445, name="smb")
    host.add_service(port=445, banner="Windows Server 2019")
    assert len(host.services) == 1
    svc = host.services[0]
    assert svc.port == 445
    assert svc.name == "smb"
    assert svc.banner == "Windows Server 2019"


def test_host_has_port(tm: TargetManager):
    host = tm.add_host("10.0.0.1")
    host.add_service(port=389, name="ldap")
    assert host.has_port(389)
    assert not host.has_port(445)


def test_users_deduplicated_and_lowercased(tm: TargetManager):
    tm.add_user("Alice")
    tm.add_user("alice")
    tm.add_user("BOB")
    tm.add_user("")  # ignored
    assert tm.users == {"alice", "bob"}


def test_dcs_filter(tm: TargetManager):
    tm.add_host("10.0.0.1", is_dc=True)
    tm.add_host("10.0.0.2")
    tm.add_host("10.0.0.3", is_dc=True)
    dcs = {h.ip for h in tm.dcs()}
    assert dcs == {"10.0.0.1", "10.0.0.3"}


def test_multi_dc_entries_are_independent(tm: TargetManager):
    """Adding a second DC must NOT overwrite the first one. Each IP
    keeps its own Host entry and ``dcs()`` returns the full list - the
    invariant that lets the orchestrator drive multi-DC engagements."""
    first = tm.add_host(
        "10.0.0.10", hostname="dc01.lab", is_dc=True, domain="lab.local"
    )
    second = tm.add_host(
        "10.0.0.11", hostname="dc02.lab", is_dc=True, domain="lab.local"
    )
    assert first is not second
    assert len(tm.dcs()) == 2
    by_ip = {h.ip: h for h in tm.dcs()}
    assert by_ip["10.0.0.10"].hostname == "dc01.lab"
    assert by_ip["10.0.0.11"].hostname == "dc02.lab"


def test_is_dc_cannot_be_demoted_by_a_later_add_host(tm: TargetManager):
    """Once a recon module has identified a host as a DC, a later
    ``add_host()`` from a different module that happens to pass
    ``is_dc=False`` must not silently strip the flag."""
    tm.add_host("10.0.0.10", is_dc=True, domain="lab.local")
    tm.add_host("10.0.0.10", is_dc=False)
    assert tm.get_host("10.0.0.10").is_dc is True

    tm.add_host("10.0.0.20", is_adcs=True)
    tm.add_host("10.0.0.20", is_adcs=False)
    assert tm.get_host("10.0.0.20").is_adcs is True


def test_findings_and_credentials(tm: TargetManager):
    tm.add_finding(Finding(id="F1", title="Test", severity="high"))
    tm.add_credential(Credential(username="svc_sql", nt_hash="aad3b..."))
    assert len(tm.findings) == 1
    assert tm.credentials[0].username == "svc_sql"


def test_credential_real_nt_hash_accepts_only_32_hex():
    # Genuine NTLM hash (32 hex) is accepted.
    real = Credential(username="svc", nt_hash="31d6cfe0d16ae931b73c59d7e0c089c0")
    assert real.real_nt_hash == "31d6cfe0d16ae931b73c59d7e0c089c0"
    assert real.has_auth_secret is True

    # A stashed kerberoast/AS-REP blob is NOT a usable hash.
    blob = Credential(username="dowens", nt_hash="$krb5tgs$23$*dowens$ROOTME$...")
    assert blob.real_nt_hash is None
    assert blob.has_auth_secret is False

    # Password-only credential authenticates.
    pwd = Credential(username="pentest", password="Pent3st123!")
    assert pwd.has_auth_secret is True

    # Nothing usable.
    empty = Credential(username="ghost")
    assert empty.real_nt_hash is None
    assert empty.has_auth_secret is False


def test_save_produces_valid_json(tm: TargetManager, tmp_path: Path):
    tm.add_host("10.0.0.1", is_dc=True, domain="lab.local")
    tm.add_user("administrator")
    tm.add_finding(Finding(id="X", title="t", severity="low", host="10.0.0.1"))
    out = tm.save(tmp_path / "state.json")
    data = json.loads(out.read_text())
    assert "10.0.0.1" in data["hosts"]
    assert data["hosts"]["10.0.0.1"]["is_dc"] is True
    assert "administrator" in data["users"]
    assert data["findings"][0]["id"] == "X"


def test_finding_method_field_round_trips(tm: TargetManager, tmp_path: Path):
    tm.add_finding(
        Finding(id="Y", title="t", severity="info", method="how X was probed")
    )
    out = tm.save(tmp_path / "state.json")
    assert json.loads(out.read_text())["findings"][0]["method"] == "how X was probed"

    # And it is restored on load.
    fresh = TargetManager(loot_dir=str(tmp_path / "loot2"))
    assert fresh.load_from_json(out) is True
    assert fresh.findings[0].method == "how X was probed"


def test_record_command_captures_and_serializes(tm: TargetManager, tmp_path: Path):
    tm.record_command(
        ["nmap", "-sV", "10.0.0.1"], phase="Phase 1 - Reconnaissance",
        tool="nmap", target="10.0.0.1",
    )
    # A raw string is accepted too (e.g. a pre-joined command).
    tm.record_command(
        "secretsdump.py d/u:pw@10.0.0.1", phase="Phase 3 - Credential Harvesting",
        tool="secretsdump", target="10.0.0.1",
    )
    assert len(tm.commands) == 2
    assert tm.commands[0]["command"] == "nmap -sV 10.0.0.1"
    assert tm.commands[0]["tool"] == "nmap"

    out = tm.save(tmp_path / "state.json")
    data = json.loads(out.read_text())
    assert len(data["commands"]) == 2

    # The ledger survives a reload (standalone later phase / report regen).
    fresh = TargetManager(loot_dir=str(tmp_path / "loot2"))
    assert fresh.load_from_json(out) is True
    assert len(fresh.commands) == 2
    assert fresh.commands[1]["command"] == "secretsdump.py d/u:pw@10.0.0.1"


def test_finding_command_round_trips(tm: TargetManager, tmp_path: Path):
    tm.add_finding(
        Finding(id="Z", title="t", severity="high",
                command="nxc ldap 10.0.0.1 -u u -p pw -M ldap-checker")
    )
    out = tm.save(tmp_path / "state.json")
    assert json.loads(out.read_text())["findings"][0]["command"].endswith("ldap-checker")

    fresh = TargetManager(loot_dir=str(tmp_path / "loot2"))
    assert fresh.load_from_json(out) is True
    assert fresh.findings[0].command.endswith("ldap-checker")


def test_render_findings_shows_command_with_copy_button(tm: TargetManager):
    """A finding's producing command is rendered with a Copy button."""
    from modules.reporting.phase1_report import _render_findings

    tm.add_finding(
        Finding(id="LDAP-CB-10.0.0.1", title="LDAPS channel binding not enforced (EPA)",
                severity="high", host="10.0.0.1",
                command="nxc ldap 10.0.0.1 -u u -p pw -M ldap-checker")
    )
    html = _render_findings(tm.to_dict())
    assert "nxc ldap 10.0.0.1 -u u -p pw -M ldap-checker" in html
    assert 'class="copy-btn"' in html
    assert "data-copy=" in html


def test_render_credentials_wraps_long_ticket_with_copy_button(tm: TargetManager):
    """A long AS-REP ticket is rendered in a wrapping copy box, not raw inline."""
    from modules.reporting.phase1_report import _render_credentials

    blob = "$krb5asrep$23$missandei@ESSOS.LOCAL:" + "a" * 800
    tm.add_credential(Credential(username="missandei", domain="ESSOS.LOCAL",
                                 ticket=blob, source="as-rep-roast-candidate"))
    html = _render_credentials(tm.to_dict())
    assert "copybox" in html
    assert 'class="copy-btn"' in html
    assert "copybox-val" in html
