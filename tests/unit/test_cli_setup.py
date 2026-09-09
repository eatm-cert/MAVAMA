"""Unit tests for ``utils.cli_setup``."""

from __future__ import annotations

import ipaddress
from pathlib import Path
from unittest.mock import MagicMock

import pytest

import utils.cli_setup as cli_setup


def test_list_config_files_includes_generated_configs_and_skips_effective(monkeypatch, tmp_path):
    config_dir = tmp_path / "config"
    generated_dir = config_dir / "generated"
    generated_dir.mkdir(parents=True)
    (config_dir / "config.yaml").write_text("a: 1\n", encoding="utf-8")
    (generated_dir / "client-audit.yaml").write_text("b: 2\n", encoding="utf-8")
    (config_dir / ".effective.yaml").write_text("c: 3\n", encoding="utf-8")

    monkeypatch.setattr(cli_setup, "CONFIG_DIR", config_dir)
    monkeypatch.setattr(cli_setup, "_PROJECT_ROOT", tmp_path)

    files = cli_setup._list_config_files()

    assert "config/config.yaml" in files
    assert "config/generated/client-audit.yaml" in files
    assert "config/.effective.yaml" not in files


def test_resolve_output_path_defaults_to_generated_directory(monkeypatch, tmp_path):
    monkeypatch.setattr(cli_setup, "_PROJECT_ROOT", tmp_path)
    monkeypatch.setattr(cli_setup, "CONFIG_DIR", tmp_path / "config")

    resolved = cli_setup._resolve_output_path("", "client-audit")

    assert resolved == (tmp_path / "config/generated/client-audit.yaml").resolve()


def test_resolve_output_path_appends_yaml_suffix(monkeypatch, tmp_path):
    monkeypatch.setattr(cli_setup, "_PROJECT_ROOT", tmp_path)

    resolved = cli_setup._resolve_output_path("/tmp/custom/report", "client-audit")

    assert resolved == Path("/tmp/custom/report.yaml").resolve()


def test_load_passwords_from_file_ignores_blank_lines_and_comments(tmp_path):
    password_file = tmp_path / "passwords.txt"
    password_file.write_text(
        "# comment\n\nPassword1\nWelcome1\n   \n# another comment\n",
        encoding="utf-8",
    )

    assert cli_setup._load_passwords_from_file(password_file) == ["Password1", "Welcome1"]


# ---------------------------------------------------------------------------
# _normalize_target_input
# ---------------------------------------------------------------------------

def _addr_count(nets: list[str]) -> int:
    """Total number of IP addresses in a list of CIDR strings."""
    return sum(ipaddress.ip_network(n).num_addresses for n in nets)


def test_normalize_plain_cidr():
    result = cli_setup._normalize_target_input("10.0.0.0/24")
    assert result == ["10.0.0.0/24"]
    assert _addr_count(result) == 256


def test_normalize_explicit_ip_range():
    result = cli_setup._normalize_target_input("192.168.56.1-192.168.56.254")
    assert _addr_count(result) == 254
    # All IPs are inside the expected bounds
    all_ips = [str(ip) for net in result for ip in ipaddress.ip_network(net)]
    assert all_ips[0] == "192.168.56.1"
    assert all_ips[-1] == "192.168.56.254"


def test_normalize_last_octet_shorthand():
    # 192.168.56.1-24 → 24 IPs (.1 through .24)
    result = cli_setup._normalize_target_input("192.168.56.1-24")
    assert result == [
        "192.168.56.1/32",
        "192.168.56.2/31",
        "192.168.56.4/30",
        "192.168.56.8/29",
        "192.168.56.16/29",
        "192.168.56.24/32",
    ]
    assert _addr_count(result) == 24


def test_normalize_prefix_suffix_stripped():
    # /24 suffix is decoration - strip it, treat remainder as last-octet range
    assert cli_setup._normalize_target_input("192.168.56.1-24/24") == \
        cli_setup._normalize_target_input("192.168.56.1-24")


def test_normalize_prefix_suffix_does_not_expand_full_subnet():
    # 192.168.56.1-24/24 must give 24 IPs (NOT 256)
    result = cli_setup._normalize_target_input("192.168.56.1-24/24")
    assert _addr_count(result) == 24


def test_normalize_comma_separated():
    result = cli_setup._normalize_target_input("10.0.0.0/30, 192.168.1.0/30")
    assert "10.0.0.0/30" in result
    assert "192.168.1.0/30" in result
    assert len(result) == 2


def test_normalize_single_host():
    result = cli_setup._normalize_target_input("10.0.0.42/32")
    assert result == ["10.0.0.42/32"]
    assert _addr_count(result) == 1


def test_normalize_invalid_raises():
    with pytest.raises(ValueError):
        cli_setup._normalize_target_input("not-an-ip")


def test_normalize_empty_raises():
    with pytest.raises(ValueError):
        cli_setup._normalize_target_input("   ")


# ---------------------------------------------------------------------------
# _describe_targets
# ---------------------------------------------------------------------------

def test_describe_targets_single_cidr():
    assert cli_setup._describe_targets(["10.0.0.0/24"]) == "10.0.0.0/24"


def test_describe_targets_single_host():
    assert cli_setup._describe_targets(["10.0.0.42/32"]) == "10.0.0.42"


def test_describe_targets_range_shows_first_last_and_count():
    nets = cli_setup._normalize_target_input("192.168.56.1-24")
    desc = cli_setup._describe_targets(nets)
    assert "192.168.56.1" in desc
    assert "192.168.56.24" in desc
    assert "24" in desc


def test_describe_targets_empty():
    assert cli_setup._describe_targets([]) == "(none)"


# ---------------------------------------------------------------------------
# _effective_scope_count
# ---------------------------------------------------------------------------

def test_effective_scope_count_with_single_exclusion():
    nets = cli_setup._normalize_target_input("192.168.56.1-24")
    # 24 IPs minus 192.168.56.1 = 23
    assert cli_setup._effective_scope_count(nets, ["192.168.56.1"]) == 23


def test_effective_scope_count_no_exclusions():
    assert cli_setup._effective_scope_count(["10.0.0.0/30"], []) == 4


def test_effective_scope_count_cidr_exclusion():
    # /30 has 4 addrs; exclude the whole thing
    assert cli_setup._effective_scope_count(["10.0.0.0/30"], ["10.0.0.0/30"]) == 0


# ---------------------------------------------------------------------------
# _detect_interface_for_subnet
# ---------------------------------------------------------------------------

def _make_psutil_addr(ip: str, netmask: str):
    import socket
    addr = MagicMock()
    addr.family = socket.AF_INET
    addr.address = ip
    addr.netmask = netmask
    return addr


def test_detect_interface_for_subnet_returns_overlapping_interface(monkeypatch):
    mock_addrs = {
        "eth0": [_make_psutil_addr("10.0.0.1", "255.255.255.0")],
        "eth1": [_make_psutil_addr("192.168.56.100", "255.255.255.0")],
    }
    monkeypatch.setattr(cli_setup.psutil, "net_if_addrs", lambda: mock_addrs)
    assert cli_setup._detect_interface_for_subnet("192.168.56.0/24") == "eth1"


def test_detect_interface_for_subnet_returns_none_when_no_match(monkeypatch):
    mock_addrs = {
        "eth0": [_make_psutil_addr("10.0.0.1", "255.255.255.0")],
    }
    monkeypatch.setattr(cli_setup.psutil, "net_if_addrs", lambda: mock_addrs)
    assert cli_setup._detect_interface_for_subnet("192.168.56.0/24") is None


def test_detect_interface_for_subnet_returns_none_when_psutil_unavailable(monkeypatch):
    monkeypatch.setattr(cli_setup, "_HAS_PSUTIL", False)
    assert cli_setup._detect_interface_for_subnet("192.168.56.0/24") is None


# ---------------------------------------------------------------------
# --phase conditioning of the wizard (public edition: NO relay phase).
# ---------------------------------------------------------------------

def test_phase_sections_recon_asks_creds_and_recon():
    assert cli_setup._phase_sections("recon") == {"creds", "recon"}


def test_phase_sections_credentials_asks_creds_and_spray():
    assert cli_setup._phase_sections("credentials") == {"creds", "spray"}


def test_phase_sections_report_asks_nothing_extra():
    assert cli_setup._phase_sections("report") == set()


def test_phase_sections_all_asks_everything_but_never_relay():
    every = cli_setup._phase_sections("all")
    assert every == {"creds", "recon", "spray"}
    assert "relay" not in every   # the public build has no relay phase
