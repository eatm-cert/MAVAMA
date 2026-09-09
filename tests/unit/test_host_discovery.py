"""Tests for ``modules.recon.host_discovery``."""

from __future__ import annotations

import ipaddress
import socket
from unittest.mock import MagicMock, patch

import pytest

from modules.recon.host_discovery import HostDiscovery


@pytest.fixture
def hd(tm):
    return HostDiscovery(
        tm=tm,
        targets=["192.168.56.0/29"],     # 6 usable IPs
        exclude=["192.168.56.3"],
        timeout=1,
    )


def test_expand_cidr(hd):
    ips = hd._expand(["192.168.56.0/30"])
    assert ips == ["192.168.56.0", "192.168.56.1", "192.168.56.2", "192.168.56.3"]


def test_expand_single_host(hd):
    ips = hd._expand(["10.0.0.42/32", "10.0.0.43"])
    assert "10.0.0.42" in ips
    assert "10.0.0.43" in ips


def test_expand_invalid_entry_is_ignored(hd):
    ips = hd._expand(["not-a-cidr", "10.0.0.0/30"])
    assert all(ip.startswith("10.0.0.") for ip in ips)


def test_scope_applies_exclusions(hd):
    scope = hd._scope()
    assert "192.168.56.3" not in scope           # excluded
    assert "192.168.56.1" in scope
    assert "192.168.56.6" in scope


def test_scope_is_sorted_numerically(hd):
    # With /28 we have 0..15; sorting lex would put 10 before 2 - not the case here,
    # but enforce the behaviour with an extra range.
    hd.targets = ["10.0.0.0/28"]
    hd.exclude = []
    scope = hd._scope()
    assert scope == [f"10.0.0.{i}" for i in range(0, 16)]


def test_tcp_probe_open(hd):
    with patch("socket.socket") as sock_cls:
        sock = MagicMock()
        sock.connect_ex.return_value = 0
        sock_cls.return_value.__enter__.return_value = sock
        assert hd._tcp_probe("10.0.0.1", 445, 1) is True


def test_tcp_probe_closed(hd):
    with patch("socket.socket") as sock_cls:
        sock = MagicMock()
        sock.connect_ex.return_value = 111
        sock_cls.return_value.__enter__.return_value = sock
        assert hd._tcp_probe("10.0.0.1", 445, 1) is False


def test_icmp_ping_handles_timeout(hd):
    with patch(
        "modules.recon.host_discovery.subprocess.run",
        side_effect=Exception("boom"),
    ):
        assert hd._icmp_ping("10.0.0.1", 1) is False


def test_tcp_ping_populates_tm(hd, tm):
    scope = ["10.0.0.1", "10.0.0.2"]
    with patch.object(HostDiscovery, "_tcp_probe", side_effect=lambda ip, port, t, attempts=1: ip == "10.0.0.1"):
        alive = hd.tcp_ping(scope)
    assert alive == {"10.0.0.1"}
    assert tm.get_host("10.0.0.1") is not None
    assert tm.get_host("10.0.0.2") is None


def test_ping_sweep_populates_tm(hd, tm):
    scope = ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
    with patch.object(HostDiscovery, "_icmp_ping", side_effect=lambda ip, t, attempts=1: ip.endswith(("1", "3"))):
        alive = hd.ping_sweep(scope)
    assert alive == {"10.0.0.1", "10.0.0.3"}


# ---------------------------------------------------------------------
# Retry behaviour (regression: a single dropped probe must not flip a live
# host to 'down', which made discovery non-deterministic between runs).
# ---------------------------------------------------------------------

def test_tcp_probe_retries_absorb_a_dropped_syn(hd):
    """First connect fails, second succeeds -> host is up (attempts=2)."""
    with patch("socket.socket") as sock_cls:
        sock = MagicMock()
        sock.connect_ex.side_effect = [111, 0]  # miss, then hit
        sock_cls.return_value.__enter__.return_value = sock
        assert hd._tcp_probe("10.0.0.1", 445, 1, attempts=2) is True


def test_tcp_probe_all_attempts_fail_is_down(hd):
    with patch("socket.socket") as sock_cls:
        sock = MagicMock()
        sock.connect_ex.return_value = 111
        sock_cls.return_value.__enter__.return_value = sock
        assert hd._tcp_probe("10.0.0.1", 445, 1, attempts=3) is False


def test_icmp_ping_sends_multiple_probes(hd):
    """attempts=3 -> ``ping -c 3`` (any reply among the 3 marks the host up)."""
    with patch("modules.recon.host_discovery.subprocess.run") as run:
        run.return_value = MagicMock(returncode=0)
        assert hd._icmp_ping("10.0.0.1", 1, attempts=3) is True
        argv = run.call_args[0][0]
        assert argv[:3] == ["ping", "-c", "3"]


def test_discovery_defaults_to_multiple_retries(tm):
    hd = HostDiscovery(tm=tm, targets=["10.0.0.0/30"])
    assert hd.retries >= 2


def test_run_aborts_on_empty_scope(tm):
    hd = HostDiscovery(tm=tm, targets=["10.0.0.0/32"], exclude=["10.0.0.0/32"])
    result = hd.run(do_arp=False, do_icmp=False, do_tcp=False)
    assert result == set()


# ---------------------------------------------------------------------------
# _get_iface_for_target
# ---------------------------------------------------------------------------

def _make_addr(ip: str, netmask: str) -> MagicMock:
    addr = MagicMock()
    addr.family = socket.AF_INET
    addr.address = ip
    addr.netmask = netmask
    return addr


def test_get_iface_for_target_returns_overlapping_interface(hd):
    mock_addrs = {
        "eth0": [_make_addr("10.0.0.1", "255.255.255.0")],
        "eth1": [_make_addr("192.168.56.100", "255.255.255.0")],
    }
    with patch("psutil.net_if_addrs", return_value=mock_addrs):
        result = hd._get_iface_for_target(ipaddress.ip_network("192.168.56.0/24"))
    assert result == "eth1"


def test_get_iface_for_target_returns_none_when_no_match(hd):
    mock_addrs = {
        "eth0": [_make_addr("10.0.0.1", "255.255.255.0")],
    }
    with patch("psutil.net_if_addrs", return_value=mock_addrs):
        result = hd._get_iface_for_target(ipaddress.ip_network("192.168.56.0/24"))
    assert result is None


def test_get_iface_for_target_returns_none_on_import_error(hd):
    with patch("builtins.__import__", side_effect=lambda n, *a, **k: (_ for _ in ()).throw(ImportError()) if n == "psutil" else __import__(n, *a, **k)):
        result = hd._get_iface_for_target(ipaddress.ip_network("192.168.56.0/24"))
    assert result is None
