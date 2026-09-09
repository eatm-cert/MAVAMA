"""Discovery of active hosts on the network.

Three techniques are combined to maximize coverage:

1. **ARP scan** (L2, scapy) - works only on local segments and requires
   ``root`` privileges. Highly reliable since it cannot be filtered by a
   host-based firewall.
2. **ICMP ping sweep** - concurrent ``ping -c1 -W<timeout>`` probes.
3. **TCP ping** - TCP connect probe on common AD ports (445/135/3389) to
   detect hosts that block ICMP but still answer on TCP.

Results are merged and published into the ``TargetManager``.
"""

from __future__ import annotations

import ipaddress
import os
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.logger import get_logger
from core.target_manager import TargetManager

try:
    from scapy.all import ARP, Ether, srp, conf as scapy_conf  # type: ignore

    scapy_conf.verb = 0
    _HAS_SCAPY = True
except Exception:  # pragma: no cover
    _HAS_SCAPY = False


class HostDiscovery:
    def __init__(
        self,
        tm: TargetManager,
        targets: list[str],
        exclude: list[str] | None = None,
        timeout: int = 2,
        tcp_ports: list[int] | None = None,
        interface: str | None = None,
        retries: int = 2,
    ):
        self.tm = tm
        self.targets = targets
        self.exclude = exclude or []
        self.timeout = timeout
        self.tcp_ports = tcp_ports or [445, 135, 3389]
        self.interface = interface
        # Each host is probed up to ``retries`` times before being declared
        # down. A single dropped ARP/ICMP/TCP packet would otherwise flip a
        # live host to 'down' between runs, making discovery non-deterministic
        # (the same lab yielding different host counts on back-to-back scans).
        self.retries = max(1, retries)
        self.log = get_logger()

    # ------------------------------------------------------------------
    # Interface helpers

    def _get_iface_for_target(self, net: ipaddress.IPv4Network) -> str | None:
        """Return the local interface whose L2 segment overlaps with net.

        Used by the ARP scan to pick the correct NIC when the operator
        chose auto-detect.  Without this, Scapy falls back to the default-
        route interface (typically the internet NIC on a multi-homed host),
        which never reaches a VirtualBox/VMware host-only segment.
        """
        try:
            import psutil
            for iface, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    if addr.family == socket.AF_INET:
                        try:
                            local_net = ipaddress.ip_network(
                                f"{addr.address}/{addr.netmask}", strict=False
                            )
                            if net.overlaps(local_net):
                                return iface
                        except Exception:
                            pass
        except ImportError:
            pass
        return None

    # ------------------------------------------------------------------
    # Range helpers

    def _expand(self, cidrs: list[str]) -> list[str]:
        ips: list[str] = []
        for entry in cidrs:
            try:
                net = ipaddress.ip_network(entry, strict=False)
            except ValueError:
                self.log.warn(f"Invalid range ignored: {entry}")
                continue
            # Include all addresses in the CIDR range (no exclusions for network/broadcast).
            ips.extend(str(ip) for ip in net)
        return ips

    def _scope(self) -> list[str]:
        ips = set(self._expand(self.targets))
        ips -= set(self._expand(self.exclude))
        return sorted(ips, key=lambda x: tuple(int(p) for p in x.split(".")))

    # ------------------------------------------------------------------
    # ARP scan

    def arp_scan(self) -> set[str]:
        if not _HAS_SCAPY:
            self.log.warn("scapy not available - ARP scan disabled")
            return set()
        if os.geteuid() != 0:
            self.log.warn("ARP scan requires root - step skipped")
            return set()

        alive: set[str] = set()
        for entry in self.targets:
            try:
                net = ipaddress.ip_network(entry, strict=False)
            except ValueError:
                continue
            # Resolve the interface: explicit config > L2-matching NIC > Scapy default.
            iface = self.interface or self._get_iface_for_target(net)
            self.log.action(f"ARP scan {entry} (iface={iface or 'auto'})")
            try:
                pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(net))
                ans, _ = srp(
                    pkt,
                    timeout=self.timeout,
                    iface=iface,
                    verbose=False,
                )
                for _, rcv in ans:
                    ip = rcv.psrc
                    mac = rcv.hwsrc
                    alive.add(ip)
                    self.tm.add_host(ip=ip, mac=mac)
                    self.log.debug(f"ARP up {ip} ({mac})")
            except PermissionError:
                self.log.error("Permission denied for ARP scan")
                return alive
            except Exception as exc:  # pragma: no cover
                self.log.error(f"ARP scan failed on {entry}: {exc}")
        return alive

    # ------------------------------------------------------------------
    # ICMP ping sweep

    @staticmethod
    def _icmp_ping(ip: str, timeout: int, attempts: int = 1) -> bool:
        # ``ping -c N`` sends N echo requests and exits 0 if ANY of them is
        # answered, so a single lost packet no longer marks a live host down.
        attempts = max(1, attempts)
        try:
            res = subprocess.run(
                ["ping", "-c", str(attempts), "-W", str(timeout), ip],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=attempts * (timeout + 1) + 1,
            )
            return res.returncode == 0
        except Exception:
            return False

    def ping_sweep(self, scope: list[str]) -> set[str]:
        self.log.action(f"ICMP ping sweep on {len(scope)} IPs")
        alive: set[str] = set()
        with ThreadPoolExecutor(max_workers=64) as pool:
            futs = {
                pool.submit(self._icmp_ping, ip, self.timeout, self.retries): ip
                for ip in scope
            }
            for fut in as_completed(futs):
                ip = futs[fut]
                if fut.result():
                    alive.add(ip)
                    self.tm.add_host(ip=ip)
                    self.log.debug(f"ICMP up {ip}")
        return alive

    # ------------------------------------------------------------------
    # TCP ping (common AD ports)

    @staticmethod
    def _tcp_probe(ip: str, port: int, timeout: int, attempts: int = 1) -> bool:
        # Retry the connect: a single dropped SYN/SYN-ACK must not flip a live
        # host to 'down' (a common source of run-to-run discovery variance).
        for _ in range(max(1, attempts)):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(timeout)
                    if s.connect_ex((ip, port)) == 0:
                        return True
            except Exception:
                pass
        return False

    def tcp_ping(self, scope: list[str]) -> set[str]:
        self.log.action(
            f"TCP ping on {len(scope)} IPs (ports {self.tcp_ports})"
        )
        alive: set[str] = set()

        def probe(ip: str) -> str | None:
            for port in self.tcp_ports:
                if self._tcp_probe(ip, port, self.timeout, self.retries):
                    return ip
            return None

        with ThreadPoolExecutor(max_workers=128) as pool:
            for ip in pool.map(probe, scope):
                if ip:
                    alive.add(ip)
                    self.tm.add_host(ip=ip)
                    self.log.debug(f"TCP up {ip}")
        return alive

    # ------------------------------------------------------------------
    # Reverse DNS resolution (best effort)

    def _resolve_hostnames(self, ips: set[str]) -> None:
        for ip in ips:
            try:
                name = socket.gethostbyaddr(ip)[0]
            except Exception:
                continue
            self.tm.add_host(ip=ip, hostname=name)
            self.log.debug(f"PTR {ip} -> {name}")

    # ------------------------------------------------------------------
    # Orchestration

    def run(
        self,
        do_arp: bool = True,
        do_icmp: bool = True,
        do_tcp: bool = True,
    ) -> set[str]:
        scope = self._scope()
        if not scope:
            self.log.error("Empty scope after exclusions - aborting")
            return set()
        self.log.info(f"Scope: {len(scope)} IPs to probe")

        alive: set[str] = set()
        if do_arp:
            alive |= self.arp_scan()
        if do_icmp:
            alive |= self.ping_sweep(scope)
        if do_tcp:
            # Only probe IPs that did not answer earlier, to limit noise
            # and overall runtime.
            remaining = [ip for ip in scope if ip not in alive]
            alive |= self.tcp_ping(remaining)

        self._resolve_hostnames(alive)

        self.log.success(f"{len(alive)} live host(s) detected")
        return alive
