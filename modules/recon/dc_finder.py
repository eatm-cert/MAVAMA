"""Domain Controller identification.

Three sources of information are combined for maximum reliability:

1. **DNS SRV** - ``_ldap._tcp.dc._msdcs.<domain>`` publishes the
   canonical list of DCs for a domain. Requires knowing the domain name
   (provided via config, or inferred from an anonymous LDAP RootDSE).
2. **Anonymous LDAP RootDSE** - an anonymous bind on port 389 exposes
   ``defaultNamingContext``, ``dnsHostName`` and ``ldapServiceName``.
   This is the most direct way to confirm a host is a DC.
3. **NetBIOS** (``nmblookup``) - fallback/cross-check when LDAP is
   filtered: a ``<1C>`` code means Domain Controllers.
"""

from __future__ import annotations

import shutil
import socket
import subprocess

from core.logger import get_logger
from core.target_manager import TargetManager

try:
    import dns.resolver  # type: ignore

    _HAS_DNSPYTHON = True
except Exception:  # pragma: no cover
    _HAS_DNSPYTHON = False

try:
    from ldap3 import Server, Connection, ALL, ANONYMOUS  # type: ignore

    _HAS_LDAP3 = True
except Exception:  # pragma: no cover
    _HAS_LDAP3 = False


class DCFinder:
    def __init__(self, tm: TargetManager, domain: str | None = None, timeout: int = 3):
        self.tm = tm
        self.domain = (domain or "").lower() or None
        self.timeout = timeout
        self.log = get_logger()

    # ------------------------------------------------------------------
    # 1. DNS SRV

    def dns_srv_lookup(self, domain: str, dns_server: str | None = None) -> list[str]:
        if not _HAS_DNSPYTHON:
            self.log.warn("dnspython not available - DNS SRV skipped")
            return []

        qname = f"_ldap._tcp.dc._msdcs.{domain}"
        self.log.action(f"DNS SRV {qname}")
        resolver = dns.resolver.Resolver()
        if dns_server:
            resolver.nameservers = [dns_server]
        resolver.timeout = self.timeout
        resolver.lifetime = self.timeout * 2

        fqdns: list[str] = []
        try:
            answers = resolver.resolve(qname, "SRV")
        except Exception as exc:
            self.log.debug(f"SRV {qname} failed: {exc}")
            return []

        for rr in answers:
            target = str(rr.target).rstrip(".")
            fqdns.append(target)

        ips: list[str] = []
        for fqdn in fqdns:
            try:
                ip = socket.gethostbyname(fqdn)
            except Exception:
                continue
            ips.append(ip)
            host = self.tm.add_host(ip=ip, hostname=fqdn, is_dc=True, domain=domain)
            host.tags.append("dc")
            self.log.success(f"DC via DNS -> {fqdn} ({ip})")
        return ips

    # ------------------------------------------------------------------
    # 2. Anonymous LDAP RootDSE

    def ldap_rootdse(self, ip: str) -> dict | None:
        if not _HAS_LDAP3:
            return None
        try:
            server = Server(ip, get_info=ALL, connect_timeout=self.timeout)
            conn = Connection(
                server,
                authentication=ANONYMOUS,
                auto_bind=True,
                receive_timeout=self.timeout,
            )
        except Exception as exc:
            self.log.debug(f"LDAP {ip} failed: {exc}")
            return None

        info = server.info
        conn.unbind()
        if info is None:
            return None

        naming = info.naming_contexts or []
        other = info.other or {}

        # Prefer the authoritative ``defaultNamingContext`` attribute: it names
        # the DC's own domain. Falling back to "first dc=* in namingContexts" is
        # WRONG because RootDSE also advertises the application partitions
        # (DC=ForestDnsZones,... / DC=DomainDnsZones,...) and their order is not
        # guaranteed - picking one yields a bogus realm (e.g.
        # forestdnszones.north.sevenkingdoms.local) that then breaks Kerberos
        # user enumeration with KDC_ERR_WRONG_REALM.
        def _nc_to_domain(nc: str) -> str:
            parts = [p.split("=", 1)[1] for p in nc.split(",") if p.lower().startswith("dc=")]
            return ".".join(parts).lower()

        default_nc = ""
        if isinstance(other, dict):
            raw_default = other.get("defaultNamingContext") or other.get("defaultnamingcontext") or []
            if raw_default:
                default_nc = raw_default[0] if isinstance(raw_default, list) else str(raw_default)

        if not default_nc:
            # Fallback: first real domain NC, explicitly skipping the DNS
            # application partitions and the config/schema contexts.
            for nc in naming:
                low = nc.lower()
                if low.startswith("dc=") and "dc=forestdnszones," not in low and "dc=domaindnszones," not in low:
                    default_nc = nc
                    break

        domain = _nc_to_domain(default_nc) if default_nc else ""

        dns_host = ""
        if isinstance(other, dict):
            raw = other.get("dnsHostName") or other.get("dNSHostName") or []
            if raw:
                dns_host = raw[0] if isinstance(raw, list) else str(raw)

        return {
            "domain": domain,
            "naming_contexts": list(naming),
            "dns_host": dns_host.lower(),
        }

    def identify_dc_by_ldap(self, ip: str) -> bool:
        host = self.tm.get_host(ip)
        if host is None:
            return False
        if not host.has_port(389) and not host.has_port(636):
            return False

        data = self.ldap_rootdse(ip)
        if not data:
            return False

        host.is_dc = True
        host.domain = data["domain"] or host.domain
        if data["dns_host"]:
            host.hostname = data["dns_host"]
        if data["domain"]:
            self.tm.add_domain(data["domain"], naming_contexts=data["naming_contexts"])
            if self.domain is None:
                self.domain = data["domain"]
        if "dc" not in host.tags:
            host.tags.append("dc")
        self.log.success(
            f"DC confirmed via LDAP: {ip} (domain={host.domain or 'n/a'})"
        )
        return True

    # ------------------------------------------------------------------
    # 3. NetBIOS (nmblookup)

    def netbios_lookup(self, ip: str) -> bool:
        tool = shutil.which("nmblookup")
        if not tool:
            return False
        cmd = [tool, "-A", ip]
        self.log.action(f"nmblookup: {' '.join(cmd)}")
        self.tm.record_command(
            cmd, phase="Phase 1 - Reconnaissance", tool="nmblookup", target=ip,
        )
        try:
            res = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout + 2,
            )
        except Exception:
            return False
        out = res.stdout
        is_dc = False
        for line in out.splitlines():
            line = line.strip()
            if not line:
                continue
            # Example: "LAB             <1C> -         <GROUP>"
            if "<1C>" in line:
                is_dc = True
                parts = line.split()
                if parts:
                    domain = parts[0].lower()
                    if domain:
                        host = self.tm.add_host(ip=ip, domain=domain, is_dc=True)
                        if "dc" not in host.tags:
                            host.tags.append("dc")
                        self.tm.add_domain(domain)
                        self.log.success(f"DC confirmed via NetBIOS: {ip} ({domain})")
        return is_dc

    # ------------------------------------------------------------------
    # Public entrypoint

    def run(self, dns_server: str | None = None) -> list[str]:
        identified: set[str] = set()

        # 1) If the domain is known (from config or inferred), try SRV.
        if self.domain:
            for ip in self.dns_srv_lookup(self.domain, dns_server=dns_server):
                identified.add(ip)

        # 2) LDAP anonymous bind on every host exposing 389/636.
        for host in self.tm.alive_hosts():
            if host.has_port(389) or host.has_port(636):
                if self.identify_dc_by_ldap(host.ip):
                    identified.add(host.ip)

        # 3) NetBIOS fallback on hosts exposing 139/445.
        for host in self.tm.alive_hosts():
            if host.ip in identified:
                continue
            if host.has_port(445) or host.has_port(139):
                if self.netbios_lookup(host.ip):
                    identified.add(host.ip)

        self.log.info(f"{len(identified)} DC(s) identified")

        # 4) If the domain is now known but was missing when we tried the
        # initial SRV lookup, retry it to catch any DC outside the scope.
        if self.domain and not any(
            ip for ip in identified if self.tm.get_host(ip) and self.tm.get_host(ip).domain == self.domain
        ):
            self.dns_srv_lookup(self.domain, dns_server=dns_server)

        return sorted(identified)
