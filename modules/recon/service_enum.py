"""Service enumeration on live hosts.

Relies on ``nmap`` (XML output) to:

- scan a set of relevant AD ports;
- identify services and versions (``-sV``);
- evaluate **SMB signing** (NSE ``smb2-security-mode``), which is critical
  for Phase 2 (NTLM relay);
- extract LDAP RootDSE and TLS certificate data.

Results flow into the ``TargetManager``: every detected service becomes a
``Service`` attached to its ``Host``. Hosts with SMB signing disabled are
tagged ``relay-target-smb`` and emit a "SMB signing disabled" finding.
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

from core.logger import get_logger
from core.target_manager import CertificateAuthority, Finding, TargetManager


# Human-readable labels per port for display/reporting.
AD_PORT_NAMES: dict[int, str] = {
    53: "dns",
    88: "kerberos",
    135: "msrpc",
    139: "netbios-ssn",
    389: "ldap",
    445: "smb",
    464: "kpasswd",
    636: "ldaps",
    593: "rpc-http",
    1433: "mssql",
    3268: "gc-ldap",
    3269: "gc-ldaps",
    3389: "rdp",
    5985: "winrm",
    5986: "winrm-tls",
    8080: "http-alt",
    8443: "https-alt",
    80: "http",
    443: "https",
}


class ServiceEnum:
    # HTTP(S) ports where ADCS Web Enrollment (ESC8) can live; always scanned.
    ADCS_WEB_PORTS: frozenset[int] = frozenset({80, 443, 8443})

    def __init__(
        self,
        tm: TargetManager,
        ports: list[int] | None = None,
        rate: int = 1000,
        timeout: int = 300,
        stealth_mode: bool = False,
    ):
        self.tm = tm
        # ESC8 (NTLM relay to ADCS web enrollment) needs the CA's HTTP endpoint
        # to be discovered. Always scan the ADCS web ports even when a config's
        # port list omits them, otherwise Phase 2 can never find an ESC8 target.
        requested = ports or list(AD_PORT_NAMES.keys())
        self.ports = sorted(set(requested) | self.ADCS_WEB_PORTS)
        self.rate = rate
        self.timeout = timeout
        self.stealth_mode = stealth_mode
        self.log = get_logger()
        self.nmap_bin = shutil.which("nmap")

    # ------------------------------------------------------------------
    # nmap pipeline

    def _build_nmap_cmd(self, targets: list[str], xml_out: Path) -> list[str]:
        ports_csv = ",".join(str(p) for p in self.ports)
        scripts = ",".join(
            [
                "smb2-security-mode",
                "smb-security-mode",
                "smb-os-discovery",
                "ldap-rootdse",
                "rdp-ntlm-info",
                "ssl-cert",
                "ms-sql-info",
                "http-title",
            ]
        )
        cmd = [
            self.nmap_bin,
            "-Pn",
            "-n",
            "-sT",              # TCP connect: works without root.
            "-sV",
            "--version-intensity", "5",
            "-p", ports_csv,
            "--script", scripts,
        ]
        if self.stealth_mode:
            # Stealth: slow timing to reduce log noise on monitored networks.
            cmd += ["-T2"]
        else:
            cmd += ["--min-rate", str(self.rate)]
        cmd += ["--open", "-oX", str(xml_out), *targets]
        return cmd

    def _parse_nmap_xml(self, xml_path: Path) -> None:
        tree = ET.parse(xml_path)
        root = tree.getroot()
        for host_el in root.findall("host"):
            status = host_el.find("status")
            if status is None or status.get("state") != "up":
                continue
            addr_el = host_el.find("address[@addrtype='ipv4']")
            if addr_el is None:
                continue
            ip = addr_el.get("addr", "")
            if not ip:
                continue

            host = self.tm.add_host(ip=ip)

            hn_el = host_el.find("hostnames/hostname")
            if hn_el is not None and not host.hostname:
                host.hostname = hn_el.get("name", "")

            os_el = host_el.find("os/osmatch")
            if os_el is not None and not host.os:
                host.os = os_el.get("name", "")

            # Aggregate host-level scripts.
            for hs in host_el.findall("hostscript/script"):
                self._consume_script(host, port=None, script=hs)

            # Ports + services.
            for port_el in host_el.findall("ports/port"):
                state = port_el.find("state")
                if state is None or state.get("state") != "open":
                    continue
                port_num = int(port_el.get("portid", "0"))
                proto = port_el.get("protocol", "tcp")

                svc = port_el.find("service")
                name = svc.get("name") if svc is not None else AD_PORT_NAMES.get(port_num, "")
                product = svc.get("product", "") if svc is not None else ""
                version = svc.get("version", "") if svc is not None else ""
                banner = " ".join(x for x in (product, version) if x).strip()

                host.add_service(port=port_num, name=name or "", banner=banner)
                # Service-level scripts.
                for scr in port_el.findall("script"):
                    self._consume_script(host, port=port_num, script=scr)

    # ------------------------------------------------------------------
    # NSE script output handling

    def _consume_script(self, host, port: int | None, script: ET.Element) -> None:
        sid = script.get("id", "")
        output = script.get("output", "") or ""

        if sid in ("smb2-security-mode", "smb-security-mode") and port in (None, 445, 139):
            signing = self._parse_smb_signing(output)
            if signing:
                host.smb_signing = signing
                self._emit_signing_finding(host, signing)

        elif sid == "ldap-rootdse" and port in (None, 389, 636, 3268, 3269):
            domain, dns_name = self._parse_rootdse(output)
            if domain:
                host.domain = domain
                self.tm.add_domain(domain, dns=dns_name)
            # A host exposing LDAP + an AD namingContext is almost always a DC.
            host.is_dc = True
            self.log.debug(f"{host.ip} -> RootDSE domain={domain}")

        elif sid == "smb-os-discovery" and port in (None, 445):
            for line in output.splitlines():
                line = line.strip()
                if line.startswith("OS:") and not host.os:
                    host.os = line.split(":", 1)[1].strip()
                elif line.startswith("Computer name:"):
                    # SMB is authoritative - overrides any prior PTR DNS
                    # value (which, on AD-integrated DNS, often returns the
                    # domain FQDN rather than the host's shortname).
                    name = line.split(":", 1)[1].strip()
                    if name:
                        host.hostname = name
                elif line.startswith("Domain name:") and not host.domain:
                    dom = line.split(":", 1)[1].strip()
                    host.domain = dom
                    self.tm.add_domain(dom)

        elif sid == "rdp-ntlm-info" and port == 3389:
            for line in output.splitlines():
                line = line.strip()
                if line.startswith("DNS_Domain_Name:") and not host.domain:
                    host.domain = line.split(":", 1)[1].strip()

        elif sid == "ssl-cert":
            # A certificate on 443 with OU=AD Certificate Services is a
            # strong signal for ADCS Web Enrollment (ESC8).
            if port in (80, 443, 8443) and "Certificate Services" in output:
                self._mark_adcs(host, port)

        elif sid == "http-title" and port in (80, 443, 8080, 8443):
            title = output.strip().lower()
            if "certificate services" in title or "active directory certificate" in title:
                self._mark_adcs(host, port)

    @staticmethod
    def _parse_smb_signing(output: str) -> str | None:
        out = output.lower()
        if "message signing: required" in out or "signing enabled and required" in out:
            return "required"
        if "message signing: enabled" in out or "signing enabled but not required" in out:
            return "enabled"
        if "message signing: disabled" in out or "signing disabled" in out:
            return "disabled"
        return None

    @staticmethod
    def _parse_rootdse(output: str) -> tuple[str, str]:
        """Extract the domain from defaultNamingContext=DC=lab,DC=local."""
        domain = ""
        dns_name = ""
        for line in output.splitlines():
            line = line.strip()
            if "defaultNamingContext" in line or "rootDomainNamingContext" in line:
                # Possible format: "defaultNamingContext: DC=lab,DC=local"
                if "DC=" in line:
                    parts = [p.strip() for p in line.split("DC=")[1:]]
                    parts = [p.rstrip(",") for p in parts]
                    domain = ".".join(parts).lower()
            elif "dnsHostName" in line:
                dns_name = line.split(":", 1)[-1].strip().lower()
        return domain, dns_name

    def _emit_signing_finding(self, host, signing: str) -> None:
        if signing == "disabled":
            self.tm.add_finding(
                Finding(
                    id=f"SMB-SIGN-{host.ip}",
                    title="SMB signing disabled",
                    severity="high",
                    host=host.ip,
                    description=(
                        "The host accepts SMB connections without requiring "
                        "signing. It is exploitable as an NTLM relay target "
                        "(Phase 2)."
                    ),
                    remediation=(
                        "Enable 'RequireSecuritySignature = 1' via GPO on "
                        "Windows servers (SMB signing required)."
                    ),
                    command=getattr(self, "_last_nmap_command", ""),
                )
            )
            host.tags.append("relay-target-smb")
            self.log.finding(f"{host.ip}: SMB signing DISABLED -> NTLM relay target")
        elif signing == "enabled":
            self.log.info(f"{host.ip}: SMB signing enabled (not required)")

    def _mark_adcs(self, host, port: int | None) -> None:
        """Tag the host as an ADCS server and register its CA in TM."""
        host.is_adcs = True
        if "adcs-web" not in host.tags:
            host.tags.append("adcs-web")
        scheme = "https" if port in (443, 8443) else "http"
        web_url = f"{scheme}://{host.ip}/certsrv"
        ca = CertificateAuthority(ip=host.ip, web_enrollment_url=web_url)
        self.tm.add_ca(ca)
        self.tm.add_finding(
            Finding(
                id=f"ADCS-WEB-{host.ip}",
                title=f"ADCS Web Enrollment detected on {host.ip}",
                severity="high",
                host=host.ip,
                description=(
                    f"Active Directory Certificate Services (ADCS) Web Enrollment "
                    f"is reachable at {web_url}. This endpoint is vulnerable to "
                    "ESC8 (NTLM relay to ADCS) when combined with coerced "
                    "authentication from a Domain Controller."
                ),
                remediation=(
                    "Enable Extended Protection for Authentication (EPA) on the "
                    "ADCS web enrollment endpoint; require HTTPS; restrict access "
                    "to authorized requestors only."
                ),
            )
        )
        self.log.finding(f"{host.ip}: ADCS Web Enrollment detected -> ESC8 candidate")

    # ------------------------------------------------------------------
    # Public entrypoint

    def run(self, hosts: list[str]) -> None:
        if not hosts:
            self.log.warn("No host to enumerate")
            return
        if not self.nmap_bin:
            self.log.error("nmap not found in PATH - enumeration impossible")
            return

        with tempfile.TemporaryDirectory() as tmp:
            xml_out = Path(tmp) / "scan.xml"
            cmd = self._build_nmap_cmd(hosts, xml_out)
            self._last_nmap_command = " ".join(cmd)
            self.log.action(f"nmap on {len(hosts)} host(s), {len(self.ports)} ports: {' '.join(cmd)}")
            self.tm.record_command(
                cmd, phase="Phase 1 - Reconnaissance", tool="nmap",
                target=f"{len(hosts)} host(s)",
            )

            try:
                proc = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=self.timeout,
                    check=False,
                )
            except subprocess.TimeoutExpired:
                self.log.error("nmap: timeout exceeded")
                return

            if proc.returncode != 0:
                self.log.error(f"nmap returned rc={proc.returncode}")
                self.log.debug(proc.stderr)
                return

            try:
                self._parse_nmap_xml(xml_out)
            except ET.ParseError as exc:
                self.log.error(f"nmap XML parse error: {exc}")
                return

        # Reliable ADCS Web Enrollment detection. nmap's http-title hits the
        # site root, which is usually the default IIS page - the CA lives at
        # /certsrv. Probe it directly on every host exposing an HTTP(S) port:
        # a real ADCS endpoint answers 401 Negotiate/NTLM. This is what unlocks
        # the ESC8 relay path when the DCs enforce SMB/LDAP signing.
        self._detect_adcs_web()

        # Summary.
        total_svc = sum(len(h.services) for h in self.tm.alive_hosts())
        self.log.success(
            f"Enumeration complete - {total_svc} service(s) identified"
        )

    def _detect_adcs_web(self) -> None:
        for host in self.tm.alive_hosts():
            if getattr(host, "is_adcs", False):
                continue  # already flagged by the nmap http-title/ssl-cert hit
            for port in sorted(self.ADCS_WEB_PORTS):
                if host.has_port(port) and self._probe_adcs_web(host.ip, port):
                    self._mark_adcs(host, port)
                    break

    @staticmethod
    def _probe_adcs_web(ip: str, port: int, timeout: int = 5) -> bool:
        """Return True if ``ip:port`` exposes ADCS Web Enrollment (/certsrv).

        A real CA answers the enrollment page with ``401`` +
        ``WWW-Authenticate: Negotiate``/``NTLM`` (Windows Integrated Auth), or a
        200 whose body names Certificate Services. Anything else (default IIS
        page, connection error) is not ADCS.
        """
        import ssl
        import urllib.error
        import urllib.request

        scheme = "https" if port in (443, 8443) else "http"
        url = f"{scheme}://{ip}:{port}/certsrv/certfnsh.asp"
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            resp = urllib.request.urlopen(url, timeout=timeout, context=ctx)
            body = resp.read(4096).decode("latin-1", "ignore").lower()
            return "certificate services" in body
        except urllib.error.HTTPError as exc:
            if exc.code == 401:
                auth = str(exc.headers.get("WWW-Authenticate", "")).lower()
                return "negotiate" in auth or "ntlm" in auth
            return False
        except Exception:
            return False
