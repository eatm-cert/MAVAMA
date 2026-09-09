"""Anonymous enumeration - leveraging unauthenticated access.

Vectors:

- **SMB null session**: anonymous connection to list shares.
- **LDAP anonymous bind**: retrieves domain information.
- **RID bruteforce**: translate SIDs into usernames via anonymous SAMR.
- **Zerologon** (CVE-2020-1472): probe Netlogon with zeroed credentials.
- **EternalBlue** (MS17-010): nmap SMBv1 vulnerability fingerprint.
- **PrintNightmare** (CVE-2021-1675): probe spoolss pipe accessibility.
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path

from core.logger import get_logger
from core.target_manager import Finding, TargetManager

try:
    from impacket.smbconnection import SMBConnection, SessionError  # type: ignore
    from impacket.dcerpc.v5 import transport, samr                 # type: ignore
    from impacket.dcerpc.v5.rpcrt import DCERPCException           # type: ignore

    _HAS_IMPACKET = True
except Exception:  # pragma: no cover
    _HAS_IMPACKET = False

try:
    from impacket.dcerpc.v5 import nrpc  # type: ignore
    _HAS_NRPC = True
except Exception:  # pragma: no cover
    _HAS_NRPC = False

try:
    from ldap3 import Server, Connection, ALL, ANONYMOUS, SIMPLE, SUBTREE  # type: ignore

    _HAS_LDAP3 = True
except Exception:  # pragma: no cover
    _HAS_LDAP3 = False


# LDAP bind result codes (RFC 4511).
LDAP_SUCCESS = 0
LDAP_STRONGER_AUTH_REQUIRED = 8
LDAP_INVALID_CREDENTIALS = 49


class AnonEnum:
    def __init__(
        self,
        tm: TargetManager,
        rid_range: tuple[int, int] = (500, 1500),
        timeout: int = 5,
    ):
        self.tm = tm
        self.rid_range = rid_range
        self.timeout = timeout
        self.log = get_logger()

    # ==================================================================
    # SMB null session
    # ==================================================================

    def smb_null_session(self, ip: str) -> None:
        if not _HAS_IMPACKET:
            return
        host = self.tm.get_host(ip)
        if host is None or not host.has_port(445):
            return

        self.log.action(f"SMB null session -> {ip}")
        try:
            smb = SMBConnection(ip, ip, timeout=self.timeout)
            smb.login("", "")
        except SessionError as exc:
            self.log.debug(f"SMB null {ip} refused: {exc}")
            # [MODIF] – explicit "resistant" notice when null session is denied.
            self.log.no_result(f"{ip}: SMB null session denied — system appears resistant")
            return
        except Exception as exc:
            self.log.debug(f"SMB null {ip} failed: {exc}")
            return

        self.log.success(f"{ip}: SMB null session allowed")
        host.tags.append("smb-null-session")
        self.tm.add_finding(
            Finding(
                id=f"SMB-NULL-{ip}",
                title="SMB null session allowed",
                severity="medium",
                host=ip,
                description="Host allows anonymous SMB authentication.",
                remediation="Set RestrictAnonymous=1 and disable unnecessary shares.",
                auth_context="anonymous",
                command=f"nxc smb {ip} -u '' -p '' --shares",
            )
        )

        # Server info. SMB is authoritative for the hostname (NetBIOS
        # computer name) - it must override any earlier PTR DNS value.
        try:
            if not host.os:
                host.os = smb.getServerOS() or host.os
            srv_name = smb.getServerName()
            if srv_name:
                host.hostname = srv_name
            if not host.domain:
                host.domain = smb.getServerDomain() or host.domain
        except Exception:
            pass

        # Share listing.
        try:
            shares = smb.listShares()
        except Exception as exc:
            self.log.debug(f"listShares failed: {exc}")
            shares = []

        for sh in shares:
            name = sh["shi1_netname"][:-1]
            remark = sh["shi1_remark"][:-1]
            readable = False
            try:
                smb.listPath(name, "\\*")
                readable = True
            except Exception:
                readable = False
            entry = {"name": name, "remark": remark, "readable_anon": readable}
            host.shares.append(entry)
            tag = "R" if readable else "-"
            self.log.info(f"  [{tag}] \\\\{ip}\\{name}  ({remark})")
            if readable and name.upper() not in ("IPC$", "PRINT$"):
                self.tm.add_finding(
                    Finding(
                        id=f"SMB-READ-{ip}-{name}",
                        title=f"Anonymously readable SMB share: {name}",
                        severity="high",
                        host=ip,
                        description=f"Share \\\\{ip}\\{name} is readable without authentication.",
                        remediation="Restrict share ACLs (remove Anonymous/Everyone access).",
                        auth_context="anonymous",
                    )
                )

        try:
            smb.close()
        except Exception:
            pass

    # ==================================================================
    # LDAP anonymous bind
    # ==================================================================

    def ldap_anonymous_bind(self, ip: str) -> None:
        if not _HAS_LDAP3:
            return
        host = self.tm.get_host(ip)
        if host is None or not host.has_port(389):
            return

        self.log.action(f"LDAP anonymous bind -> {ip}")
        try:
            server = Server(ip, get_info=ALL, connect_timeout=self.timeout)
            conn = Connection(
                server, authentication=ANONYMOUS, auto_bind=True,
                receive_timeout=self.timeout,
            )
        except Exception as exc:
            self.log.debug(f"Anon bind failed on {ip}: {exc}")
            # [MODIF] – explicit "resistant" notice when anonymous bind is rejected.
            self.log.no_result(f"{ip}: LDAP anonymous bind rejected — system appears resistant")
            return

        info = server.info
        if info is None:
            conn.unbind()
            # [MODIF] – server accepted the bind but returned no RootDSE info.
            self.log.no_result(f"{ip}: LDAP anonymous bind — no server info returned")
            return

        self.log.success(f"{ip}: LDAP anonymous bind accepted")
        host.tags.append("ldap-anon-bind")
        naming = list(info.naming_contexts or [])

        # Attempt to read a base (often denied but sometimes allowed on
        # misconfigured environments).
        read_ok = False
        base = next((n for n in naming if n.lower().startswith("dc=")), None)
        if base:
            try:
                conn.search(
                    search_base=base,
                    search_filter="(objectClass=user)",
                    search_scope=SUBTREE,
                    attributes=["sAMAccountName"],
                    size_limit=5,
                    time_limit=self.timeout,
                )
                read_ok = bool(conn.entries)
                if read_ok:
                    for entry in conn.entries:
                        sam = str(entry.sAMAccountName)
                        self.tm.add_user(sam)
            except Exception:
                read_ok = False

        severity = "high" if read_ok else "low"
        self.tm.add_finding(
            Finding(
                id=f"LDAP-ANON-{ip}",
                title="LDAP anonymous bind allowed",
                severity=severity,
                host=ip,
                description=(
                    "Domain controller allows anonymous LDAP bind. "
                    + ("Reading domain objects is also possible." if read_ok else "")
                ),
                remediation=(
                    "Enable 'LDAP server signing requirements = Require signing' "
                    "and disable anonymous authentication."
                ),
                auth_context="anonymous",
                command=f"ldapsearch -x -H ldap://{ip} -s base -b '' namingContexts",
            )
        )
        conn.unbind()

    # ==================================================================
    # LDAP signing probe
    # ==================================================================

    def ldap_signing_probe(self, ip: str) -> None:
        """Infer whether the DC requires LDAP signing.

        Method: issue an LDAP simple bind with dummy credentials on plain
        port 389 and interpret the server's response code:

        - ``strongerAuthRequired`` (8)   -> signing required (bind refused
          at protocol layer because integrity was not negotiated).
        - ``invalidCredentials`` (49)    -> signing NOT required (server is
          willing to evaluate the credentials, which means it would also
          accept an unsigned NTLM relay bind).
        - ``success`` (0) (unexpected)   -> also treated as not required.

        When signing is not required, a finding is emitted so Phase 2 can
        target the DC for LDAP NTLM relay.
        """
        if not _HAS_LDAP3:
            return
        host = self.tm.get_host(ip)
        if host is None or not host.has_port(389):
            return

        self.log.action(f"LDAP signing probe -> {ip}")

        conn = None
        code: int | None = None
        try:
            server = Server(ip, port=389, get_info=None, connect_timeout=self.timeout)
            conn = Connection(
                server,
                user="cn=ldap-signing-probe,dc=invalid",
                password="invalid",
                authentication=SIMPLE,
                auto_bind=False,
                raise_exceptions=False,
                receive_timeout=self.timeout,
            )
            conn.open()
            conn.bind()
            code = conn.result.get("result") if conn.result else None
        except Exception as exc:
            self.log.debug(f"LDAP signing probe error on {ip}: {exc}")
            return
        finally:
            if conn is not None:
                try:
                    conn.unbind()
                except Exception:
                    pass

        if code == LDAP_STRONGER_AUTH_REQUIRED:
            host.ldap_signing = "required"
            self.log.info(f"{ip}: LDAP signing required (bind rejected: code 8)")
            return

        if code in (LDAP_SUCCESS, LDAP_INVALID_CREDENTIALS):
            host.ldap_signing = "not-required"
            self.tm.add_finding(
                Finding(
                    id=f"LDAP-SIGN-{ip}",
                    title="LDAP signing not enforced",
                    severity="medium",
                    host=ip,
                    description=(
                        "Domain controller accepts unsigned LDAP binds "
                        f"(bind returned code {code}). Combined with a "
                        "coerced authentication, this enables NTLM relay "
                        "attacks against LDAP (RBCD, Shadow Credentials)."
                    ),
                    remediation=(
                        "Set 'Domain controller: LDAP server signing "
                        "requirements' to 'Require signing' via GPO."
                    ),
                    auth_context="anonymous",
                    command=f"nxc ldap {ip} -u '' -p '' -M ldap-checker",
                )
            )
            self.log.finding(
                f"{ip}: LDAP signing NOT required -> LDAP relay target"
            )
            return

        self.log.debug(
            f"{ip}: LDAP signing probe inconclusive (result code {code!r})"
        )

    # ==================================================================
    # RID bruteforce via SAMR
    # ==================================================================

    def rid_bruteforce(self, ip: str) -> list[dict]:
        """Translate RIDs [start..end] into names via SAMR.

        Method: anonymous SAMR open -> SamrConnect -> SamrOpenDomain ->
        SamrLookupIdsInDomain. Works on many pre-2012 Windows Servers and
        on GOAD when RestrictAnonymous == 0.
        """
        if not _HAS_IMPACKET:
            return []
        host = self.tm.get_host(ip)
        if host is None or not host.has_port(445):
            return []

        self.log.action(f"RID bruteforce {ip} [{self.rid_range[0]}-{self.rid_range[1]}]")

        try:
            rpctransport = transport.SMBTransport(ip, 445, r"\samr", "", "")
            rpctransport.set_connect_timeout(self.timeout)
            dce = rpctransport.get_dce_rpc()
            dce.connect()
            dce.bind(samr.MSRPC_UUID_SAMR)
        except Exception as exc:
            self.log.debug(f"SAMR bind failed on {ip}: {exc}")
            return []

        try:
            server_handle = samr.hSamrConnect(dce)["ServerHandle"]
            domains = samr.hSamrEnumerateDomainsInSamServer(dce, server_handle)[
                "Buffer"
            ]["Buffer"]
            # The first "Builtin" domain is ignored, pick the next one.
            domain_name = None
            for d in domains:
                name = d["Name"]
                if name.lower() != "builtin":
                    domain_name = name
                    break
            if domain_name is None:
                dce.disconnect()
                return []

            domain_sid = samr.hSamrLookupDomainInSamServer(dce, server_handle, domain_name)[
                "DomainId"
            ]
            domain_handle = samr.hSamrOpenDomain(
                dce, server_handle, domainId=domain_sid
            )["DomainHandle"]
        except Exception as exc:
            self.log.debug(f"SAMR open domain failed: {exc}")
            try:
                dce.disconnect()
            except Exception:
                pass
            return []

        results: list[dict] = []
        start, end = self.rid_range
        # Query in batches of 100 to limit round-trips.
        batch = 100
        for chunk_start in range(start, end + 1, batch):
            rids = list(range(chunk_start, min(chunk_start + batch, end + 1)))
            try:
                resp = samr.hSamrLookupIdsInDomain(dce, domain_handle, rids)
            except DCERPCException as exc:
                if "STATUS_NONE_MAPPED" in str(exc):
                    continue
                self.log.debug(f"SAMR lookup failed (rid {chunk_start}): {exc}")
                continue
            except Exception as exc:
                self.log.debug(f"SAMR lookup failed (rid {chunk_start}): {exc}")
                continue

            names = resp["Names"]["Element"]
            types = resp["Use"]["Element"]
            for i, rid in enumerate(rids):
                if i >= len(names):
                    break
                raw = names[i].get("Data") if isinstance(names[i], dict) else names[i]["Data"]
                name = str(raw) if raw else ""
                if not name:
                    continue
                type_id = types[i]
                kind = {
                    samr.SID_NAME_USE.SidTypeUser: "user",
                    samr.SID_NAME_USE.SidTypeGroup: "group",
                    samr.SID_NAME_USE.SidTypeAlias: "alias",
                    samr.SID_NAME_USE.SidTypeWellKnownGroup: "wellknown",
                }.get(type_id, "other")
                entry = {"rid": rid, "name": name, "type": kind}
                results.append(entry)
                if kind == "user":
                    self.tm.add_user(name)

        try:
            dce.disconnect()
        except Exception:
            pass

        if results:
            host.rid_users = results
            self.log.success(f"{ip}: RID brute -> {len(results)} entr(y/ies) retrieved")
            self.tm.add_finding(
                Finding(
                    id=f"RID-BRUTE-{ip}",
                    title="Anonymous SAMR RID bruteforce possible",
                    severity="medium",
                    host=ip,
                    description=(
                        "SAMR service accepts anonymous queries and exposes "
                        f"the list of users/groups ({len(results)} objects)."
                    ),
                    remediation=(
                        "Set RestrictAnonymousSAM=1 and RestrictAnonymous=1 in "
                        "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa."
                    ),
                    auth_context="anonymous",
                    command=f"nxc smb {ip} -u '' -p '' --rid-brute",
                )
            )
        else:
            # [MODIF] – upgrade to no_result for consistent "resistant" messaging.
            self.log.no_result(f"{ip}: RID brute returned nothing — anonymous SAMR denied")
        return results

    # ==================================================================
    # Unauthenticated vulnerability checks
    # ==================================================================

    def zerologon_check(self, ip: str) -> None:
        """Detect CVE-2020-1472 (Zerologon) — detection only, no exploitation.

        Probes the Netlogon service with zeroed client credentials up to
        MAX_ATTEMPTS times. AES-CFB8 with an all-zero IV produces an all-zero
        ciphertext with probability 1/256, so ~256 attempts gives ~63%
        detection probability without resetting any password or causing damage.
        """
        if not _HAS_NRPC or not _HAS_IMPACKET:
            self.log.debug(f"zerologon: impacket nrpc unavailable, skipping {ip}")
            return

        host = self.tm.get_host(ip) or self.tm.add_host(ip)
        dc_name = (host.hostname or "").split(".")[0] or "DC"
        MAX_ATTEMPTS = 256

        self.log.action(f"Zerologon probe -> {ip} (up to {MAX_ATTEMPTS} attempts)")
        try:
            binding = f"ncacn_np:{ip}[\\PIPE\\netlogon]"
            rpc_transport = transport.DCERPCTransportFactory(binding)
            rpc_transport.set_connect_timeout(self.timeout)
            dce = rpc_transport.get_dce_rpc()
            dce.connect()
            dce.bind(nrpc.MSRPC_UUID_NRPC)

            for _ in range(MAX_ATTEMPTS):
                # Fresh challenge per attempt.
                req = nrpc.NetrServerReqChallenge()
                req["PrimaryName"] = "\x00"
                req["ComputerName"] = "test\x00"
                req["ClientChallenge"] = b"\x00" * 8
                try:
                    dce.request(req)
                except Exception:
                    break

                auth = nrpc.NetrServerAuthenticate3()
                auth["PrimaryName"] = "\x00"
                auth["AccountName"] = dc_name + "$\x00"
                auth["SecureChannelType"] = nrpc.NETLOGON_SECURE_CHANNEL_TYPE.ServerSecureChannel
                auth["ComputerName"] = "test\x00"
                auth["ClientCredential"] = b"\x00" * 8
                auth["NegotiateFlags"] = 0x212FFFFF
                try:
                    dce.request(auth)
                    # Server accepted zeroed credentials → VULNERABLE.
                    dce.disconnect()
                    self.log.finding(f"[ZEROLOGON] {ip}: VULNERABLE (CVE-2020-1472)")
                    host.tags.append("zerologon-vulnerable")
                    self.tm.add_finding(Finding(
                        id=f"ZEROLOGON-{ip}",
                        title="Zerologon — unauthenticated domain takeover (CVE-2020-1472)",
                        severity="critical",
                        host=ip,
                        description=(
                            "The Netlogon service (MS-NRPC) accepted zeroed authentication "
                            "credentials. An unauthenticated attacker can reset the DC machine "
                            "account password and gain full domain control via DCSync. "
                            "No credentials required."
                        ),
                        remediation=(
                            "Apply the August 2020 security update (KB4565349 / KB4571694 "
                            "depending on OS version). Enable Netlogon enforcement mode: "
                            "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters\\"
                            "FullSecureChannelProtection = 1."
                        ),
                        evidence=f"NetrServerAuthenticate3 accepted zeroed credentials on {ip}",
                        auth_context="anonymous",
                    ))
                    return
                except Exception:
                    continue

            try:
                dce.disconnect()
            except Exception:
                pass
            # [MODIF] – upgrade to no_result for consistent "resistant" messaging.
            self.log.no_result(f"{ip}: Zerologon — not vulnerable (zeroed auth rejected)")

        except Exception as exc:
            self.log.debug(f"zerologon probe failed on {ip}: {exc}")

    # ------------------------------------------------------------------

    def eternalblue_check(self, ip: str) -> None:
        """Detect MS17-010 (EternalBlue) via the nmap smb-vuln-ms17-010 script."""
        nmap_bin = shutil.which("nmap")
        if not nmap_bin:
            self.log.debug(f"eternalblue: nmap not found, skipping {ip}")
            return

        self.log.action(f"EternalBlue probe -> {ip} (nmap smb-vuln-ms17-010)")
        with tempfile.TemporaryDirectory() as tmp:
            out_xml = str(Path(tmp) / "ms17010.xml")
            cmd = [
                nmap_bin, "-Pn", "-n", "-p", "445",
                "--script", "smb-vuln-ms17-010",
                "--script-timeout", "10s",
                "-oX", out_xml,
                ip,
            ]
            self.tm.record_command(
                cmd, phase="Phase 1 - Reconnaissance", tool="nmap", target=ip,
            )
            try:
                proc = subprocess.run(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    stdin=subprocess.DEVNULL,
                    text=True,
                    timeout=30,
                )
                output = proc.stdout + proc.stderr
            except Exception as exc:
                self.log.debug(f"eternalblue nmap failed on {ip}: {exc}")
                return

        output_lower = output.lower()
        if "vulnerable" in output_lower and "not vulnerable" not in output_lower:
            self.log.finding(f"[ETERNALBLUE] {ip}: VULNERABLE (MS17-010)")
            host = self.tm.get_host(ip) or self.tm.add_host(ip)
            host.tags.append("eternalblue-vulnerable")
            self.tm.add_finding(Finding(
                id=f"ETERNALBLUE-{ip}",
                title="EternalBlue — unauthenticated RCE via SMBv1 (MS17-010)",
                severity="critical",
                host=ip,
                description=(
                    "SMBv1 is enabled and the host is vulnerable to MS17-010 "
                    "(EternalBlue). An unauthenticated attacker can achieve remote "
                    "code execution as SYSTEM. This vulnerability was used by WannaCry "
                    "and NotPetya ransomware."
                ),
                remediation=(
                    "Apply MS17-010 (KB4012212 / KB4012215 depending on OS). "
                    "Disable SMBv1: Set-SmbServerConfiguration -EnableSMB1Protocol $false. "
                    "Block TCP/445 at the perimeter."
                ),
                evidence="nmap smb-vuln-ms17-010 reported VULNERABLE",
                auth_context="anonymous",
            ))
        elif "not vulnerable" in output_lower or proc.returncode == 0:
            # [MODIF] – upgrade to no_result for consistent "resistant" messaging.
            self.log.no_result(f"{ip}: EternalBlue — not vulnerable (MS17-010)")
        else:
            self.log.debug(f"{ip}: EternalBlue — inconclusive (nmap rc={proc.returncode})")

    # ------------------------------------------------------------------

    def printnightmare_check(self, ip: str) -> None:
        """Detect PrintNightmare (CVE-2021-1675 / CVE-2021-34527).

        Probes whether the Print Spooler service is accessible via the
        \\PIPE\\spoolss named pipe through an anonymous SMB session.
        An accessible spoolss on a DC is the necessary precondition for
        PrintNightmare exploitation.
        """
        if not _HAS_IMPACKET:
            self.log.debug(f"printnightmare: impacket not available, skipping {ip}")
            return

        self.log.action(f"PrintNightmare probe -> {ip} (\\PIPE\\spoolss)")
        try:
            smb = SMBConnection(ip, ip, timeout=self.timeout)
            smb.login("", "")   # anonymous / null session
            tid = smb.connectTree("IPC$")
            try:
                fid = smb.openFile(
                    tid, "\\spoolss",
                    desiredAccess=0x00120089,   # FILE_READ_DATA | SYNCHRONIZE
                    creationOption=0x00000060,  # non-directory
                    creationDisposition=0x00000001,  # OPEN_EXISTING
                )
                smb.closeFile(tid, fid)
                spooler_accessible = True
            except Exception:
                spooler_accessible = False
            smb.logoff()

            if spooler_accessible:
                self.log.finding(f"[PRINTNIGHTMARE] {ip}: Print Spooler accessible anonymously")
                host = self.tm.get_host(ip) or self.tm.add_host(ip)
                host.tags.append("spooler-exposed")
                self.tm.add_finding(Finding(
                    id=f"PRINTNIGHTMARE-{ip}",
                    title="PrintNightmare — Print Spooler exposed (CVE-2021-1675)",
                    severity="high",
                    host=ip,
                    description=(
                        "The Print Spooler service (\\PIPE\\spoolss) is accessible via "
                        "anonymous SMB. Combined with CVE-2021-1675 / CVE-2021-34527, "
                        "a low-privileged user can load an arbitrary DLL as SYSTEM. "
                        "On Domain Controllers this leads to full domain compromise."
                    ),
                    remediation=(
                        "Apply KB5004945 (July 2021) or later. "
                        "Disable the Print Spooler service on all DCs and servers "
                        "that do not need printing: Stop-Service Spooler; "
                        "Set-Service Spooler -StartupType Disabled."
                    ),
                    evidence=f"\\\\{ip}\\IPC$\\spoolss opened successfully via null session",
                    auth_context="anonymous",
                ))
            else:
                # [MODIF] – upgrade to no_result for consistent "resistant" messaging.
                self.log.no_result(f"{ip}: PrintNightmare — Print Spooler not accessible anonymously")

        except Exception as exc:
            self.log.debug(f"printnightmare probe failed on {ip}: {exc}")

    # ==================================================================
    # Public entrypoint
    # ==================================================================

    def run(
        self,
        do_smb: bool = True,
        do_ldap: bool = True,
        do_rid: bool = True,
        do_vuln_checks: bool = True,
    ) -> None:
        phase = "Phase 1 - Reconnaissance"
        for host in self.tm.alive_hosts():
            if do_smb and host.has_port(445):
                self.tm.record_activity(
                    "smb-null-session", host.ip, phase=phase,
                    details="anonymous SMB session + share enumeration",
                )
                self.smb_null_session(host.ip)
            if do_ldap and (host.has_port(389) or host.has_port(636)):
                self.tm.record_activity(
                    "ldap-anon-bind", host.ip, phase=phase,
                    port=636 if not host.has_port(389) else 389,
                    details="anonymous LDAP bind + RootDSE/subtree read",
                )
                self.ldap_anonymous_bind(host.ip)
                if host.has_port(389):
                    self.ldap_signing_probe(host.ip)
            if do_rid and host.has_port(445):
                self.tm.record_activity(
                    "rid-brute", host.ip, phase=phase,
                    details="SAMR/LSA RID cycling to resolve account names",
                )
                self.rid_bruteforce(host.ip)
            if do_vuln_checks and host.is_dc:
                if host.has_port(445):
                    for cve, label in (
                        ("CVE-2020-1472", "Zerologon"),
                        ("MS17-010", "EternalBlue"),
                        ("CVE-2021-34527", "PrintNightmare"),
                    ):
                        self.tm.record_activity(
                            "vuln-scan", host.ip, phase=phase, port=445, protocol="smb",
                            details=f"detection-only {label} ({cve}) check",
                        )
                    self.zerologon_check(host.ip)
                    self.eternalblue_check(host.ip)
                    self.printnightmare_check(host.ip)
