"""MITRE ATT&CK mapping for the SOC detection-test activity log.

Every test the tool fires against the network is recorded as an
:class:`~core.target_manager.Activity` carrying *when*, *which source IP*,
*which target* and *which test*. To make those rows correlatable by a blue
team, each test is tagged with its MITRE ATT&CK technique - the lingua franca
SOC analysts use to map a detection back to an adversary behaviour.

This module is the single source of truth for that mapping. Instrumentation
sites pass a short, stable ``technique key`` (e.g. ``"kerberoast"``); the
catalog resolves it to the ATT&CK technique id, tactic and a human-readable
name, plus a sensible default tool/port/protocol the call site may override.

Keeping the mapping here (rather than scattered string literals across the
modules) means a reviewer can audit the whole TTP coverage in one place, and
the CSV the SOC ingests stays consistent regardless of which phase emitted the
row.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Technique:
    """An ATT&CK technique an emitted activity maps to.

    ``tool``, ``port`` and ``proto`` are *defaults* surfaced when the call
    site does not provide its own (many tests have one canonical tool/port);
    the recording API always lets the caller override them.
    """

    mitre_id: str
    tactic: str
    name: str
    tool: str = ""
    port: int | None = None
    proto: str = ""


# ---------------------------------------------------------------------------
# Catalog - keyed by the stable technique key used at instrumentation sites.
# ---------------------------------------------------------------------------

_CATALOG: dict[str, Technique] = {
    # --- Phase 1 - reconnaissance / discovery ------------------------------
    "host-discovery-arp": Technique(
        "T1018", "Discovery", "Remote System Discovery (ARP sweep)", "arp-scan"
    ),
    "host-discovery-icmp": Technique(
        "T1018", "Discovery", "Remote System Discovery (ICMP sweep)", "ping"
    ),
    "host-discovery-tcp": Technique(
        "T1018", "Discovery", "Remote System Discovery (TCP ping)", "nmap"
    ),
    "service-enum": Technique(
        "T1046", "Discovery", "Network Service Discovery", "nmap"
    ),
    "dc-discovery": Technique(
        "T1018", "Discovery", "Remote System Discovery (Domain Controllers)", "nslookup"
    ),
    "smb-null-session": Technique(
        "T1135", "Discovery", "Network Share Discovery (SMB null session)",
        "netexec", 445, "smb",
    ),
    "ldap-anon-bind": Technique(
        "T1087.002", "Discovery", "Account Discovery: Domain Account (LDAP anonymous bind)",
        "ldapsearch", 389, "ldap",
    ),
    "rid-brute": Technique(
        "T1087.002", "Discovery", "Account Discovery: Domain Account (RID brute force)",
        "netexec", 445, "smb",
    ),
    "kerberos-user-enum": Technique(
        "T1087.002", "Discovery", "Account Discovery: Domain Account (Kerberos enum)",
        "kerbrute", 88, "kerberos",
    ),

    # --- Phase 1b - authenticated reconnaissance ---------------------------
    "ldap-enum": Technique(
        "T1087.002", "Discovery", "Account Discovery: Domain Account (authenticated LDAP)",
        "netexec", 389, "ldap",
    ),
    "password-policy": Technique(
        "T1201", "Discovery", "Password Policy Discovery", "netexec", 445, "smb"
    ),
    "machine-account-quota": Technique(
        "T1087.002", "Discovery", "Account Discovery (ms-DS-MachineAccountQuota)",
        "netexec", 389, "ldap",
    ),
    "vuln-scan": Technique(
        "T1595.002", "Reconnaissance", "Vulnerability Scanning (detection-only check)",
        "netexec",
    ),
    "laps-read": Technique(
        "T1555", "Credential Access", "Credentials from Password Stores (LAPS)",
        "netexec", 389, "ldap",
    ),
    "adcs-enum": Technique(
        "T1649", "Credential Access",
        "Steal or Forge Authentication Certificates (AD CS enumeration)",
        "certipy", 445, "smb",
    ),

    # --- Phase 2 - poisoning / relay / coercion ----------------------------
    "ipv6-poisoning": Technique(
        "T1557.003", "Credential Access",
        "Adversary-in-the-Middle: DHCPv6 Spoofing", "mitm6",
    ),
    "llmnr-poisoning": Technique(
        "T1557.001", "Credential Access",
        "Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning", "responder",
    ),
    "ntlm-relay": Technique(
        "T1557.001", "Credential Access",
        "Adversary-in-the-Middle: NTLM Relay", "ntlmrelayx",
    ),
    "coercion": Technique(
        "T1187", "Credential Access", "Forced Authentication (RPC coercion)", "coercer"
    ),
    "rbcd": Technique(
        "T1098", "Persistence",
        "Account Manipulation: Resource-Based Constrained Delegation",
        "ntlmrelayx", 389, "ldap",
    ),
    "shadow-credentials": Technique(
        "T1098", "Persistence", "Account Manipulation: Shadow Credentials",
        "ntlmrelayx", 389, "ldap",
    ),
    "adcs-esc8": Technique(
        "T1649", "Credential Access",
        "Steal or Forge Authentication Certificates (ESC8 web enrollment relay)",
        "ntlmrelayx", 80, "http",
    ),

    # --- Phase 3 - credential harvesting -----------------------------------
    "asreproast": Technique(
        "T1558.004", "Credential Access",
        "Steal or Forge Kerberos Tickets: AS-REP Roasting",
        "GetNPUsers", 88, "kerberos",
    ),
    "kerberoast": Technique(
        "T1558.003", "Credential Access", "Steal or Forge Kerberos Tickets: Kerberoasting",
        "GetUserSPNs", 88, "kerberos",
    ),
    "password-spray": Technique(
        "T1110.003", "Credential Access", "Brute Force: Password Spraying", "netexec"
    ),
    "secretsdump-local": Technique(
        "T1003.002", "Credential Access", "OS Credential Dumping: SAM / LSA Secrets",
        "secretsdump", 445, "smb",
    ),
    "dcsync": Technique(
        "T1003.006", "Credential Access", "OS Credential Dumping: DCSync",
        "secretsdump", 445, "smb",
    ),

    # --- Phase 4 - exploitation / privilege escalation ---------------------
    "s4u-ticket": Technique(
        "T1558", "Credential Access", "Steal or Forge Kerberos Tickets (S4U2Proxy)",
        "getST", 88, "kerberos",
    ),
    "pkinit-auth": Technique(
        "T1649", "Credential Access",
        "Steal or Forge Authentication Certificates (PKINIT auth)",
        "certipy", 88, "kerberos",
    ),
    "golden-ticket": Technique(
        "T1558.001", "Credential Access", "Steal or Forge Kerberos Tickets: Golden Ticket",
        "ticketer",
    ),
    "silver-ticket": Technique(
        "T1558.002", "Credential Access", "Steal or Forge Kerberos Tickets: Silver Ticket",
        "ticketer",
    ),

    # --- Phase 4b - BloodHound collection ----------------------------------
    "bloodhound": Technique(
        "T1087.002", "Discovery", "Account Discovery: Domain Account (BloodHound)",
        "bloodhound-python", 389, "ldap",
    ),

    # --- Phase 5 - lateral movement ----------------------------------------
    "lateral-exec-smb": Technique(
        "T1021.002", "Lateral Movement",
        "Remote Services: SMB/Windows Admin Shares", "netexec", 445, "smb",
    ),
    "lateral-exec-winrm": Technique(
        "T1021.006", "Lateral Movement", "Remote Services: Windows Remote Management",
        "netexec", 5985, "winrm",
    ),
    "lateral-exec-wmi": Technique(
        "T1047", "Execution", "Windows Management Instrumentation", "netexec", 135, "wmi"
    ),
    "lateral-exec-mssql": Technique(
        "T1059", "Execution", "Command and Scripting Interpreter (MSSQL xp_cmdshell)",
        "netexec", 1433, "mssql",
    ),
    "pass-the-hash": Technique(
        "T1550.002", "Lateral Movement", "Use Alternate Authentication Material: Pass the Hash",
        "netexec", 445, "smb",
    ),
}

_UNKNOWN = Technique("T0000", "Unknown", "Unmapped activity")


def lookup(technique_key: str) -> Technique:
    """Resolve a technique key to its :class:`Technique`.

    Unknown keys return a clearly-labelled placeholder (``T0000`` / Unknown)
    rather than raising, so a missing mapping degrades to a still-usable CSV
    row instead of breaking a live engagement.
    """
    return _CATALOG.get(technique_key, _UNKNOWN)


def known_keys() -> list[str]:
    """All registered technique keys (used by tests to guard coverage)."""
    return sorted(_CATALOG)
