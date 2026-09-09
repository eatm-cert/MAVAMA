"""Finding methodology catalog - explains *how* each finding was discovered.

Every :class:`~core.target_manager.Finding` answers *what* is wrong (title,
description) and *how to fix it* (remediation). This module adds the missing
third question - *how did the tool find it?* - so the operator can reproduce,
trust, or rule out each result.

The explanation comes in two granularities:

* ``short``  - a single line printed to the terminal the moment the finding is
  recorded, so the operator sees the technique in context with the scan output.
* ``detail`` - a fuller paragraph rendered in the HTML report, naming the
  protocol/tool used and why the observed behaviour proves the weakness.

Resolution order for a finding:

1. An explicit ``method`` set on the finding always wins (a module can describe
   a one-off technique that the static catalog does not know about).
2. Otherwise the finding ``id`` is matched against the catalog by prefix
   (``SMB-NULL-10.0.0.1`` -> ``SMB-NULL``). The most specific (longest) prefix
   wins, so ``SMB-NULL`` is preferred over a hypothetical ``SMB`` entry.
3. Otherwise a generic fallback is returned.

The lookup accepts either a :class:`~core.target_manager.Finding` object or the
plain ``dict`` produced by ``TargetManager.to_dict()`` (the report works from
the serialized state), so this module never imports the ``Finding`` class and
stays free of import cycles.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Methodology:
    """How a finding was discovered, at two levels of detail."""

    short: str   # one-liner for the live terminal output
    detail: str  # paragraph for the written report


# ---------------------------------------------------------------------------
# Catalog
# ---------------------------------------------------------------------------
#
# Keyed by the static portion of a finding ``id`` (everything before the
# dynamic ``-<ip>`` / ``-<user>`` / ``-<template>`` suffix). Keep the wording
# accurate to what the corresponding module actually does - these strings are
# the audit trail an operator (or a reviewer of the report) relies on.

_CATALOG: dict[str, Methodology] = {
    # --- Phase 1 - anonymous reconnaissance --------------------------------
    "SMB-NULL": Methodology(
        short="anonymous SMB logon (empty username/password) on port 445 was accepted",
        detail=(
            "An SMB session was opened to port 445 with an empty username and "
            "password (a NULL session). The server accepted the bind, which "
            "proves anonymous SMB authentication is allowed. The same session "
            "was then used to enumerate the server name, OS and share list."
        ),
    ),
    "SMB-READ": Methodology(
        short="the share was listed and read over an anonymous (NULL) SMB session",
        detail=(
            "After a NULL session was accepted on port 445, every share was "
            "enumerated and a directory listing was attempted on each one. This "
            "share returned its contents without any credential, proving it is "
            "readable by anonymous users."
        ),
    ),
    "SMB-SIGN": Methodology(
        short="the SMB negotiate response advertised signing as not required",
        detail=(
            "During service enumeration the host's SMB negotiate response was "
            "inspected (nmap smb2-security-mode / NetExec). It reported that "
            "message signing is enabled but not required, so an attacker can "
            "relay an intercepted NTLM authentication to this host without the "
            "signature check rejecting it."
        ),
    ),
    "LDAP-ANON": Methodology(
        short="an anonymous LDAP bind on port 389 was accepted and RootDSE read",
        detail=(
            "An anonymous (unauthenticated) LDAP bind was performed against "
            "port 389. The server accepted it and returned its RootDSE, exposing "
            "the naming contexts and base DN. Where the directory also answered a "
            "subtree search for user objects, that confirmed anonymous read "
            "access and raised the severity."
        ),
    ),
    "LDAP-SIGN": Methodology(
        short="a plaintext LDAP simple bind succeeded, so signing is not enforced",
        detail=(
            "A simple bind was issued over cleartext LDAP (port 389) to probe the "
            "server's signing policy. Because the bind was processed rather than "
            "rejected with a 'strong authentication required' error, the DC does "
            "not enforce LDAP signing/channel-binding and is a viable relay target."
        ),
    ),
    "RID-BRUTE": Methodology(
        short="SIDs were walked over SAMR/LSA and resolved to account names",
        detail=(
            "Using the anonymous/low-privilege access available on the host, the "
            "domain SID was obtained and RIDs were iterated over the configured "
            "range (SAMR/LSA lookupsids). Each RID that resolved to a name was "
            "recorded, recovering valid user and group accounts without "
            "credentials."
        ),
    ),
    "ASREP": Methodology(
        short="a Kerberos AS-REP came back without pre-authentication being required",
        detail=(
            "An AS-REQ was sent to the KDC (port 88) for the account without "
            "pre-authentication. The KDC replied with an AS-REP containing an "
            "encrypted blob instead of demanding pre-auth, which proves the "
            "account has 'Do not require Kerberos preauthentication' set and its "
            "hash can be cracked offline (ASREProasting)."
        ),
    ),
    "ADCS-WEB": Methodology(
        short="the AD CS HTTP enrollment endpoint answered on the web-enrollment URL",
        detail=(
            "Service enumeration probed the Certificate Authority's web "
            "enrollment endpoint (certsrv over HTTP/HTTPS). The endpoint "
            "responded, confirming web enrollment is reachable - the prerequisite "
            "for the ESC8 NTLM-relay-to-AD-CS attack."
        ),
    ),

    # --- Phase 1b - authenticated reconnaissance ---------------------------
    "PASS-POL": Methodology(
        short="the domain password policy was read over LDAP/SMB with a valid account",
        detail=(
            "Using an authenticated account, the domain password policy was "
            "queried (NetExec --pass-pol). The reported lockout threshold of 0 "
            "(or none) means failed logons never lock accounts, so password "
            "spraying can run unthrottled."
        ),
    ),
    "MAQ": Methodology(
        short="ms-DS-MachineAccountQuota was read from the domain over LDAP",
        detail=(
            "The ms-DS-MachineAccountQuota attribute was read from the domain "
            "object via authenticated LDAP (NetExec -M maq). A non-zero value "
            "means any authenticated user may create computer accounts, which "
            "enables RBCD and noPac-style escalation."
        ),
    ),
    "LAPS-READ": Methodology(
        short="the current account successfully read LAPS admin passwords over LDAP",
        detail=(
            "An authenticated LDAP query for the LAPS attribute "
            "(ms-Mcs-AdmPwd / ms-LAPS-Password) returned cleartext values "
            "(NetExec -M laps). This proves the account is authorized to read "
            "local-administrator passwords for the affected hosts."
        ),
    ),
    "NOPAC": Methodology(
        short="a detection-only noPac check (CVE-2021-42278/42287) flagged the DC",
        detail=(
            "A non-destructive NetExec module (-M nopac) tested the DC for the "
            "sAMAccountName-spoofing / S4U2self confusion behind noPac. The "
            "module reported the DC as vulnerable. This is detection only - no "
            "account was created and no impersonation was performed."
        ),
    ),
    "ZEROLOGON": Methodology(
        short="a detection-only Zerologon check (CVE-2020-1472) flagged the DC",
        detail=(
            "A non-destructive NetExec module (-M zerologon) probed the Netlogon "
            "secure channel for the CVE-2020-1472 flaw. The module reported the "
            "DC as vulnerable. The check is detection only - the machine account "
            "password was not reset."
        ),
    ),
    "COERCE": Methodology(
        short="a detection-only check found RPC coercion methods exposed on the host",
        detail=(
            "A NetExec detection module (-M coerce_plus) queried the host's RPC "
            "interfaces for the methods abused by PetitPotam / PrinterBug / "
            "DFSCoerce / ShadowCoerce. One or more responded, showing the host "
            "can be coerced into authenticating to an attacker. No coercion was "
            "actually triggered."
        ),
    ),
    "SPOOLER": Methodology(
        short="the Print Spooler RPC interface (MS-RPRN) answered as enabled",
        detail=(
            "The MS-RPRN Print System Remote Protocol interface was queried "
            "(NetExec -M spooler). It responded as running, meaning the host is "
            "exposed to the PrinterBug coercion technique. Detection only - no "
            "print job or coercion was issued."
        ),
    ),
    "ADCS": Methodology(
        short="Certipy enumerated the CA templates and flagged a misconfiguration",
        detail=(
            "Certipy was run in enumeration mode ('certipy find') against AD CS "
            "using a valid account. It parsed the published certificate templates "
            "and their security descriptors and flagged this template as matching "
            "a known ESC misconfiguration. Enumeration only - no certificate was "
            "requested."
        ),
    ),
    "BLOODHOUND": Methodology(
        short="BloodHound collected the domain over LDAP with an authenticated account",
        detail=(
            "A BloodHound collection (bloodhound-python / NetExec --bloodhound) "
            "ran against the domain with a valid credential, gathering users, "
            "groups, sessions, ACLs and trusts over LDAP. The resulting graph is "
            "what surfaces the attack paths reported here."
        ),
    ),

    # --- Phase 2 - poisoning / relay / coercion ----------------------------
    "IPV6-POISON": Methodology(
        short="mitm6 served rogue DHCPv6 leases and spoofed DNS on the interface",
        detail=(
            "mitm6 was started on the interface and replied to clients' DHCPv6 "
            "solicitations, assigning them the attacker as their IPv6 DNS server. "
            "Spoofed DNS replies were then served, redirecting victims' WPAD / "
            "name lookups to the attacker to capture NTLM authentication."
        ),
    ),
    "RESPONDER": Methodology(
        short="Responder answered LLMNR/NBT-NS/mDNS queries to capture authentication",
        detail=(
            "Responder was started on the interface and answered broadcast "
            "LLMNR, NBT-NS and mDNS name-resolution queries, impersonating the "
            "requested hosts. Victims that fell back to these protocols then "
            "authenticated to the attacker."
        ),
    ),
    "NTLMV2-CAPTURE": Methodology(
        short="an NTLMv2 challenge/response was captured from a poisoned victim",
        detail=(
            "A victim coerced or poisoned into name resolution authenticated to "
            "the attacker's rogue service. The NTLMv2 challenge/response was "
            "captured and is crackable offline (hashcat/john) or relayable to "
            "another host."
        ),
    ),
    "COERCION": Methodology(
        short="a coercion RPC call forced the target to authenticate to the attacker",
        detail=(
            "A coercion trigger (PetitPotam / DFSCoerce / PrinterBug / Coercer) "
            "invoked the relevant RPC method against the target with the "
            "attacker's listener as the destination. The target connected back "
            "and authenticated, confirming the coercion path is exploitable."
        ),
    ),
    "NTLM-RELAY": Methodology(
        short="ntlmrelayx forwarded a captured NTLM authentication to the target",
        detail=(
            "An incoming NTLM authentication (from poisoning or coercion) was "
            "relayed by ntlmrelayx to the configured target before the session "
            "was torn down. The target accepted the relayed credentials, which "
            "is what enabled the follow-on action recorded in the description."
        ),
    ),
    "RBCD-DELEGATION": Methodology(
        short="a relayed LDAP write set msDS-AllowedToActOnBehalfOfOtherIdentity",
        detail=(
            "Through a relayed LDAP session, the "
            "msDS-AllowedToActOnBehalfOfOtherIdentity attribute on the victim "
            "computer was written to trust an attacker-controlled account "
            "(Resource-Based Constrained Delegation). The attacker can now forge "
            "service tickets for any user on that host."
        ),
    ),

    # --- Phase 3-5 - credentials / exploitation / lateral ------------------
    "SPRAY-HIT": Methodology(
        short="a password spray authenticated successfully for this account",
        detail=(
            "A password from the spray list was tested against the account "
            "(NetExec), respecting the detected lockout policy. The "
            "authentication succeeded, confirming a valid credential."
        ),
    ),
    "DUMP": Methodology(
        short="secretsdump extracted secrets from the target's SAM/LSA/NTDS",
        detail=(
            "Impacket secretsdump was run against the target with the available "
            "credential, extracting hashes/secrets from the SAM, LSA or NTDS "
            "store. The recovered material is summarized in the description."
        ),
    ),
    "DCSYNC": Methodology(
        short="a DCSync replicated account secrets directly from the DC",
        detail=(
            "Using replication rights, secretsdump performed a DCSync "
            "(DRSUAPI GetNCChanges) against the domain controller and replicated "
            "account password hashes - including krbtgt - without touching the "
            "host's disk."
        ),
    ),
    "RCE": Methodology(
        short="NetExec confirmed remote command execution with a recovered credential",
        detail=(
            "NetExec authenticated to the host with a recovered credential and "
            "executed a benign command (e.g. whoami) over the chosen protocol. "
            "The command returned output, proving remote code execution - and "
            "administrative access where it ran as a privileged user."
        ),
    ),
}

# Match longest (most specific) prefixes first so e.g. ``ADCS-WEB`` wins over
# the generic ``ADCS`` entry.
_PREFIXES_BY_LENGTH = sorted(_CATALOG, key=len, reverse=True)

_FALLBACK = Methodology(
    short="recorded by automated reconnaissance (see description / evidence)",
    detail=(
        "This finding was recorded automatically by Mavama during the "
        "audit. Refer to the description and any captured evidence for the "
        "specific signal that triggered it."
    ),
)


# ---------------------------------------------------------------------------
# Lookup
# ---------------------------------------------------------------------------

def _field(finding: Any, name: str) -> str:
    """Read ``name`` from a Finding object or a serialized finding dict."""
    if isinstance(finding, Mapping):
        value = finding.get(name)
    else:
        value = getattr(finding, name, None)
    return str(value) if value else ""


def _first_sentence(text: str) -> str:
    """Best-effort one-liner: the first sentence, trimmed to a sane length."""
    text = " ".join(text.split())
    for sep in (". ", "; "):
        if sep in text:
            text = text.split(sep, 1)[0]
            break
    return text if len(text) <= 160 else text[:157].rstrip() + "..."


def explain(finding: Any) -> Methodology:
    """Return the :class:`Methodology` describing how ``finding`` was found.

    ``finding`` may be a :class:`~core.target_manager.Finding` or the dict from
    ``TargetManager.to_dict()``. An explicit ``method`` on the finding overrides
    the catalog; otherwise the finding ``id`` is matched by prefix; otherwise a
    generic fallback is returned.
    """
    explicit = _field(finding, "method")
    if explicit:
        return Methodology(short=_first_sentence(explicit), detail=explicit)

    fid = _field(finding, "id")
    for prefix in _PREFIXES_BY_LENGTH:
        if fid == prefix or fid.startswith(prefix + "-"):
            return _CATALOG[prefix]

    return _FALLBACK
