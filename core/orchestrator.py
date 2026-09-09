"""Central engine - chains phases based on the engagement state.

Phases currently wired:

* Phase 1 - :func:`Orchestrator.run_recon` (anonymous + authenticated)
* Phase 3 - :func:`Orchestrator.run_credentials` (ASREProast / Kerberoast / spraying)
* Phase 6 - :func:`Orchestrator.run_report`
"""

from __future__ import annotations

import sys
from datetime import datetime
from pathlib import Path

import yaml

from core.logger import AuditLogger, get_logger
from core.target_manager import Credential, TargetManager
from modules.credentials.cred_manager import CredentialManager
from modules.recon.authed_recon import AuthedRecon
from modules.recon.recon import ReconEngine
from modules.reporting.phase1_report import generate_from_target_manager
from modules.reporting.soc_report import (
    generate_from_target_manager as generate_soc_csv,
)


class Orchestrator:
    def __init__(self, config_path: str | Path, fresh: bool = False):
        self.config_path = Path(config_path)
        with self.config_path.open("r", encoding="utf-8") as fh:
            self.config = yaml.safe_load(fh)

        # Per-engagement workspace: scope loot/logs by a slug derived from the
        # engagement name + its scope/domain, so one engagement never loads
        # another's state.json (credentials, users, findings). Re-running the
        # same config resolves to the same slug, so resuming still works.
        log_cfg = self.config.setdefault("logging", {})
        slug = self._engagement_slug()
        loot_dir = str(Path(log_cfg.get("loot_dir", "./loot")) / slug)
        log_dir = str(Path(log_cfg.get("log_dir", "./logs")) / slug)
        # Persist the scoped paths back into the config so every manager that
        # reads logging.loot_dir inherits the same isolated workspace.
        log_cfg["loot_dir"] = loot_dir
        log_cfg["log_dir"] = log_dir

        AuditLogger.init(log_dir=log_dir, level=log_cfg.get("level", "INFO"))
        self.log = get_logger()

        self.tm = TargetManager(loot_dir=loot_dir)
        self.log.info(f"Session started - config: {self.config_path}")
        self.log.info(f"Engagement workspace: {loot_dir}")
        self.log.info(f"Log file: {self.log.log_file}")

        # --fresh: archive any prior state for this engagement so the run starts
        # from a clean slate instead of resuming accumulated hosts/credentials.
        if fresh:
            state_file = Path(loot_dir) / "state.json"
            if state_file.exists():
                backup = state_file.with_name(
                    f"state.{datetime.now():%Y%m%d_%H%M%S}.bak.json"
                )
                state_file.rename(backup)
                self.log.warn(f"--fresh: archived previous state to {backup}")

        # Grey/white box: inject operator-supplied credentials before any phase.
        self._load_provided_credentials()

    def _engagement_slug(self) -> str:
        """Stable per-engagement directory name: ``<name>-<scope hash>``.

        The hash of the scope targets + domain disambiguates engagements that
        share a name (e.g. the default "client-audit") but target different
        environments, so their state never mixes; the same config always maps
        to the same slug so a later ``--phase`` resumes the right workspace.
        """
        import hashlib
        import re

        eng = self.config.get("engagement", {}) or {}
        name = str(eng.get("name") or "engagement").strip().lower()
        name = re.sub(r"[^a-z0-9._-]+", "-", name).strip("-") or "engagement"

        scope = (self.config.get("scope", {}) or {}).get("targets", []) or []
        domain = str(self.config.get("domain") or "")
        key = "|".join(sorted(str(s) for s in scope)) + "|" + domain.lower()
        digest = hashlib.sha1(key.encode("utf-8")).hexdigest()[:8]
        return f"{name}-{digest}"

    # ------------------------------------------------------------------
    # Credential bootstrap (grey / white box)
    # ------------------------------------------------------------------

    def _load_provided_credentials(self) -> None:
        """Load operator-supplied credentials from ``credentials_file``.

        The path is read from the top-level ``credentials_file`` key in the
        config (null in black-box engagements). Each entry of the file's
        ``credentials:`` list is mapped onto a :class:`Credential` and added
        to the engagement state, so Phases 3-5 can consume them as if they
        had been harvested during the audit.
        """
        cred_path = self.config.get("credentials_file")
        if not cred_path:
            return
        # Relative paths resolve against the working directory, consistent
        # with the other paths in the config (log_dir, loot_dir, userlist).
        self._load_credentials_file(Path(cred_path))

    def _load_credentials_file(self, path: Path) -> int:
        """Parse a credentials YAML file into the engagement state.

        Returns the number of credentials loaded. Shared by the startup
        bootstrap and the interactive post-recon credential prompt.
        """
        if not path.is_file():
            self.log.warn(f"credentials_file not found, skipping: {path}")
            return 0

        try:
            with path.open("r", encoding="utf-8") as fh:
                data = yaml.safe_load(fh) or {}
        except Exception as exc:
            self.log.error(f"Failed to parse credentials_file {path}: {exc}")
            return 0

        entries = data.get("credentials") or []
        loaded = 0
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            username = (entry.get("username") or "").strip()
            if not username:
                self.log.warn("credentials_file: entry without username ignored")
                continue
            self.tm.add_user(username)
            self.tm.add_credential(
                Credential(
                    username=username,
                    domain=(entry.get("domain") or "").strip(),
                    password=entry.get("password"),
                    nt_hash=entry.get("nt_hash"),
                    lm_hash=entry.get("lm_hash"),
                    ticket=entry.get("ticket"),
                    source=entry.get("source") or "provided",
                )
            )
            loaded += 1

        if loaded:
            self.log.success(
                f"Loaded {loaded} operator-supplied credential(s) from {path.name}"
            )
        return loaded

    # ------------------------------------------------------------------
    # Phase 1
    # ------------------------------------------------------------------

    def run_recon(self) -> None:
        self.log.banner("Phase 1 - Reconnaissance")
        engine = ReconEngine(config=self.config, tm=self.tm)
        completed = engine.run()
        if not completed:
            # Step mode: the operator stopped before the end of the phase.
            # The step runner already offered to persist progress, so we do
            # not save/authenticate/report behind their back.
            self.log.warn(
                "Phase 1 stopped early by operator - skipping authenticated "
                "recon and report. Resume later with: --phase authed-recon / "
                "--phase report"
            )
            return
        state_path = self.tm.save()
        self.log.success(f"State saved to {state_path}")
        # Phase 1b: authenticated recon. Runs automatically when a credential
        # is already known (grey box); in black box the operator is offered
        # (interactively, TTY only) to inject one before moving on.
        self._maybe_run_authed_recon()
        # Render the report last so it captures any Phase 1b findings too.
        self.run_report()

    # ------------------------------------------------------------------
    # Phase 1b - Authenticated reconnaissance
    # ------------------------------------------------------------------

    def _restore_state_if_empty(self) -> bool:
        """Load ``loot/state.json`` when a phase is invoked standalone.

        Phases that consume earlier results (authenticated recon,
        credentials) can be launched on their own (``--phase authed-recon``
        / ``--phase credentials``) with an in-memory state that is still
        empty. In that case we restore the persisted engagement state so they
        can run after a previous recon. Returns ``True`` when state is
        available, ``False`` when nothing could be loaded (caller should skip).
        """
        if self.tm.hosts:
            return True
        state_file = self.tm.loot_dir / "state.json"
        if self.tm.load_from_json(state_file):
            self.log.info(f"Loaded engagement state from {state_file}")
            return True
        self.log.warn(
            "No engagement state available - run recon first. Skipping."
        )
        return False

    def run_authed_recon(self) -> None:
        """Phase 1b - authenticated recon with the first usable credential.

        Drives :class:`AuthedRecon` (NetExec domain enumeration, detection-only
        vulnerability checks, LDAP recon, Certipy ADCS find). Restores state
        from ``loot/state.json`` when invoked standalone (``--phase
        authed-recon``) so it can run after a previous recon.
        """
        self.log.banner("Phase 1b - Authenticated reconnaissance")

        if not self._restore_state_if_empty():
            return

        cred = self._pick_first_credential()
        if cred is None:
            self.log.warn(
                "Authenticated recon skipped: no usable credential in state"
            )
            return

        # Prefer the credential's own domain (reliable in multi-domain
        # forests), then a DC that actually serves that domain.
        domain = self._resolve_credential_domain(cred)
        dc_ip = self._dc_ip_for_domain(domain)
        if not dc_ip:
            self.log.warn(
                "Authenticated recon: no DC known - LDAP/ADCS checks limited"
            )

        # Snapshot the state so the recap can flag what authenticated recon
        # adds on top of the anonymous Phase 1 (or a restored state.json).
        before_findings = {f.id for f in self.tm.findings}
        before_users = set(self.tm.users)

        authed_cfg = (self.config.get("recon") or {}).get("authed_recon") or {}
        runner = AuthedRecon(
            tm=self.tm,
            credential=cred,
            domain=domain,
            dc_ip=dc_ip,
            loot_dir=self.config.get("logging", {}).get("loot_dir", "./loot"),
            timeout=int(authed_cfg.get("timeout", AuthedRecon.DEFAULT_TIMEOUT)),
        )
        result = runner.run()
        self.log.info(
            f"Phase 1b: status={result.status}, users={result.users_found}, "
            f"shares={result.shares_found}, vulns={len(result.vulns)}, "
            f"adcs_templates={len(result.adcs_templates)}"
        )
        self.tm.save()

        # Re-display the recap so a black-box restart with credentials always
        # shows the current picture, highlighting whatever Phase 1b added (or
        # stating plainly that nothing new turned up).
        from modules.recon.recon import render_summary  # noqa: PLC0415

        render_summary(
            self.tm,
            self.log.console,
            title="Phase 1b - Authenticated recon summary",
            new_finding_ids={f.id for f in self.tm.findings} - before_findings,
            new_users=set(self.tm.users) - before_users,
            show_delta_note=True,
        )

    def _resolve_credential_domain(self, cred: "Credential") -> str:
        """Return the effective domain for *cred*, falling back to the discovered domain.

        When the credential's domain field does not match any known DC (e.g. the
        operator typed a placeholder like 'FQDN' or 'domain.local' in the wizard),
        we silently fall back to the domain discovered during Phase 1 recon so that
        nxc / certipy / impacket calls still work correctly.
        """
        candidate = (cred.domain or "").strip()
        if candidate:
            dom_lower = candidate.lower()
            for dc in self.tm.dcs():
                if dc.domain and dc.domain.lower() == dom_lower:
                    return candidate          # exact match — trust it
            # No DC recognises this domain name; fall back and warn.
            discovered = self._engagement_domain()
            if discovered and discovered.lower() != dom_lower:
                self.log.warn(
                    f"Credential domain '{candidate}' does not match any "
                    f"discovered DC domain — using '{discovered}' instead. "
                    f"Update the credentials file if this is wrong."
                )
                return discovered
        return candidate or self._engagement_domain()

    def _dc_ip_for_domain(self, domain: str) -> str:
        """Pick the DC IP that serves ``domain``; fall back to the first DC.

        In a multi-domain forest several DCs are known; authenticating a
        credential against a DC of the wrong domain would fail, so we match
        on the domain when we can.
        """
        dcs = self.tm.dcs()
        if not dcs:
            return ""
        if domain:
            dom = domain.lower()
            for d in dcs:
                if d.domain and d.domain.lower() == dom:
                    return d.ip
        return dcs[0].ip

    def _pick_first_credential(self) -> Credential | None:
        """First credential bearing a password, else the first genuine NT hash.

        The second pass guards on ``real_nt_hash`` rather than the raw
        ``nt_hash`` slot: roasting stashes a ``$krb5*`` blob there, and that
        blob is not authentication material. Returning such a credential would
        feed a malformed ``-H $krb5...`` to the nxc/impacket calls in
        authenticated recon. See :pyattr:`Credential.real_nt_hash`.
        """
        for c in self.tm.credentials:
            if c.password:
                return c
        for c in self.tm.credentials:
            if c.real_nt_hash:
                return c
        return None

    def _maybe_run_authed_recon(self) -> None:
        """Decide whether/how to run Phase 1b after the anonymous recon.

        * Grey box (a credential is already loaded) -> run it automatically.
        * Black box (no credential) -> offer to inject one, but only when
          attached to an interactive terminal. In non-interactive runs we
          simply note that Phase 3 will attempt account discovery.
        """
        # Gate on a credential that can actually authenticate, not on the raw
        # credential list: ASREProast/Kerberoast stash a $krb5* blob in a
        # Credential's nt_hash, so ``tm.credentials`` can be non-empty while
        # holding nothing usable. Without this guard we logged "Credentials
        # available - launching authenticated recon" and then immediately
        # aborted with "no usable credential", which is confusing and skips
        # the black-box account-discovery path.
        if any(c.has_auth_secret for c in self.tm.credentials):
            self.log.info("Credentials available - launching authenticated recon")
            self.run_authed_recon()
            return

        if not sys.stdin.isatty():
            self.log.info(
                "Black box (no TTY): skipping authenticated-recon offer. "
                "Phase 3 will try to discover accounts (ASREPRoast, spraying). "
                "Add a credential later with: --phase authed-recon"
            )
            return

        if not self._offer_and_load_credentials():
            self.log.info(
                "Continuing in black box. If no account is known, Phase 3 will "
                "attempt to discover one (ASREPRoast, password spraying). You "
                "can run authenticated recon later with: --phase authed-recon"
            )
            return

        self.run_authed_recon()

    def _offer_and_load_credentials(self) -> bool:
        """Interactively offer to add a credential. Returns True if one was added.

        The initial yes/no gate auto-resolves to "no" after 30s of inactivity so
        an unattended auto-mode run is never blocked waiting on the operator.
        """
        try:
            import questionary  # noqa: PLC0415 - optional, lazy
        except ImportError:
            self.log.warn("questionary not available - cannot prompt for credentials")
            return False

        from utils.timed_prompt import confirm_with_timeout  # noqa: PLC0415

        proceed = confirm_with_timeout(
            "No credentials yet. Add one now to run authenticated recon "
            "(nxc enum, nopac/zerologon checks, certipy ADCS) before Phase 4?",
            timeout=30.0,
            default=False,
        )
        if not proceed:
            return False

        before = len(self.tm.credentials)
        source = questionary.select(
            "How do you want to provide the credential?",
            choices=[
                questionary.Choice("Enter it inline", value="inline"),
                questionary.Choice("Load a credentials YAML file", value="file"),
            ],
        ).ask()

        if source == "file":
            raw = questionary.text(
                "Path to credentials YAML file:",
                default="config/credentials.yaml",
            ).ask()
            if raw and raw.strip():
                self._load_credentials_file(Path(raw.strip()))
        elif source == "inline":
            self._prompt_inline_credential(questionary)

        return len(self.tm.credentials) > before

    def _prompt_inline_credential(self, questionary) -> None:
        """Prompt for a single credential and add it to the engagement state."""
        username = (questionary.text("Username (sAMAccountName):").ask() or "").strip()
        if not username:
            return
        domain = (
            questionary.text("Domain:", default=self._engagement_domain()).ask()
            or ""
        ).strip()
        secret_kind = questionary.select(
            "Secret type:",
            choices=[
                questionary.Choice("Password", value="pw"),
                questionary.Choice("NT hash (pass-the-hash)", value="nt"),
            ],
        ).ask()

        password = nt_hash = None
        if secret_kind == "pw":
            password = (questionary.text("Password:").ask() or "").strip() or None
        else:
            nt_hash = (
                questionary.text("NT hash (LM:NT or NT):").ask() or ""
            ).strip() or None
        if not (password or nt_hash):
            self.log.warn("No secret provided - credential not added")
            return

        self.tm.add_user(username)
        self.tm.add_credential(
            Credential(
                username=username,
                domain=domain,
                password=password,
                nt_hash=nt_hash,
                source="operator-supplied (post-recon)",
            )
        )
        self.log.success(f"Added credential for {domain}\\{username}")

    # ------------------------------------------------------------------
    # Phase 3
    # ------------------------------------------------------------------

    def run_credentials(self) -> None:
        """Run Phase 3 (ASREProast / Kerberoast / spraying / dumping).

        Reads users, DCs and existing credentials from the engagement
        state populated by Phase 1.
        Components that lack the prerequisites they need (no credential
        for kerberoast, no users for spray, ...) are skipped with a
        clear log line and the manager continues with the next one.
        """
        self.log.banner("Phase 3 - Credential Harvesting")
        if not self.tm.hosts:
            state_file = self.tm.loot_dir / "state.json"
            if self.tm.load_from_json(state_file):
                self.log.info(f"Loaded engagement state from {state_file}")
            else:
                self.log.warn(
                    "No engagement state available - run recon first or use --phase all."
                )
        manager = CredentialManager(config=self.config, tm=self.tm)
        manager.run()
        state_path = self.tm.save()
        self.log.success(f"State saved to {state_path}")

    # ------------------------------------------------------------------
    # Phase 6 - Reporting
    # ------------------------------------------------------------------

    def run_report(self, force: bool = False) -> None:
        """Render the Phase 1 reconnaissance findings to a standalone HTML page.

        Consumes the current engagement state. When the in-memory state is
        empty (e.g. ``--phase report`` invoked on its own), it is first
        restored from ``loot/state.json`` so the report can be regenerated
        from a previous run without re-scanning.

        Honours the operator's ``reporting.enabled`` choice: when it is false
        the automatic end-of-phase report is skipped. ``force=True`` (used by
        the explicit ``--phase report``) overrides that, since invoking the
        report phase by hand is an unambiguous request for one.
        """
        report_cfg = self.config.get("reporting", {}) or {}
        if not force and not report_cfg.get("enabled", True):
            self.log.info(
                "Report generation disabled (reporting.enabled: false) - "
                "skipping. Generate one later with: --phase report"
            )
            return

        self.log.banner("Phase 6 - Reporting")

        if not self.tm.hosts:
            state_file = self.tm.loot_dir / "state.json"
            if self.tm.load_from_json(state_file):
                self.log.info(f"Loaded engagement state from {state_file}")
            else:
                self.log.warn(
                    "No engagement state available - run recon first. Skipping."
                )
                return

        out_dir = Path(report_cfg.get("output_dir", "./reports"))
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_path = out_dir / f"mavama_report_{stamp}.html"

        engagement = self.config.get("engagement", {}) or {}
        meta = {
            "name": engagement.get("name", "Mavama engagement"),
            "operator": engagement.get("operator", "unknown"),
            "scope": (self.config.get("scope", {}) or {}).get("targets", []),
        }

        path = generate_from_target_manager(self.tm, out_path, meta)
        self.log.success(f"HTML report written to {path}")

        # SOC detection-test log: a timestamped, MITRE-tagged CSV of every test
        # fired (when / source IP / target / technique), for blue teams to
        # ingest and correlate against their EDR/SIEM. Skipped when disabled
        # (reporting.soc_log: false) or when no activity was recorded so we
        # never emit an empty file.
        if report_cfg.get("soc_log", True) and self.tm.activities:
            soc_path = out_dir / f"mavama_soc_log_{stamp}.csv"
            written = generate_soc_csv(self.tm, soc_path)
            self.log.success(
                f"SOC detection-test log written to {written} "
                f"({len(self.tm.activities)} events)"
            )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _engagement_domain(self) -> str:
        """Pick a usable AD domain. Config wins; fall back to recon."""
        if self.config.get("domain"):
            return str(self.config["domain"])
        for h in self.tm.alive_hosts():
            if h.is_dc and h.domain:
                return h.domain
        if self.tm.domains:
            return next(iter(self.tm.domains.keys()))
        return ""

    # ------------------------------------------------------------------
    # Multi-phase
    # ------------------------------------------------------------------

    def run_all(self) -> None:
        self.run_recon()
        self.run_credentials()
        # Final report: run_recon already emitted a Phase 1 snapshot, but the
        # engagement state has since accumulated Phase 3 findings (ASREProast,
        # Kerberoast, spraying). Regenerate so the report reflects the WHOLE
        # engagement, not just recon. force=True because an explicit
        # end-of-run report is always wanted (honours --no-report, which sets
        # reporting.enabled=false, only for the auto Phase 1 one).
        if self.config.get("reporting", {}).get("enabled", True):
            self.run_report(force=True)
