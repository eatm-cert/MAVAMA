"""Phase 1 orchestrator - chains the recon submodules.

The phase is expressed as an ordered list of reviewable steps (see
:mod:`utils.step_runner`):

1. **ARP scan**          - layer-2 sweep of the scope (local segment).
2. **ICMP ping sweep**   - ICMP echo probes across the scope.
3. **TCP ping**          - TCP connect probes for ICMP-filtered hosts.
4. **Service enum**      - nmap -sV + NSE scripts (including SMB signing).
5. **DC identification** - DNS SRV + LDAP RootDSE + NetBIOS.
6. **Anonymous enum**    - SMB null session, LDAP anonymous bind, RID brute.
7. **Kerberos user enum**- AS-REQ user enum per (domain, KDC) pair.

In ``auto`` mode the steps run back-to-back. In ``step`` (semi-automatic)
mode the operator reviews the result of each step and decides whether to
continue, skip, or stop (with an optional progress save). A summary table is
printed at the end (hosts / DCs / findings).
"""

from __future__ import annotations

from rich.table import Table

from core.logger import get_logger, severity_badge
from core.target_manager import TargetManager
from modules.recon.anon_enum import AnonEnum
from modules.recon.dc_finder import DCFinder
from modules.recon.host_discovery import HostDiscovery
from modules.recon.service_enum import ServiceEnum
from modules.recon.user_enum import UserEnum
from utils.step_runner import Step, StepRunner, normalize_mode

# Phase label stamped on every SOC activity emitted by this engine.
_PHASE = "Phase 1 - Reconnaissance"


class ReconEngine:
    def __init__(self, config: dict, tm: TargetManager):
        self.cfg = config
        self.tm = tm
        self.log = get_logger()

    # ------------------------------------------------------------------

    def run(self) -> bool:
        """Run Phase 1.

        Returns ``True`` when the phase completed (auto mode, or every step
        run/skipped in step mode) and ``False`` when the operator stopped
        early in step mode (so the caller can skip post-recon work).
        """
        scope_cfg = self.cfg.get("scope", {})
        recon_cfg = self.cfg.get("recon", {})
        iface = self.cfg.get("interface")
        stealth_mode = bool(
            self.cfg.get("engagement", {}).get("stealth_mode", False)
        )

        hd_cfg = recon_cfg.get("host_discovery", {})
        hd = HostDiscovery(
            tm=self.tm,
            targets=scope_cfg.get("targets", []),
            exclude=scope_cfg.get("exclude", []),
            timeout=hd_cfg.get("timeout", 2),
            tcp_ports=hd_cfg.get("tcp_ping_ports", [445, 135, 3389]),
            interface=iface,
        )
        scope = hd._scope()
        if not scope:
            self.log.error("Empty scope after exclusions - aborting Phase 1")
            return False
        self.log.info(f"Scope: {len(scope)} IPs to probe")

        # ``alive`` accumulates the IPs reported by each host-discovery
        # technique and drives the guards on the downstream steps, mirroring
        # the original "stop when no live host" behaviour.
        alive: set[str] = set()
        # Domain learned by the DC-finder step; consumed by the user-enum step.
        self._discovered_domain = ""

        steps = self._build_steps(
            hd=hd,
            scope=scope,
            alive=alive,
            recon_cfg=recon_cfg,
            hd_cfg=hd_cfg,
            stealth_mode=stealth_mode,
        )

        runner = StepRunner(mode=self._execution_mode(), tm=self.tm, log=self.log)
        completed = runner.run(steps)

        self._print_summary()
        return completed

    # ------------------------------------------------------------------
    # Step construction
    # ------------------------------------------------------------------

    def _execution_mode(self) -> str:
        """Resolve the execution mode from the engagement config."""
        return normalize_mode(
            self.cfg.get("engagement", {}).get("execution_mode", "auto")
        )

    def _build_steps(
        self,
        *,
        hd: HostDiscovery,
        scope: list[str],
        alive: set[str],
        recon_cfg: dict,
        hd_cfg: dict,
        stealth_mode: bool,
    ) -> list[Step]:
        """Assemble the ordered list of Phase 1 steps.

        Each step closes over the shared ``alive`` set so that techniques
        skipped by the operator (in step mode) simply contribute nothing and
        the downstream steps still see whatever was discovered.
        """
        steps: list[Step] = []

        # The scope exactly as the operator declared it (CIDR / range / list),
        # recorded on every sweep so the SOC report shows where a scan ran
        # without expanding it to hundreds of individual IPs.
        scope_label = ", ".join(
            str(t) for t in (self.cfg.get("scope", {}) or {}).get("targets", []) or []
        )

        # --- Host discovery: one step per technique so the operator can
        # review what each one finds before launching the next. ---
        if hd_cfg.get("arp_scan", True):

            def _arp() -> list[str]:
                self.tm.record_activity(
                    "host-discovery-arp", phase=_PHASE, targets=scope_label,
                    details=f"layer-2 ARP sweep of {len(scope)} IP(s)",
                )
                found = hd.arp_scan()
                alive.update(found)
                return [f"ARP: {len(found)} host(s) responded"] + self._fmt_ips(found)

            steps.append(Step(
                "ARP scan",
                "Layer-2 ARP sweep of the scope (local segment, requires root).",
                _arp,
            ))

        if hd_cfg.get("ping_sweep", True):

            def _icmp() -> list[str]:
                self.tm.record_activity(
                    "host-discovery-icmp", phase=_PHASE, targets=scope_label,
                    details=f"ICMP echo sweep of {len(scope)} IP(s)",
                )
                found = hd.ping_sweep(scope)
                new = found - alive
                alive.update(found)
                return [
                    f"ICMP: {len(found)} host(s) answered ({len(new)} new)"
                ] + self._fmt_ips(new)

            steps.append(Step(
                "ICMP ping sweep",
                "ICMP echo probes across every IP in scope.",
                _icmp,
            ))

        def _tcp() -> list[str]:
            remaining = [ip for ip in scope if ip not in alive]
            # TCP ping only probes the ICMP-filtered remainder, so record that
            # actual subset (compact list when short, else the declared scope).
            tcp_targets = (
                ", ".join(remaining) if 0 < len(remaining) <= 16 else scope_label
            )
            self.tm.record_activity(
                "host-discovery-tcp", phase=_PHASE, targets=tcp_targets,
                details=f"TCP connect probe on {hd.tcp_ports} for {len(remaining)} IP(s)",
            )
            found = hd.tcp_ping(remaining)
            alive.update(found)
            hd._resolve_hostnames(alive)
            return [
                f"TCP: {len(found)} extra host(s) on ports {hd.tcp_ports}",
                f"Live hosts so far: {len(alive)}",
            ] + self._fmt_ips(found)

        steps.append(Step(
            "TCP ping",
            f"TCP connect probes on {hd.tcp_ports} for hosts that filter ICMP.",
            _tcp,
        ))

        # --- Service enumeration ---
        ps_cfg = recon_cfg.get("port_scan", {})

        def _svc() -> list[str]:
            if not alive:
                return ["No live host - service enumeration skipped"]
            se = ServiceEnum(
                tm=self.tm,
                ports=ps_cfg.get("ports"),
                rate=ps_cfg.get("rate", 1000),
                timeout=ps_cfg.get("timeout", 300),
                stealth_mode=stealth_mode,
            )
            for ip in sorted(alive):
                self.tm.record_activity(
                    "service-enum", ip, phase=_PHASE,
                    details="nmap -sV + NSE (incl. smb2-security-mode signing probe)",
                )
            se.run(sorted(alive))
            return self._service_summary()

        steps.append(Step(
            "Service enumeration",
            "nmap -sV + NSE scripts (incl. SMB signing) on the live hosts.",
            _svc,
        ))

        # --- DC identification ---
        def _dcf() -> list[str]:
            if not alive:
                return ["No live host - DC identification skipped"]
            dcf = DCFinder(
                tm=self.tm,
                domain=self.cfg.get("domain"),
                timeout=hd_cfg.get("timeout", 3),
            )
            self.tm.record_activity(
                "dc-discovery", phase=_PHASE,
                details="DNS SRV (_ldap._tcp.dc._msdcs) + LDAP RootDSE + NetBIOS",
            )
            dcf.run()
            self._discovered_domain = getattr(dcf, "domain", "") or ""
            dcs = self.tm.dcs()
            if not dcs:
                return ["No Domain Controller identified"]
            return [f"{len(dcs)} Domain Controller(s) identified:"] + [
                f"  {d.ip}  {d.hostname or '-'}  ({d.domain or '?'})" for d in dcs
            ]

        steps.append(Step(
            "DC identification",
            "Locate Domain Controllers via DNS SRV, LDAP RootDSE and NetBIOS.",
            _dcf,
        ))

        # --- Anonymous enumeration ---
        ae_cfg = recon_cfg.get("anon_enum", {})

        def _anon() -> list[str]:
            if not alive:
                return ["No live host - anonymous enumeration skipped"]
            users_before = len(self.tm.users)
            findings_before = len(self.tm.findings)
            ae = AnonEnum(
                tm=self.tm,
                rid_range=tuple(ae_cfg.get("rid_range", [500, 1500])),
                timeout=5,
            )
            ae.run(
                do_smb=ae_cfg.get("smb_null_session", True),
                do_ldap=ae_cfg.get("ldap_anonymous_bind", True),
                do_rid=ae_cfg.get("rid_bruteforce", True),
                do_vuln_checks=ae_cfg.get("vuln_checks", True),
            )
            return [
                f"Users discovered: +{len(self.tm.users) - users_before} "
                f"(total {len(self.tm.users)})",
                f"New findings: +{len(self.tm.findings) - findings_before}",
            ]

        steps.append(Step(
            "Anonymous enumeration",
            "SMB null session, LDAP anonymous bind and RID brute force.",
            _anon,
        ))

        # --- Kerberos user enumeration ---
        ue_cfg = recon_cfg.get("user_enum", {})
        if ue_cfg.get("enabled", True):

            def _ue() -> list[str]:
                if not alive:
                    return ["No live host - Kerberos user enum skipped"]
                return self._run_user_enum(ue_cfg, stealth_mode)

            steps.append(Step(
                "Kerberos user enumeration",
                "AS-REQ user enumeration per (domain, KDC) pair - no lockout risk.",
                _ue,
            ))

        return steps

    def _run_user_enum(self, ue_cfg: dict, stealth_mode: bool) -> list[str]:
        """Run Kerberos user enum once per (domain, DC) pair.

        Accounts from every domain in a multi-domain forest are tested against
        their own KDC, which avoids ``KDC_ERR_C_PRINCIPAL_UNKNOWN`` for
        accounts that only exist in a child/sibling domain.
        """
        dcs = self.tm.dcs()
        # An operator-supplied domain overrides auto-discovery and is tried
        # first against the first DC that serves it.
        forced_domain = self.cfg.get("domain") or self._discovered_domain or ""
        pairs: list[tuple[str, str]] = []
        seen_domains: set[str] = set()
        for dc in dcs:
            dom = (dc.domain or "").lower()
            if not dom or dom in seen_domains:
                continue
            seen_domains.add(dom)
            pairs.append((dc.domain, dc.ip))
        if forced_domain and forced_domain.lower() not in seen_domains and dcs:
            pairs.insert(0, (forced_domain, dcs[0].ip))

        if not pairs:
            self.log.warn("Kerberos user enum skipped: no DC or domain known")
            return ["Skipped: no DC or domain known"]

        totals = {"valid": 0, "asreproastable": 0, "disabled": 0}
        for domain, kdc_ip in pairs:
            self.log.info(f"Kerberos user enum: domain={domain} KDC={kdc_ip}")
            self.tm.record_activity(
                "kerberos-user-enum", kdc_ip, phase=_PHASE,
                details=f"AS-REQ user enumeration (no pre-auth) for domain {domain}",
            )
            ue = UserEnum(
                tm=self.tm,
                domain=domain,
                kdc_ip=kdc_ip,
                userlist=ue_cfg.get("userlist"),
                threads=ue_cfg.get("threads", 10),
                stealth_mode=stealth_mode,
            )
            res = ue.run() or {}
            for key in totals:
                totals[key] += len(res.get(key, []))

        return [
            f"Tested {len(pairs)} (domain, DC) pair(s)",
            f"Valid: {totals['valid']}, "
            f"ASREP-roastable: {totals['asreproastable']}, "
            f"disabled: {totals['disabled']}",
        ]

    @staticmethod
    def _fmt_ips(ips, limit: int = 12) -> list[str]:
        """Return an indented, truncated, sorted list of IPs for display."""
        if not ips:
            return []
        ordered = sorted(ips, key=lambda x: tuple(int(p) for p in x.split(".")))
        lines = ["  " + ", ".join(ordered[:limit])]
        if len(ordered) > limit:
            lines.append(f"  ... (+{len(ordered) - limit} more)")
        return lines

    def _service_summary(self) -> list[str]:
        """Build summary lines after the service-enumeration step."""
        hosts = self.tm.alive_hosts()
        with_services = [h for h in hosts if h.services]
        lines = [f"{len(with_services)} host(s) with identified services"]
        relay_targets = [h.ip for h in hosts if "relay-target-smb" in h.tags]
        if relay_targets:
            lines.append(
                "SMB relay targets (signing not required): "
                + ", ".join(sorted(relay_targets))
            )
        return lines

    # ------------------------------------------------------------------

    def _print_summary(self) -> None:
        render_summary(self.tm, self.log.console, title="Phase 1 - Summary")


# ---------------------------------------------------------------------------
# Reusable recap rendering (shared by Phase 1 and the authenticated-recon
# restart so the operator always gets the same hosts/findings/users tables).
# ---------------------------------------------------------------------------

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _auth_context_badge(auth_context: str) -> str:
    """Return a compact coloured badge for the finding auth_context field."""
    if auth_context == "anonymous":
        return "[cyan]anon[/cyan]"
    if auth_context == "authenticated":
        return "[yellow]auth[/yellow]"
    return "[dim]-[/dim]"


def render_summary(
    tm: TargetManager,
    console,
    *,
    title: str = "Phase 1 - Summary",
    new_finding_ids: frozenset[str] | set[str] = frozenset(),
    new_users: frozenset[str] | set[str] = frozenset(),
    show_delta_note: bool = False,
) -> None:
    """Print the engagement recap: hosts, findings (severity-coloured), users.

    When ``show_delta_note`` is set, findings/users whose id/name is in
    ``new_finding_ids`` / ``new_users`` are flagged ``NEW`` and a one-line delta
    note is printed (or "nothing new" when both sets are empty) — used when the
    recap is re-displayed after authenticated reconnaissance.
    """
    hosts = tm.alive_hosts()

    t = Table(title=title, show_lines=False)
    t.add_column("IP", style="bold blue")
    t.add_column("Hostname", style="cyan")
    t.add_column("OS", style="white")
    t.add_column("Domain", style="magenta")
    t.add_column("Ports", style="green")
    t.add_column("Tags", style="yellow")

    for h in sorted(hosts, key=lambda x: tuple(int(p) for p in x.ip.split("."))):
        ports = ",".join(str(s.port) for s in sorted(h.services, key=lambda s: s.port))
        tags = ",".join(h.tags)
        if h.is_dc and "dc" not in tags:
            tags = f"dc,{tags}" if tags else "dc"
        t.add_row(h.ip, h.hostname or "-", h.os or "-", h.domain or "-", ports or "-", tags or "-")
    console.print(t)

    # Findings - one colour-coded badge per severity, highest severity first.
    if tm.findings:
        f_table = Table(title="Findings", show_lines=False)
        f_table.add_column("Severity", no_wrap=True)
        f_table.add_column("Host")
        f_table.add_column("Access", no_wrap=True)
        f_table.add_column("Title")
        for f in sorted(tm.findings, key=lambda x: _SEV_ORDER.get(x.severity, 5)):
            title_cell = f.title
            if f.id in new_finding_ids:
                title_cell = f"[bold green]NEW[/] {title_cell}"
            access_cell = _auth_context_badge(f.auth_context)
            f_table.add_row(severity_badge(f.severity), f.host or "-", access_cell, title_cell)
        console.print(f_table)
    else:
        console.print("[dim]No findings recorded.[/dim]")

    # Users.
    if tm.users:
        console.print(
            f"[bold yellow]Discovered users[/bold yellow] "
            f"({len(tm.users)}): "
            + ", ".join(sorted(tm.users)[:40])
            + (" ..." if len(tm.users) > 40 else "")
        )
    if new_users:
        console.print(
            f"[bold green]New users this phase[/bold green] "
            f"({len(new_users)}): " + ", ".join(sorted(new_users))
        )

    if show_delta_note:
        if new_finding_ids or new_users:
            console.print(
                f"[green]+{len(new_finding_ids)} new finding(s), "
                f"+{len(new_users)} new user(s) since the anonymous recon.[/green]"
            )
        else:
            console.print(
                "[yellow]No new findings or users discovered during "
                "authenticated reconnaissance.[/yellow]"
            )
