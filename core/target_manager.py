"""Engagement state: hosts, services, credentials, findings.

The ``TargetManager`` is the single source of truth for the engagement.
All modules read and write their results here; it is JSON-serializable so
the session can be persisted and consumed by the final report."""

from __future__ import annotations

import csv
import json
import re
from dataclasses import dataclass, field, fields, asdict
from datetime import datetime, timezone
from pathlib import Path
from threading import RLock
from typing import Any

from core import attack_catalog
from core.net import source_ip_for


@dataclass
class Service:
    port: int
    proto: str = "tcp"
    name: str = ""
    banner: str = ""
    extra: dict = field(default_factory=dict)


@dataclass
class Host:
    ip: str
    hostname: str = ""
    os: str = ""
    mac: str = ""
    is_dc: bool = False
    is_adcs: bool = False
    domain: str = ""
    services: list[Service] = field(default_factory=list)
    smb_signing: str | None = None      # "required", "enabled", "disabled"
    ldap_signing: str | None = None
    shares: list[dict] = field(default_factory=list)
    rid_users: list[dict] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)

    def add_service(self, port: int, name: str = "", banner: str = "", **extra: Any) -> None:
        for s in self.services:
            if s.port == port:
                if name:
                    s.name = name
                if banner:
                    s.banner = banner
                s.extra.update(extra)
                return
        self.services.append(Service(port=port, name=name, banner=banner, extra=extra))

    def has_port(self, port: int) -> bool:
        return any(s.port == port for s in self.services)


@dataclass
class Credential:
    username: str
    domain: str = ""
    password: str | None = None
    nt_hash: str | None = None
    lm_hash: str | None = None
    ticket: str | None = None
    source: str = ""
    valid_on: list[str] = field(default_factory=list)

    @property
    def real_nt_hash(self) -> str | None:
        """The ``nt_hash`` only when it is a genuine 32-hex NTLM hash.

        Some phases (kerberoast / AS-REP roast) stash a crackable ``$krb5*``
        blob in the ``nt_hash`` slot for loot purposes. Those blobs are NOT
        usable for authentication (pass-the-hash, BloodHound ``--hashes`` ...);
        this guard lets consumers tell a real hash from a stashed blob.
        """
        h = self.nt_hash
        if h and re.fullmatch(r"[0-9a-fA-F]{32}", h):
            return h
        return None

    @property
    def has_auth_secret(self) -> bool:
        """True when this credential carries material usable to authenticate.

        A cleartext password or a genuine NT hash — NOT a stashed roast blob.
        Tickets are handled by their own Kerberos flow, not here.
        """
        return bool(self.password) or self.real_nt_hash is not None


@dataclass
class CertificateAuthority:
    ip: str
    ca_name: str = ""
    web_enrollment_url: str = ""
    tags: list[str] = field(default_factory=list)


@dataclass
class Finding:
    id: str
    title: str
    severity: str          # "info", "low", "medium", "high", "critical"
    host: str = ""
    description: str = ""
    remediation: str = ""
    evidence: str = ""
    # Optional free-text override describing *how* the finding was discovered.
    # When empty, the methodology is derived from the finding ``id`` via
    # ``core.methodology`` (catalog lookup) for both the terminal and report.
    method: str = ""
    # "anonymous" = no credentials needed, "authenticated" = valid creds required, "" = unknown.
    auth_context: str = ""
    # A copyable command for this finding, shown in the report with a copy
    # button so the operator can continue by hand. It is either the exact
    # command the tool ran (e.g. the nxc call that flagged the host) or, for
    # findings raised by pure in-process probes (impacket/ldap3), a canonical
    # command to reproduce or exploit the finding. Empty when neither applies.
    command: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


@dataclass
class Activity:
    """One test the tool fired at the network, for SOC/blue-team correlation.

    This is the unit of the *detection-test log*: a precise, machine-readable
    record of *when* (UTC + local timestamp), from *which source IP*, against
    *which target*, the tool ran *which test* (named and mapped to MITRE
    ATT&CK), with *which tool/command*, and the *outcome*. A SOC ingests the
    resulting CSV to verify their EDR/SIEM detected the activity and to
    correlate alerts back to a concrete technique by timestamp + IP.

    UTC is recorded explicitly (``timestamp``) because cross-correlating with
    a SIEM requires an unambiguous, timezone-anchored time; ``timestamp_local``
    is kept alongside for human reading of the report.
    """

    event_id: str
    timestamp: str            # ISO 8601, UTC (authoritative for correlation)
    timestamp_local: str      # ISO 8601, local time (human-friendly)
    phase: str
    technique_key: str
    mitre_id: str
    mitre_tactic: str
    technique: str            # human-readable technique name
    source_ip: str            # attacker / tool source IP
    target_ip: str            # single host (correlation key); empty for sweeps
    target_host: str
    port: int | None
    protocol: str
    tool: str
    command: str
    status: str               # "executed", "completed", "failed", "skipped"
    details: str
    # Target *set* for multi-host operations (nmap/ARP/ICMP sweeps, --shares
    # across the scope, ...): a CIDR ("192.168.56.0/24"), a range, or a
    # comma-separated IP list. Empty for single-host activities, where
    # ``target_ip`` already carries the host. Has a default so older saved
    # states (without this field) still reload cleanly.
    targets: str = ""


# Column order for the SOC CSV - front-loads the fields an analyst pivots on
# (time, source, target, technique) so the file reads left-to-right by
# relevance. Shared by the live writer here and the report exporter.
ACTIVITY_CSV_COLUMNS = [
    "event_id",
    "timestamp",
    "timestamp_local",
    "phase",
    "mitre_id",
    "mitre_tactic",
    "technique",
    "technique_key",
    "source_ip",
    "target_ip",
    "targets",
    "target_host",
    "port",
    "protocol",
    "tool",
    "command",
    "status",
    "details",
]


class TargetManager:
    """Shared engagement state."""

    def __init__(self, loot_dir: str = "./loot"):
        self.loot_dir = Path(loot_dir)
        self.loot_dir.mkdir(parents=True, exist_ok=True)
        self._lock = RLock()

        self.hosts: dict[str, Host] = {}
        self.domains: dict[str, dict] = {}
        self.users: set[str] = set()
        self.credentials: list[Credential] = []
        self.findings: list[Finding] = []
        self.modifications: list[dict] = []
        self.certificate_authorities: list[CertificateAuthority] = []
        self.started_at: str = datetime.now().isoformat()

        # SOC detection-test log: every test fired at the network, recorded
        # for blue-team correlation (see :meth:`record_activity`). Streamed to
        # a CSV in the loot dir as it happens so the log survives a crash.
        self.activities: list[Activity] = []
        self._activity_seq: int = 0
        self._source_ip_cache: dict[str, str] = {}
        self.soc_csv_path: Path = self.loot_dir / "soc_detection_log.csv"

        # Command ledger: the actual external commands the tool ran, captured
        # where each wrapper builds its argv. Surfaced in the HTML report so the
        # operator can copy a command and keep going by hand after the run.
        self.commands: list[dict] = []

    # --- Hosts ---------------------------------------------------------

    # Boolean flags that may only be promoted (False -> True), never
    # demoted. Multiple recon sources flip ``is_dc`` and ``is_adcs``
    # based on the signal they happen to see (LDAP RootDSE, NetBIOS,
    # SMB OS discovery, NSE script output). A later source that misses
    # the signal must not be allowed to silently overwrite an earlier
    # positive identification - otherwise the second DC found in a
    # multi-DC engagement could "unmark" the first one.
    _STICKY_TRUE_FLAGS = ("is_dc", "is_adcs")

    def add_host(self, ip: str, **kwargs: Any) -> Host:
        with self._lock:
            host = self.hosts.get(ip)
            if host is None:
                host = Host(ip=ip)
                self.hosts[ip] = host
            for k, v in kwargs.items():
                if v is None or v == "":
                    continue
                if k in self._STICKY_TRUE_FLAGS and getattr(host, k, False) and not v:
                    continue
                if hasattr(host, k):
                    setattr(host, k, v)
            return host

    def get_host(self, ip: str) -> Host | None:
        return self.hosts.get(ip)

    def alive_hosts(self) -> list[Host]:
        return list(self.hosts.values())

    def dcs(self) -> list[Host]:
        return [h for h in self.hosts.values() if h.is_dc]

    # --- Domains -------------------------------------------------------

    def add_domain(self, name: str, **kwargs: Any) -> None:
        with self._lock:
            entry = self.domains.setdefault(name.lower(), {"name": name.lower()})
            entry.update({k: v for k, v in kwargs.items() if v is not None})

    # --- Users / creds -------------------------------------------------

    def add_user(self, username: str) -> None:
        with self._lock:
            if username:
                self.users.add(username.lower())

    def add_credential(self, cred: Credential) -> None:
        with self._lock:
            # Deduplicate: same username + domain + secret (password or hash).
            for existing in self.credentials:
                if (
                    existing.username.lower() == cred.username.lower()
                    and existing.domain.lower() == cred.domain.lower()
                    and existing.password == cred.password
                    and existing.nt_hash == cred.nt_hash
                ):
                    return
            self.credentials.append(cred)

    # --- Findings ------------------------------------------------------

    def add_finding(self, finding: Finding) -> None:
        with self._lock:
            # Deduplicate by ID — a re-run must not accumulate identical findings.
            if any(f.id == finding.id for f in self.findings):
                return
            self.findings.append(finding)
        # Surface a one-line "how it was found" note right after the finding is
        # recorded, so the operator sees the technique in context with the live
        # scan output. The detailed version is rendered in the report. Logging
        # must never break state recording, hence the broad guard.
        try:
            from core.logger import (  # noqa: PLC0415 - avoid import cycle
                get_logger,
                severity_marker,
            )
            from core.methodology import explain  # noqa: PLC0415

            get_logger().info(
                f"    {severity_marker(finding.severity)} "
                f"how it was found -> {explain(finding).short}"
            )
        except Exception:
            pass

    def add_ca(self, ca: CertificateAuthority) -> None:
        with self._lock:
            if not any(c.ip == ca.ip for c in self.certificate_authorities):
                self.certificate_authorities.append(ca)

    # --- SOC detection-test log ----------------------------------------

    def _resolve_source_ip(self, target_ip: str) -> str:
        """Local source IP the tool uses toward ``target_ip`` (cached).

        For broadcast / link-local techniques (poisoning) ``target_ip`` is
        empty; we then probe toward the first known DC, else the first host,
        else the default egress, so the row still carries a real source IP.
        """
        hint = target_ip
        if not hint:
            dcs = self.dcs()
            if dcs:
                hint = dcs[0].ip
            elif self.hosts:
                hint = next(iter(self.hosts))
        if hint in self._source_ip_cache:
            return self._source_ip_cache[hint]
        ip = source_ip_for(hint)
        self._source_ip_cache[hint] = ip
        return ip

    def record_activity(
        self,
        technique_key: str,
        target_ip: str = "",
        *,
        phase: str = "",
        targets: str = "",
        target_host: str = "",
        port: int | None = None,
        protocol: str = "",
        tool: str = "",
        command: str = "",
        status: str = "executed",
        details: str = "",
        source_ip: str | None = None,
    ) -> Activity:
        """Record one test fired at the network for SOC/blue-team correlation.

        ``technique_key`` is resolved against :mod:`core.attack_catalog` to
        fill the MITRE id / tactic / human name and to default the tool, port
        and protocol when the caller omits them. ``source_ip`` is auto-resolved
        from the host routing table toward ``target_ip`` when not supplied.

        The activity is appended to the engagement state (persisted in
        ``state.json``) and a row is streamed immediately to the SOC CSV, so a
        crash mid-engagement still leaves the blue team a complete log up to
        the failure point. Recording never raises: a logging failure must not
        abort a live test (mirrors :meth:`add_finding`).
        """
        tech = attack_catalog.lookup(technique_key)
        host = self.hosts.get(target_ip) if target_ip else None
        with self._lock:
            self._activity_seq += 1
            now = datetime.now(timezone.utc)
            activity = Activity(
                event_id=f"EVT-{self._activity_seq:06d}",
                timestamp=now.isoformat(timespec="milliseconds"),
                timestamp_local=datetime.now().isoformat(timespec="milliseconds"),
                phase=phase,
                technique_key=technique_key,
                mitre_id=tech.mitre_id,
                mitre_tactic=tech.tactic,
                technique=tech.name,
                source_ip=source_ip if source_ip is not None
                else self._resolve_source_ip(target_ip),
                target_ip=target_ip,
                targets=targets,
                target_host=target_host or (host.hostname if host else ""),
                port=port if port is not None else tech.port,
                protocol=protocol or tech.proto,
                tool=tool or tech.tool,
                command=command,
                status=status,
                details=details,
            )
            self.activities.append(activity)
            try:
                self._append_activity_csv(activity)
            except OSError:
                pass
        return activity

    def record_command(
        self,
        command: str | list[str],
        *,
        phase: str = "",
        tool: str = "",
        target: str = "",
        status: str = "executed",
    ) -> None:
        """Record one external command the tool executed, for the report.

        ``command`` may be a raw string or an argv list (joined with spaces).
        This is the operator-facing "what did we run" ledger: the HTML report
        renders it as a copy-pasteable list so the operator can rerun or
        continue a command by hand after the automated pass. Recording never
        raises - a bookkeeping failure must not abort a live test.
        """
        cmd_str = command if isinstance(command, str) else " ".join(str(c) for c in command)
        with self._lock:
            self.commands.append({
                "phase": phase,
                "tool": tool,
                "target": target,
                "command": cmd_str,
                "status": status,
            })

    def _append_activity_csv(self, activity: Activity) -> None:
        """Stream one activity row to the live SOC CSV (header on first write)."""
        self.soc_csv_path.parent.mkdir(parents=True, exist_ok=True)
        write_header = not self.soc_csv_path.exists()
        with self.soc_csv_path.open("a", encoding="utf-8", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=ACTIVITY_CSV_COLUMNS)
            if write_header:
                writer.writeheader()
            writer.writerow(asdict(activity))

    # --- Persistence ---------------------------------------------------

    def to_dict(self) -> dict:
        return {
            "started_at": self.started_at,
            "hosts": {ip: asdict(h) for ip, h in self.hosts.items()},
            "domains": self.domains,
            "users": sorted(self.users),
            "credentials": [asdict(c) for c in self.credentials],
            "findings": [asdict(f) for f in self.findings],
            "modifications": list(self.modifications),
            "certificate_authorities": [asdict(c) for c in self.certificate_authorities],
            "activities": [asdict(a) for a in self.activities],
            "commands": list(self.commands),
        }

    def save(self, path: str | Path | None = None) -> Path:
        target = Path(path) if path else self.loot_dir / "state.json"
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("w", encoding="utf-8") as fh:
            json.dump(self.to_dict(), fh, indent=2, default=str)
        return target

    def load_from_json(self, path: str | Path) -> bool:
        """Restore engagement state from a previous :meth:`save` output.

        Best-effort: unknown fields are dropped, missing sections are
        treated as empty. Used by Phase 4 so ``--phase exploit`` can
        run standalone after Phase 2 completed in a previous
        invocation. Returns ``True`` when the file was found and
        parsed, ``False`` otherwise (no exception is raised - callers
        decide whether to skip).
        """
        p = Path(path)
        if not p.is_file():
            return False
        try:
            with p.open("r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, ValueError):
            return False

        with self._lock:
            self.started_at = data.get("started_at", self.started_at)
            host_field_names = {f.name for f in fields(Host)}
            for ip, host_data in (data.get("hosts") or {}).items():
                services_raw = host_data.get("services") or []
                services = []
                svc_field_names = {f.name for f in fields(Service)}
                for s in services_raw:
                    services.append(
                        Service(**{k: v for k, v in s.items() if k in svc_field_names})
                    )
                kwargs = {
                    k: v for k, v in host_data.items()
                    if k in host_field_names and k != "services"
                }
                host = Host(**kwargs)
                host.services = services
                self.hosts[ip] = host

            for name, dom in (data.get("domains") or {}).items():
                self.domains[name.lower()] = dom

            for u in data.get("users") or []:
                self.users.add(u.lower())

            cred_field_names = {f.name for f in fields(Credential)}
            seen_creds: set[tuple] = set()
            for c in data.get("credentials") or []:
                cred = Credential(**{k: v for k, v in c.items() if k in cred_field_names})
                key = (cred.username.lower(), cred.domain.lower(), cred.password, cred.nt_hash)
                if key not in seen_creds:
                    seen_creds.add(key)
                    self.credentials.append(cred)

            finding_field_names = {f.name for f in fields(Finding)}
            seen_findings: set[str] = set()
            for f in data.get("findings") or []:
                finding = Finding(**{k: v for k, v in f.items() if k in finding_field_names})
                if finding.id not in seen_findings:
                    seen_findings.add(finding.id)
                    self.findings.append(finding)

            self.modifications.extend(data.get("modifications") or [])

            ca_field_names = {f.name for f in fields(CertificateAuthority)}
            for c in data.get("certificate_authorities") or []:
                self.certificate_authorities.append(
                    CertificateAuthority(
                        **{k: v for k, v in c.items() if k in ca_field_names}
                    )
                )

            # Restore the detection-test log and resume the event sequence so a
            # standalone later phase keeps emitting unique, monotonic event ids.
            activity_field_names = {f.name for f in fields(Activity)}
            for a in data.get("activities") or []:
                self.activities.append(
                    Activity(**{k: v for k, v in a.items() if k in activity_field_names})
                )
            if self.activities:
                self._activity_seq = max(self._activity_seq, len(self.activities))

            for c in data.get("commands") or []:
                if isinstance(c, dict):
                    self.commands.append(c)
        return True
