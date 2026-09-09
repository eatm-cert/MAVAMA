"""Interactive CLI setup wizard for Mavama.

Triggered on startup when no explicit --config flag is provided.
Lets the operator either load an existing YAML configuration or build
a new one interactively, then returns the resolved config Path to main.
"""

from __future__ import annotations

import copy
import sys
from pathlib import Path
from typing import Any

import questionary
import yaml

try:
    import psutil
    _HAS_PSUTIL = True
except ImportError:
    _HAS_PSUTIL = False

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
CONFIG_DIR = _PROJECT_ROOT / "config"
WORDLISTS_DIR = _PROJECT_ROOT / "wordlists"


_CREDENTIALS_DEFAULTS: dict[str, Any] = {
    "asreproast": {"enabled": True, "timeout": 120},
    "kerberoast": {"enabled": True, "timeout": 120},
    "spraying": {
        "enabled": False,
        "protocol": "smb",
        "targets": [],
        "passwords": [],
        "probe_password_policy": True,
        "safety_margin": 2,
        "timeout": 300,
    },
    "dumping": {"enabled": False, "operations": []},
}

_RECON_DEFAULTS: dict[str, Any] = {
    "host_discovery": {
        "arp_scan": True,
        "ping_sweep": True,
        "tcp_ping_ports": [445, 135, 3389],
        "timeout": 2,
    },
    "port_scan": {
        "ports": [
            53, 88, 135, 139, 389, 445, 464, 636,
            1433, 3268, 3269, 3389, 5985, 5986, 8080, 8443,
        ],
        "rate": 1000,
        "timeout": 300,
    },
    "anon_enum": {
        "smb_null_session": True,
        "ldap_anonymous_bind": True,
        "rid_bruteforce": True,
        "rid_range": [500, 1500],
        "vuln_checks": True,
    },
    "user_enum": {
        "enabled": True,
        "userlist": "./wordlists/users.txt",
        "threads": 10,
    },
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _list_interfaces() -> list[str]:
    """Return available network interface names, sorted."""
    if _HAS_PSUTIL:
        return sorted(psutil.net_if_addrs().keys())
    # Fallback: parse /proc/net/dev on Linux
    interfaces: list[str] = []
    try:
        with open("/proc/net/dev") as fh:
            for line in fh:
                line = line.strip()
                if ":" in line:
                    interfaces.append(line.split(":")[0].strip())
    except OSError:
        pass
    return interfaces or ["eth0", "lo"]


def _detect_interface_for_subnet(subnet: str) -> str | None:
    """Return the local interface whose address is in the same L2 segment as subnet.

    Mirrors the logic used by HostDiscovery._get_iface_for_target so that the
    wizard pre-selects the correct NIC before the user can confirm.
    """
    import ipaddress
    import socket

    if not _HAS_PSUTIL:
        return None
    try:
        net = ipaddress.ip_network(subnet, strict=False)
        for iface, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == socket.AF_INET:
                    try:
                        local_net = ipaddress.ip_network(
                            f"{addr.address}/{addr.netmask}", strict=False
                        )
                        if net.overlaps(local_net):
                            return iface
                    except Exception:
                        pass
    except Exception:
        pass
    return None


def _list_config_files() -> list[str]:
    """Return paths (relative to project root) for every .yaml in config/."""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    return sorted(
        str(p.relative_to(_PROJECT_ROOT))
        for p in CONFIG_DIR.rglob("*.yaml")
        if p.is_file()
        and p.name != ".effective.yaml"
        and not any(part.startswith(".") for part in p.relative_to(CONFIG_DIR).parts)
    )


def _resolve_project_path(raw_path: str, *, default: Path | None = None) -> Path:
    """Resolve a user-provided path relative to the project root."""
    candidate = raw_path.strip()
    if not candidate:
        if default is None:
            raise ValueError("A path or default value is required.")
        path = default
    else:
        path = Path(candidate).expanduser()

    if not path.is_absolute():
        path = (_PROJECT_ROOT / path).resolve()
    else:
        path = path.resolve()
    return path


def _load_passwords_from_file(path: Path) -> list[str]:
    """Load spray passwords from a text file, one password per line."""
    passwords: list[str] = []
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            cleaned = line.strip()
            if not cleaned or cleaned.startswith("#"):
                continue
            passwords.append(cleaned)
    return passwords


def _default_output_path(engagement_name: str) -> Path:
    """Return the default output path for a generated engagement config."""
    return CONFIG_DIR / "generated" / f"{engagement_name}.yaml"


def _resolve_output_path(raw_path: str, engagement_name: str) -> Path:
    """Resolve the config output path and normalize missing YAML suffixes."""
    path = _resolve_project_path(raw_path, default=_default_output_path(engagement_name))
    if path.suffix == "":
        path = path.with_suffix(".yaml")
    return path


def _prompt_credentials_manually(domain_hint: str | None) -> list[dict]:
    """Collect one or more credentials interactively and return a list of dicts."""
    import re
    _nt_re = re.compile(r"^[0-9a-fA-F]{32}$")
    _lmnt_re = re.compile(r"^[0-9a-fA-F]{32}:[0-9a-fA-F]{32}$")

    creds: list[dict] = []
    while True:
        print("\n  -- Credential entry --")

        username = _ask(
            questionary.text,
            "Username (sAMAccountName):",
            validate=lambda v: bool(v.strip()) or "Username is required.",
        ).strip()

        domain_val = _ask(
            questionary.text,
            "AD domain name (e.g. corp.local or CORP — not the word 'FQDN'):",
            default=domain_hint or "",
            validate=lambda v: bool(v.strip()) or "Domain is required.",
        ).strip()

        auth_type = _ask(
            questionary.select,
            "Authentication type:",
            choices=[
                questionary.Choice("Cleartext password", value="password"),
                questionary.Choice("NT hash  (pass-the-hash)", value="nt_hash"),
                questionary.Choice("Kerberos ticket  (pass-the-ticket)", value="ticket"),
            ],
        )

        password: str | None = None
        nt_hash: str | None = None
        lm_hash: str | None = None
        ticket: str | None = None

        if auth_type == "password":
            password = _ask(questionary.text, "Password:") or None

        elif auth_type == "nt_hash":
            def _validate_hash(v: str) -> bool | str:
                v = v.strip()
                if _nt_re.match(v) or _lmnt_re.match(v):
                    return True
                return "Expected 32 hex chars (NT only) or LM:NT format."

            raw_hash = _ask(
                questionary.text,
                "Hash (32 hex chars, or LM:NT):",
                validate=_validate_hash,
            ).strip()
            if ":" in raw_hash:
                lm_hash, nt_hash = raw_hash.split(":", 1)
            else:
                nt_hash = raw_hash

        elif auth_type == "ticket":
            ticket = _ask(
                questionary.text,
                "Kerberos ticket (base64 blob or path to .ccache):",
                validate=lambda v: bool(v.strip()) or "Ticket value is required.",
            ).strip() or None

        source = _ask(
            questionary.text,
            "Source tag (e.g. client-provided, phishing):",
            default="client-provided",
        ).strip()

        creds.append({
            "username": username,
            "domain": domain_val,
            "password": password,
            "nt_hash": nt_hash,
            "lm_hash": lm_hash,
            "ticket": ticket,
            "source": source,
        })
        print(f"  [+] Added credential: {username}@{domain_val}")

        if not _ask(questionary.confirm, "Add another credential?", default=False):
            break

    return creds


def _prompt_spray_passwords() -> list[str]:
    """Collect spray passwords either manually or from a text file."""
    source = _ask(
        questionary.select,
        "How do you want to provide spray passwords?",
        choices=[
            questionary.Choice("Enter passwords manually", value="manual"),
            questionary.Choice(
                "Load passwords from a text file",
                value="file",
            ),
        ],
    )

    if source == "manual":
        pw_raw = _ask(
            questionary.text,
            "Passwords to spray (comma-separated):",
            default="Password1,Welcome1",
        ).strip()
        return [p.strip() for p in pw_raw.split(",") if p.strip()]

    default_file = WORDLISTS_DIR / "test_passwords.txt"

    def _validate_password_file(value: str):
        path = _resolve_project_path(value, default=default_file)
        return path.is_file() or f"Password file not found: {path}"

    file_raw = _ask(
        questionary.text,
        "Password file path:",
        default=str(default_file.relative_to(_PROJECT_ROOT)),
        validate=_validate_password_file,
    )
    path = _resolve_project_path(file_raw, default=default_file)
    return _load_passwords_from_file(path)


def _describe_targets(nets: list[str]) -> str:
    """Return a compact human-readable description of a list of CIDR strings.

    Example: ['192.168.56.1/32', '192.168.56.2/31', ..., '192.168.56.24/32']
             → '192.168.56.1 - 192.168.56.24  (24 addresses)'
    """
    import ipaddress

    if not nets:
        return "(none)"
    parsed = sorted(ipaddress.ip_network(n) for n in nets)
    total = sum(n.num_addresses for n in parsed)
    first = str(parsed[0].network_address)
    last = str(parsed[-1].broadcast_address)
    if total == 1:
        return first
    if len(nets) == 1:
        return nets[0]
    return f"{first} - {last}  ({total} addresses)"


def _effective_scope_count(target_nets: list[str], exclude_list: list[str]) -> int:
    """Count IPs remaining in scope after applying exclusions."""
    import ipaddress

    targets: set[ipaddress.IPv4Address] = set()
    for net_str in target_nets:
        targets.update(ipaddress.ip_network(net_str))

    excluded: set[ipaddress.IPv4Address] = set()
    for entry in exclude_list:
        try:
            excluded.update(ipaddress.ip_network(entry, strict=False))
        except ValueError:
            try:
                excluded.add(ipaddress.ip_address(entry))
            except ValueError:
                pass

    return len(targets - excluded)


def _normalize_target_input(raw: str) -> list[str]:
    """Normalize a user-provided target expression into a list of CIDR strings.

    Supported forms:
    - CIDR:                10.0.0.0/24
    - explicit IP range:   192.168.56.1-192.168.56.254
    - last-octet range:    192.168.56.1-24    -> 192.168.56.1 … 192.168.56.24 (24 IPs)
    - /prefix suffix:      192.168.56.1-24/24 -> suffix stripped, treated as range above
    - comma-separated:     10.0.0.0/24, 192.168.56.1-24/24
    """
    import ipaddress

    parts = [p.strip() for p in raw.split(",") if p.strip()]
    if not parts:
        raise ValueError("Empty target expression")

    nets: list[str] = []
    for part in parts:
        # direct CIDR
        try:
            net = ipaddress.ip_network(part, strict=False)
            nets.append(str(net))
            continue
        except Exception:
            pass

        # range with dash
        # If the part contains both a dash (range indicator) and /prefix,
        # strip the /prefix and treat the dash-separated part as a true range.
        # E.g. '192.168.56.1-24/24' -> '192.168.56.1-24' -> range 1 to 24.
        import re
        if "-" in part and "/" in part:
            part = re.sub(r"/\d{1,2}$", "", part)

        if "-" in part:
            left, right = (s.strip() for s in part.split("-", 1))

            # if right looks like a number, decide whether it's a prefix
            # length (e.g. '24') or a last-octet shorthand (e.g. 1-24).
            if right.isdigit():
                rint = int(right)
                # Prefer last-octet shorthand when right is <=255 and left is an IP
                if rint <= 255 and left.count(".") == 3:
                    try:
                        start_ip = ipaddress.ip_address(left)
                        parts_left = left.split(".")
                        parts_left[-1] = right
                        end_ip = ipaddress.ip_address(".".join(parts_left))
                        for n in ipaddress.summarize_address_range(start_ip, end_ip):
                            nets.append(str(n))
                        continue
                    except Exception:
                        raise ValueError(f"Invalid shorthand range: {part}")

                # Treat as prefix only if the left looks like a network base (endswith .0)
                if 0 < rint <= 32 and left.endswith(".0"):
                    try:
                        net = ipaddress.ip_network(f"{left}/{rint}", strict=False)
                        nets.append(str(net))
                        continue
                    except Exception:
                        raise ValueError(f"Invalid ip/prefix combination: {part}")

            # full ip range
            try:
                start_ip = ipaddress.ip_address(left)
                end_ip = ipaddress.ip_address(right)
                for n in ipaddress.summarize_address_range(start_ip, end_ip):
                    nets.append(str(n))
                continue
            except Exception:
                raise ValueError(f"Invalid range format: {part}")

        raise ValueError(f"Invalid target format: {part}")

    return nets


def _ask(prompt_fn, *args, **kwargs):
    """Call a questionary prompt and exit cleanly on Ctrl+C (None return)."""
    result = prompt_fn(*args, **kwargs).ask()
    if result is None:
        print("\n[!] Setup cancelled by user.", file=sys.stderr)
        sys.exit(130)
    return result


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def _phase_sections(phase: str | None) -> set[str]:
    """Which wizard question groups are relevant for the requested ``--phase``.

    Sections:
      * ``creds`` - engagement mode (black/grey box) + credentials.
      * ``recon`` - Phase 1 Kerberos user-enum wordlist.
      * ``spray`` - Phase 3 password spraying.

    Scope, interface, domain, reporting and logging are always asked (every
    phase needs them). An unknown phase (or ``all``) asks everything relevant
    to this edition (there is no relay phase in the public build).
    """
    per_phase = {
        "recon":        {"creds", "recon"},
        "authed-recon": {"creds"},
        "credentials":  {"creds", "spray"},
        "report":       set(),
    }
    return per_phase.get((phase or "all").lower(), {"creds", "recon", "spray"})


def run_setup_wizard(phase: str | None = None) -> Path:
    """Run the interactive setup wizard and return the config file Path.

    ``phase`` is the ``--phase`` the operator asked for; the creation wizard
    only asks the questions relevant to it (e.g. ``--phase recon`` skips the
    spraying questions). Defaults to asking everything.
    """
    print()  # visual separation after the banner

    action = _ask(
        questionary.select,
        "How do you want to configure this engagement?",
        choices=[
            questionary.Choice("Load an existing configuration file", value="load"),
            questionary.Choice("Create a new engagement interactively", value="create"),
        ],
    )

    if action == "load":
        return _load_existing(phase=phase)
    return _create_new(phase=phase)


# ---------------------------------------------------------------------------
# Load flow
# ---------------------------------------------------------------------------

def _load_existing(phase: str | None = None) -> Path:
    yaml_files = _list_config_files()
    if not yaml_files:
        print(
            f"[!] No .yaml files found in {CONFIG_DIR}. "
            "Switching to creation wizard.",
            file=sys.stderr,
        )
        return _create_new(phase=phase)

    chosen = _ask(
        questionary.select,
        "Select a configuration file:",
        choices=yaml_files,
    )
    path = (_PROJECT_ROOT / chosen).resolve()
    print(f"[+] Loaded: {chosen}")
    return path


# ---------------------------------------------------------------------------
# Create flow
# ---------------------------------------------------------------------------

def _create_new(phase: str | None = None) -> Path:  # noqa: PLR0912  (intentional: linear Q&A wizard)
    print("\n  -- New Engagement --\n")

    # Only ask the questions relevant to the requested --phase. Skipped groups
    # fall back to their defaults so the written config stays complete.
    sections = _phase_sections(phase)
    if phase and phase not in ("all", None):
        print(f"  [i] Configuring for '--phase {phase}': asking only the relevant questions.\n")

    # --- Identity -----------------------------------------------------------
    engagement_name = (
        _ask(
            questionary.text,
            "Engagement name:",
            default="client-audit",
            validate=lambda v: bool(v.strip()) or "Name cannot be empty.",
        )
        .strip()
        .replace(" ", "-")
    )

    output_path_raw = _ask(
        questionary.text,
        "Output configuration file path:",
        default=str(_default_output_path(engagement_name).relative_to(_PROJECT_ROOT)),
    ).strip()

    operator = _ask(
        questionary.text,
        "Operator name:",
        default="pentester",
    ).strip()

    safe_mode = _ask(
        questionary.confirm,
        "Enable safe mode? (enumeration only - no password spraying or credential dumping)",
        default=False,
    )

    # Execution pacing: run the whole phase end-to-end, or pause after each
    # step so the operator can review results and decide whether to continue.
    execution_mode = _ask(
        questionary.select,
        "Execution mode:",
        choices=[
            questionary.Choice(
                "Auto         - run each phase end-to-end without pausing",
                value="auto",
            ),
            questionary.Choice(
                "Step-by-step - review results after each step, then continue/skip/stop",
                value="step",
            ),
        ],
    )

    # --- Scope --------------------------------------------------------------
    def _validate_target(value: str):
        if not value or not value.strip():
            return "Target subnet is required."
        try:
            _normalize_target_input(value)
            return True
        except Exception as exc:
            return str(exc)

    # Collect one or more target ranges. A single entry may already carry
    # several comma-separated ranges; the loop lets the operator append more
    # without cramming everything onto one line.
    target_subnets: list[str] = []
    while True:
        target_subnet_raw = _ask(
            questionary.text,
            "Target subnet or range (CIDR or range, e.g. 10.0.0.0/24 or "
            "192.168.56.0-24; comma-separated allowed):",
            validate=_validate_target,
        ).strip()
        target_subnets.extend(_normalize_target_input(target_subnet_raw))
        print(f"    [+] Scope now: {_describe_targets(target_subnets)}")
        if not _ask(
            questionary.confirm,
            "Add another target range?",
            default=False,
        ):
            break

    exclude_raw = _ask(
        questionary.text,
        "IPs/ranges to exclude (comma-separated, e.g. 192.168.56.1, blank for none):",
        default="",
    ).strip()
    exclude = [ip.strip() for ip in exclude_raw.split(",") if ip.strip()] if exclude_raw else []

    # --- Network ------------------------------------------------------------
    # Auto-detect the interface that can reach the first target subnet so we
    # can pre-select the right NIC.  The ARP scan silently uses the wrong
    # interface (default route NIC instead of the host-only adapter) when
    # this is left to "auto-detect".
    interfaces = _list_interfaces()
    detected_iface = _detect_interface_for_subnet(target_subnets[0]) if target_subnets else None
    hint = f" [detected: {detected_iface}]" if detected_iface else ""
    iface_default = detected_iface if (detected_iface and detected_iface in interfaces) else "auto-detect"
    chosen_iface = _ask(
        questionary.select,
        f"Network interface{hint}:",
        choices=interfaces + ["auto-detect"],
        default=iface_default,
    )
    interface: str | None = None if chosen_iface == "auto-detect" else chosen_iface

    domain_raw = _ask(
        questionary.text,
        "AD domain hint (blank = auto-discover via DNS/LDAP):",
        default="",
    ).strip()
    domain: str | None = domain_raw or None

    # --- Credentials file (grey box) ----------------------------------------
    # Two engagement modes:
    #   black box -> no credential up front; full auto-discovery. The operator
    #                can still inject credentials after recon (authenticated
    #                reconnaissance, Phase 1b).
    #   grey box  -> one or more accounts already known; authenticated recon
    #                runs automatically right after Phase 1.
    engagement_mode = "black"
    credentials_file: str | None = None
    if "creds" in sections:
        engagement_mode = _ask(
            questionary.select,
            "Engagement mode:",
            choices=[
                questionary.Choice(
                    "Black box  - no credentials, full auto-discovery",
                    value="black",
                ),
                questionary.Choice(
                    "Grey box   - one or more accounts already known",
                    value="grey",
                ),
            ],
        )

    if engagement_mode == "grey":
        cred_source = _ask(
            questionary.select,
            "How do you want to provide credentials?",
            choices=[
                questionary.Choice("Enter credentials manually", value="manual"),
                questionary.Choice("Load from an existing YAML file", value="file"),
            ],
        )

        if cred_source == "manual":
            manual_creds = _prompt_credentials_manually(domain)
            cred_out = (
                CONFIG_DIR / "generated" / f"{engagement_name}_credentials.yaml"
            )
            cred_out.parent.mkdir(parents=True, exist_ok=True)
            with cred_out.open("w", encoding="utf-8") as fh:
                yaml.safe_dump(
                    {"credentials": manual_creds},
                    fh,
                    sort_keys=False,
                    allow_unicode=True,
                )
            credentials_file = str(cred_out.relative_to(_PROJECT_ROOT))
            print(f"  [+] Credentials saved to {credentials_file}")

        else:
            template = Path("config/credentials.template.yaml")
            print(
                f"\n  [i] Fill in {template} (copy it first) then provide the path below."
            )

            def _validate_cred_file(value: str):
                if not value.strip():
                    return "Path is required for grey box mode."
                p = Path(value.strip())
                return p.is_file() or f"File not found: {p}"

            cred_path_raw = _ask(
                questionary.text,
                "Path to credentials YAML file:",
                default="config/credentials.yaml",
                validate=_validate_cred_file,
            ).strip()
            credentials_file = cred_path_raw

    # --- Kerberos user enumeration (Phase 1) --------------------------------
    # AS-REQ user enumeration tests a list of candidate usernames against the
    # KDC. The operator chooses the source of that list: the bundled default
    # wordlist, a custom file, or none (built-in common names + any user
    # already discovered during recon).
    user_enum_wordlist: str | None = "./wordlists/users.txt"
    if "recon" in sections:
        kerb_choice = _ask(
            questionary.select,
            "Kerberos user-enum wordlist (AS-REQ enumeration against the KDC):",
            choices=[
                questionary.Choice(
                    "Default wordlist (./wordlists/users.txt)", value="default"
                ),
                questionary.Choice("Custom wordlist file", value="custom"),
                questionary.Choice(
                    "No wordlist - built-in common names + discovered users only",
                    value="none",
                ),
            ],
        )

        if kerb_choice == "default":
            user_enum_wordlist = "./wordlists/users.txt"
        elif kerb_choice == "custom":
            def _validate_wordlist(value: str):
                if not value.strip():
                    return "Path is required (or pick another option)."
                p = _resolve_project_path(value)
                return p.is_file() or f"File not found: {p}"

            wl_raw = _ask(
                questionary.text,
                "Path to the user wordlist:",
                default="./wordlists/users.txt",
                validate=_validate_wordlist,
            ).strip()
            user_enum_wordlist = wl_raw
        else:
            user_enum_wordlist = None

    # --- Credentials / Phase 3 ----------------------------------------------
    enable_spraying = False
    spray_passwords: list[str] = []
    if "spray" in sections:
        enable_spraying = _ask(
            questionary.confirm,
            "Enable password spraying in Phase 3?",
            default=False,
        )
        if enable_spraying:
            spray_passwords = _prompt_spray_passwords()

    # --- Reporting ----------------------------------------------------------
    generate_report = _ask(
        questionary.confirm,
        "Generate an HTML report at the end of each phase?",
        default=True,
    )

    # --- Logging ------------------------------------------------------------
    log_level = _ask(
        questionary.select,
        "Log verbosity:",
        choices=["INFO", "DEBUG", "WARNING", "ERROR"],
    )

    # --- Assemble config dict -----------------------------------------------
    # Deep-copy the recon defaults before overriding the user-enum wordlist so
    # the module-level template is never mutated across wizard invocations.
    recon_cfg = copy.deepcopy(_RECON_DEFAULTS)
    recon_cfg["user_enum"]["userlist"] = user_enum_wordlist

    cfg: dict[str, Any] = {
        "engagement": {
            "name": engagement_name,
            "operator": operator,
            "safe_mode": safe_mode,
            "execution_mode": execution_mode,
        },
        "scope": {
            "targets": target_subnets,
            "exclude": exclude,
        },
        "interface": interface,
        "domain": domain,
        # External tools to remove from the engagement. Left empty here; the
        # startup tool preflight (utils/tool_preflight.py) lets the operator
        # prune this interactively right before the run.
        "tools": {"disabled": []},
        "credentials_file": credentials_file,
        "logging": {
            "level": log_level,
            "log_dir": "./logs",
            "loot_dir": "./loot",
        },
        "recon": recon_cfg,
        "credentials": {
            **_CREDENTIALS_DEFAULTS,
            "spraying": {
                **_CREDENTIALS_DEFAULTS["spraying"],
                "enabled": enable_spraying,
                "passwords": spray_passwords,
            },
        },
        "reporting": {
            "enabled": generate_report,
            "format": "markdown",
            "output_dir": "./reports",
        },
    }

    # --- Write to disk ------------------------------------------------------
    out_path = _resolve_output_path(output_path_raw, engagement_name)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Display summary before writing to disk
    effective = _effective_scope_count(target_subnets, exclude)
    print("\n  -- Configuration Summary --\n")
    print(f"  Targets:  {_describe_targets(target_subnets)}")
    if exclude:
        print(f"  Exclude:  {', '.join(exclude)}")
    print(f"  Scope:    {effective} address(es) to scan\n")
    
    with out_path.open("w", encoding="utf-8") as fh:
        yaml.safe_dump(cfg, fh, sort_keys=False, allow_unicode=True)

    rel = out_path.relative_to(_PROJECT_ROOT)
    print(f"[+] Configuration saved to {rel}")
    print(f"    Reuse later with:  sudo python3 main.py -c {rel}\n")
    return out_path
