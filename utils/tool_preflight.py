"""Startup tool preflight - prune, then quickly verify external tools.

Mavama drives a set of external command-line tools (nmap, NetExec, the
Impacket scripts, Certipy, ...). Before any phase runs, this
module:

1. **Asks** the operator which of those tools to *remove* from this engagement
   (none by default). An operator may not have - or may not want to use - a
   given tool, and there is no point warning about it.
2. **Verifies** only the remaining tools, quickly, with a ``$PATH`` lookup
   (``shutil.which``), and prints a present/missing summary.

The verification deliberately happens *after* the removal step ("from there,
not before"), so the operator never sees noise about tools they just excluded.

Removed tools are persisted under ``cfg["tools"]["disabled"]`` (so the choice
survives into the effective config and the audit trail). For a tool that has a
dedicated config switch, removing it also flips that switch off, so "remove"
actually disables the feature rather than merely silencing its check.

This module is import-safe and side-effect free until ``run_tool_preflight`` is
called; ``questionary`` is imported lazily so headless runs do not require it.
"""

from __future__ import annotations

import shutil
import sys
from dataclasses import dataclass, field


@dataclass(frozen=True)
class ToolSpec:
    """A single external tool the orchestrator may shell out to."""

    key: str                       # stable identifier used in config/CLI
    display: str                   # human-readable name
    candidates: tuple[str, ...]    # binary names tried in order via which()
    purpose: str                   # what it is used for (shown to the operator)
    # Dotted config path (e.g. "relay.responder") flipped to False when the
    # tool is removed; None for tools without a dedicated on/off switch.
    config_toggle: str | None = None


# Order roughly follows the kill-chain so the verification reads top-to-bottom.
KNOWN_TOOLS: tuple[ToolSpec, ...] = (
    ToolSpec("nmap", "nmap", ("nmap",),
             "Port & service scanning (Phase 1)"),
    ToolSpec("netexec", "NetExec", ("nxc", "netexec", "crackmapexec"),
             "SMB/LDAP enumeration, vuln checks (Phases 1b/3)"),
    ToolSpec("nmblookup", "nmblookup", ("nmblookup",),
             "NetBIOS Domain Controller discovery (Phase 1)"),
    ToolSpec("getnpusers", "Impacket GetNPUsers",
             ("GetNPUsers.py", "impacket-GetNPUsers", "GetNPUsers"),
             "ASREProasting (Phase 3)"),
    ToolSpec("getuserspns", "Impacket GetUserSPNs",
             ("GetUserSPNs.py", "impacket-GetUserSPNs", "GetUserSPNs"),
             "Kerberoasting (Phase 3)"),
    ToolSpec("secretsdump", "Impacket secretsdump",
             ("secretsdump.py", "impacket-secretsdump", "secretsdump"),
             "SAM/LSA/NTDS dumping (Phase 3)"),
    ToolSpec("certipy", "Certipy", ("certipy", "certipy-ad"),
             "AD CS enumeration / ESC checks (Phase 1b)"),
)

_TOOLS_BY_KEY = {t.key: t for t in KNOWN_TOOLS}


@dataclass
class ToolStatus:
    """Result of verifying a single tool."""

    spec: ToolSpec
    resolved: str | None = None     # path to the first candidate found, if any
    disabled: bool = False          # removed by the operator

    @property
    def present(self) -> bool:
        return self.resolved is not None


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------

def _resolve(spec: ToolSpec) -> str | None:
    """Return the path of the first candidate binary found.

    Search order (highest to lowest priority):
    1. The venv's own bin directory — avoids the sudo PATH-stripping problem
       where tools installed in the venv are invisible to ``shutil.which``.
    2. User-local bin directories (~/.local/bin, ~/bin) — covers tools
       installed via ``pip install --user`` or ``pipx``.
    3. ``shutil.which`` against the current ``$PATH``.
    """
    import os
    import sys
    from pathlib import Path

    extra_dirs: list[Path] = []
    # Venv bin directory (robust even when sudo resets PATH).
    extra_dirs.append(Path(sys.executable).parent)
    # Under sudo, Path.home() returns /root — also check the real user's home.
    homes: list[Path] = []
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user:
        import pwd
        try:
            homes.append(Path(pwd.getpwnam(sudo_user).pw_dir))
        except KeyError:
            pass
    homes.append(Path.home())
    for home in homes:
        for rel in (".local/bin", "bin"):
            extra_dirs.append(home / rel)
    # pipx shared bin directory
    pipx_bin = Path(os.environ.get("PIPX_BIN_DIR", homes[0] / ".local/bin" if homes else Path.home() / ".local/bin"))
    extra_dirs.append(pipx_bin)

    for cand in spec.candidates:
        for d in extra_dirs:
            p = d / cand
            if p.is_file() and os.access(p, os.X_OK):
                return str(p)
        path = shutil.which(cand)
        if path:
            return path
    return None


def verify_tools(
    tools: tuple[ToolSpec, ...] = KNOWN_TOOLS,
    disabled: set[str] | None = None,
) -> list[ToolStatus]:
    """Quickly check tool availability, skipping the ``disabled`` ones."""
    disabled = disabled or set()
    statuses: list[ToolStatus] = []
    for spec in tools:
        if spec.key in disabled:
            statuses.append(ToolStatus(spec=spec, disabled=True))
            continue
        statuses.append(ToolStatus(spec=spec, resolved=_resolve(spec)))
    return statuses


# ---------------------------------------------------------------------------
# Interactive removal
# ---------------------------------------------------------------------------

def _interactive_available() -> bool:
    if not sys.stdin.isatty():
        return False
    try:
        import questionary  # noqa: F401, PLC0415
    except ImportError:
        return False
    return True


def select_disabled_tools(
    tools: tuple[ToolSpec, ...] = KNOWN_TOOLS,
    preselected: set[str] | None = None,
) -> set[str]:
    """Prompt the operator for tools to remove. Returns the set of keys.

    Pre-checks ``preselected`` (tools already disabled in the config). On a
    non-interactive run, or if the prompt is cancelled, ``preselected`` is
    returned unchanged.
    """
    preselected = preselected or set()
    if not _interactive_available():
        return set(preselected)

    import questionary  # noqa: PLC0415

    choices = [
        questionary.Choice(
            title=f"{spec.display:<22} - {spec.purpose}",
            value=spec.key,
            checked=spec.key in preselected,
        )
        for spec in tools
    ]
    answer = questionary.checkbox(
        "Remove any tools from this engagement? "
        "(space to toggle, enter to confirm; leave all unchecked to keep them)",
        choices=choices,
    ).ask()
    if answer is None:  # Ctrl+C / cancelled - keep the existing selection.
        return set(preselected)
    return set(answer)


# ---------------------------------------------------------------------------
# Config helpers
# ---------------------------------------------------------------------------

def _set_config_path(cfg: dict, dotted: str, value: object) -> None:
    """Set ``cfg[a][b][...] = value`` for a dotted ``a.b.c`` path."""
    keys = dotted.split(".")
    node = cfg
    for key in keys[:-1]:
        child = node.get(key)
        if not isinstance(child, dict):
            child = {}
            node[key] = child
        node = child
    node[keys[-1]] = value


def _print_summary(statuses: list[ToolStatus]) -> None:
    enabled = [s for s in statuses if not s.disabled]
    present = [s for s in enabled if s.present]
    missing = [s for s in enabled if not s.present]
    removed = [s for s in statuses if s.disabled]

    print(
        f"\n[*] Tool availability check "
        f"({len(present)} present, {len(missing)} missing, "
        f"{len(removed)} removed):"
    )
    for s in statuses:
        name = s.spec.display.ljust(22)
        if s.disabled:
            print(f"    [skip] {name} removed by operator")
        elif s.present:
            print(f"    [+]    {name} {s.resolved}")
        else:
            print(f"    [-]    {name} MISSING - {s.spec.purpose}")

    if missing:
        names = ", ".join(s.spec.display for s in missing)
        print(
            f"[!] {len(missing)} tool(s) missing: {names}. "
            "The phases that rely on them will be skipped at runtime.\n"
        )
    else:
        print("[+] All retained tools are available.\n")


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def run_tool_preflight(cfg: dict, interactive: bool = True) -> dict:
    """Run the prune-then-verify preflight and return the updated config.

    * Reads the current removal set from ``cfg["tools"]["disabled"]``.
    * When interactive (and a TTY/questionary are available), asks the operator
      which tools to remove and updates that set.
    * Persists the set back to ``cfg["tools"]["disabled"]`` and flips off the
      config switch of any removed tool that has one.
    * Verifies the retained tools and prints the summary.
    """
    tools_cfg = cfg.setdefault("tools", {})
    raw_disabled = tools_cfg.get("disabled") or []
    # Keep only keys we actually know about (ignore stale/unknown entries).
    disabled = {k for k in raw_disabled if k in _TOOLS_BY_KEY}

    if interactive:
        disabled = select_disabled_tools(KNOWN_TOOLS, preselected=disabled)
    elif not raw_disabled:
        print(
            "[*] Tool preflight: non-interactive run - verifying all tools "
            "(remove some via config 'tools.disabled')."
        )

    tools_cfg["disabled"] = sorted(disabled)

    # Give "remove" real teeth for any tool that has a dedicated config switch.
    for key in disabled:
        toggle = _TOOLS_BY_KEY[key].config_toggle
        if toggle:
            _set_config_path(cfg, toggle, False)

    statuses = verify_tools(KNOWN_TOOLS, disabled=disabled)
    _print_summary(statuses)
    return cfg
