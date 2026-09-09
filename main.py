#!/usr/bin/env python3
"""Mavama - CLI entry point.

Usage:
    sudo python3 main.py                                   # interactive setup wizard
    sudo python3 main.py -c config/config.yaml             # skip wizard, load existing config
    sudo python3 main.py --targets 192.168.56.0/24 --domain lab.local
    sudo python3 main.py --phase recon
    sudo python3 main.py --phase credentials -c config/config.yaml
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

# The project is meant to be runnable from a checkout: prepend the
# project root to ``sys.path`` so that ``core.*`` / ``modules.*``
# imports resolve without an ``editable install``.
PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))


def _reexec_in_venv() -> None:
    """Run under the project's own virtualenv interpreter, transparently.

    ``sudo python3 main.py`` invokes the SYSTEM python (root's), which lacks the
    project dependencies (questionary, impacket, ...). Instead of forcing users
    to spell out ``sudo env "PATH=$PATH" .venv/bin/python3 main.py``, we re-exec
    under ``.venv/bin/python3`` on entry -- preserving root and argv -- and
    augment PATH so spawned CLI tools (nxc, certipy, GetNPUsers, secretsdump)
    still resolve under sudo's sanitized environment. This must run before
    importing any third-party module.
    """
    venv_py = PROJECT_ROOT / ".venv" / "bin" / "python3"

    # Expose the venv, system, and the invoking (pre-sudo) user's pipx bin dirs
    # to child processes: sudo sanitizes PATH and drops ~/.local/bin.
    extra = [str(PROJECT_ROOT / ".venv" / "bin"), "/usr/local/sbin", "/usr/local/bin"]
    sudo_user = os.environ.get("SUDO_USER")
    try:
        home = Path(f"~{sudo_user}").expanduser() if sudo_user else Path.home()
    except (KeyError, RuntimeError):
        home = Path.home()
    extra.append(str(home / ".local" / "bin"))
    seen: set[str] = set()
    merged: list[str] = []
    for part in [*extra, *os.environ.get("PATH", "").split(os.pathsep)]:
        if part and part not in seen:
            seen.add(part)
            merged.append(part)
    os.environ["PATH"] = os.pathsep.join(merged)

    if not venv_py.exists():
        return  # no venv (deps installed system-wide, e.g. Kali) - run as-is

    # Detect the interpreter by its prefix, NOT by resolving the binary: a venv
    # python is a symlink to the base interpreter, so resolved paths would match
    # even from the system python and wrongly skip the switch.
    try:
        in_venv = Path(sys.prefix).resolve() == (PROJECT_ROOT / ".venv").resolve()
    except OSError:
        in_venv = False
    if in_venv or os.environ.get("_MAVAMA_REEXEC") == "1":
        return

    os.environ["_MAVAMA_REEXEC"] = "1"  # guard against exec loops
    os.execv(str(venv_py), [str(venv_py), str(Path(__file__).resolve()), *sys.argv[1:]])


# Switch to the venv interpreter before importing any third-party dependency.
_reexec_in_venv()

import yaml  # noqa: E402

from core.orchestrator import Orchestrator  # noqa: E402


BANNER = r"""
    __  ___
   /  |/  /___ __   ______ _____ ___  ____ _
  / /|_/ / __ `/ | / / __ `/ __ `__ \/ __ `/
 / /  / / /_/ /| |/ / /_/ / / / / / / /_/ /
/_/  /_/\__,_/ |___/\__,_/_/ /_/ /_/\__,_/  Active Directory audit orchestrator
"""


PHASE_CHOICES = [
    "recon",
    "authed-recon",
    "credentials",
    "report",
    "all",
]


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="Mavama",
        description="Active Directory offensive audit orchestrator.",
    )
    p.add_argument(
        "--config", "-c", default=None,
        help=(
            "Path to the YAML configuration file. "
            "If omitted, the interactive setup wizard runs."
        ),
    )
    p.add_argument(
        "--phase", choices=PHASE_CHOICES, default="recon",
        help=(
            "Phase to execute (default: recon). "
            "'credentials' runs Phase 3 only and assumes recon state is "
            "already available (either via 'all' or a previous run). "
            "'all' chains every implemented phase."
        ),
    )
    p.add_argument(
        "--targets", nargs="+",
        help="Override: CIDR ranges to scan (space-separated).",
    )
    p.add_argument(
        "--exclude", nargs="+",
        help="Override: IPs/ranges to exclude from the scope.",
    )
    p.add_argument(
        "--domain",
        help="Override: known AD domain (e.g. lab.local).",
    )
    p.add_argument(
        "--interface", "-i",
        help="Network interface (overrides config).",
    )
    p.add_argument(
        "--safe", action="store_true",
        help="Enable safe mode (enumeration only - no password spraying or credential dumping).",
    )
    p.add_argument(
        "--stealth", action="store_true",
        help=(
            "Enable stealth mode: slower nmap timing (-T2), jitter between "
            "Kerberos AS-REQ probes, and at most one password per spray round."
        ),
    )
    p.add_argument(
        "--step", action="store_true",
        help=(
            "Semi-automatic execution: pause after each recon step to review "
            "the results and decide whether to continue, skip the next step, "
            "or stop (with an optional progress save). Requires an "
            "interactive terminal; falls back to auto mode otherwise."
        ),
    )
    p.add_argument(
        "--no-tool-check", action="store_true",
        help=(
            "Skip the startup tool preflight (the prompt asking which external "
            "tools to remove, followed by the availability check)."
        ),
    )
    p.add_argument(
        "--no-report", action="store_true",
        help=(
            "Do not auto-generate the HTML report at the end of a phase "
            "(sets reporting.enabled=false). '--phase report' still forces one."
        ),
    )
    p.add_argument(
        "--fresh", action="store_true",
        help=(
            "Start a clean engagement workspace: archive any existing "
            "state.json for this engagement before running, instead of resuming "
            "its previously discovered hosts/credentials/findings."
        ),
    )
    p.add_argument(
        "--no-banner", action="store_true", help="Hide the banner.",
    )
    return p.parse_args()


def _apply_overrides(cfg: dict, args: argparse.Namespace) -> dict:
    cfg.setdefault("scope", {})
    cfg.setdefault("engagement", {})
    if args.targets:
        cfg["scope"]["targets"] = args.targets
    if args.exclude:
        cfg["scope"]["exclude"] = args.exclude
    if args.domain:
        cfg["domain"] = args.domain
    if args.interface:
        cfg["interface"] = args.interface
    if args.safe:
        cfg["engagement"]["safe_mode"] = True
    if args.stealth:
        cfg["engagement"]["stealth_mode"] = True
    if args.step:
        cfg["engagement"]["execution_mode"] = "step"
    if args.no_report:
        cfg.setdefault("reporting", {})["enabled"] = False
    return cfg


def main() -> int:
    args = parse_args()
    if not args.no_banner:
        print(BANNER)

    if args.config is None:
        from utils.cli_setup import run_setup_wizard  # noqa: PLC0415
        cfg_path = run_setup_wizard(phase=args.phase)
    else:
        cfg_path = Path(args.config)
        if not cfg_path.is_file():
            print(f"[!] Config not found: {cfg_path}", file=sys.stderr)
            return 2

    with cfg_path.open("r", encoding="utf-8") as fh:
        cfg = yaml.safe_load(fh) or {}
    cfg = _apply_overrides(cfg, args)

    # Tool preflight: let the operator prune the external-tool set, then
    # quickly verify what remains. Runs before the orchestrator so the choice
    # (and any tool it disables) lands in the effective config below.
    if not args.no_tool_check:
        from utils.tool_preflight import run_tool_preflight  # noqa: PLC0415
        cfg = run_tool_preflight(cfg)

    # Persist the effective configuration so the orchestrator consumes
    # exactly the same values as the CLI (important for reproducibility
    # and for the audit trail).
    effective = cfg_path.parent / ".effective.yaml"
    with effective.open("w", encoding="utf-8") as fh:
        yaml.safe_dump(cfg, fh, sort_keys=False, allow_unicode=True)

    if os.geteuid() != 0:
        print(
            "[!] Warning: running without root - ARP scan and the Kerberoast "
            "clock sync (ntpdate) will be skipped.",
            file=sys.stderr,
        )

    orch = Orchestrator(config_path=effective, fresh=args.fresh)
    try:
        if args.phase == "recon":
            orch.run_recon()
        elif args.phase == "authed-recon":
            orch.run_authed_recon()
            orch.run_report()
        elif args.phase == "credentials":
            orch.run_credentials()
        elif args.phase == "report":
            orch.run_report(force=True)
        else:
            orch.run_all()
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user", file=sys.stderr)
        orch.tm.save()
        return 130
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
