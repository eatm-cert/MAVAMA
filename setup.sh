#!/usr/bin/env bash
#
# Mavama - one-shot environment setup.
#
# Installs the system packages, creates the Python virtualenv, installs the
# pinned requirements (impacket / netexec / ...), and installs Certipy (AD CS
# enumeration, used by Phase 1b authenticated recon; not pinned in
# requirements.txt).
#
# Usage:
#   ./setup.sh                 # full setup (apt + venv + requirements + certipy)
#   ./setup.sh --no-apt        # skip system packages (already installed / non-Debian)
#   ./setup.sh -h | --help
#
# Re-runnable: existing venv and already-installed packages are reused.

set -euo pipefail

# Resolve and move into the project root (directory of this script).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

VENV_DIR=".venv"
SKIP_APT=0

# --- pretty logging --------------------------------------------------------
if [[ -t 1 ]]; then
    C_INFO="\033[1;34m"; C_OK="\033[1;32m"; C_WARN="\033[1;33m"; C_ERR="\033[1;31m"; C_OFF="\033[0m"
else
    C_INFO=""; C_OK=""; C_WARN=""; C_ERR=""; C_OFF=""
fi
info()  { echo -e "${C_INFO}[*]${C_OFF} $*"; }
ok()    { echo -e "${C_OK}[+]${C_OFF} $*"; }
warn()  { echo -e "${C_WARN}[!]${C_OFF} $*" >&2; }
err()   { echo -e "${C_ERR}[x]${C_OFF} $*" >&2; }

usage() {
    sed -n '3,18p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
    exit "${1:-0}"
}

# --- argument parsing ------------------------------------------------------
while [[ $# -gt 0 ]]; do
    case "$1" in
        --no-apt)        SKIP_APT=1 ;;
        -h|--help)       usage 0 ;;
        *) err "Unknown option: $1"; usage 2 ;;
    esac
    shift
done

# --- 1. system packages (Debian / Kali) ------------------------------------
if [[ $SKIP_APT -eq 0 ]]; then
    if command -v apt-get >/dev/null 2>&1; then
        SUDO=""
        [[ $EUID -ne 0 ]] && SUDO="sudo"
        info "Installing system packages (nmap, samba-common-bin, git, pipx, build deps)..."
        $SUDO apt-get update -y
        # Mandatory core packages available on both Debian/Kali and Ubuntu.
        # (samba-common-bin provides nmblookup; there is no 'nmblookup' package.)
        # build-essential + *-dev headers let pipx build NetExec and any
        # source-only Python deps on a minimal Ubuntu (where wheels are missing).
        $SUDO apt-get install -y \
            nmap samba-common-bin git \
            python3 python3-venv python3-pip python3-dev pipx \
            build-essential libffi-dev libssl-dev
        # impacket-scripts is Kali/Debian-only and does NOT exist on Ubuntu; the
        # venv's pip impacket provides the same scripts (GetNPUsers.py,
        # GetUserSPNs.py, secretsdump.py), so this is best-effort.
        $SUDO apt-get install -y impacket-scripts \
            || warn "apt has no 'impacket-scripts' (e.g. Ubuntu) - the venv impacket provides those scripts."
        # netexec is a separate package; '|| true' so a mirror without it does
        # not abort the run (the pipx fallback below handles it).
        $SUDO apt-get install -y netexec || warn "apt has no 'netexec' package - will try pipx."
        ok "System packages installed."
    else
        warn "apt-get not found - skipping system packages."
        warn "Install manually: nmap, samba-common-bin, impacket-scripts, python3-venv, pipx."
    fi
else
    info "Skipping system packages (--no-apt)."
fi

# --- 2. Python virtualenv + pinned requirements ----------------------------
if [[ ! -d "$VENV_DIR" ]]; then
    info "Creating virtualenv in $VENV_DIR ..."
    python3 -m venv "$VENV_DIR"
else
    info "Reusing existing virtualenv in $VENV_DIR."
fi

# A venv created before python3-venv/ensurepip was available (or an interrupted
# creation) has no pip -> "No module named pip". Self-heal: bootstrap pip via
# ensurepip, and recreate the venv from scratch if even that is unavailable.
if ! "$VENV_DIR/bin/python" -m pip --version >/dev/null 2>&1; then
    warn "venv has no pip - bootstrapping via ensurepip..."
    if ! "$VENV_DIR/bin/python" -m ensurepip --upgrade >/dev/null 2>&1; then
        warn "ensurepip unavailable - recreating the virtualenv from scratch..."
        rm -rf "$VENV_DIR"
        python3 -m venv "$VENV_DIR"
    fi
fi

VENV_PY="$VENV_DIR/bin/python"
info "Upgrading pip and installing requirements.txt (this can take a while)..."
"$VENV_PY" -m pip install --upgrade pip
"$VENV_PY" -m pip install -r requirements.txt
ok "Python requirements installed."

# --- 3. CLI tools not on PyPI: Certipy + NetExec ---------------------------
# Both are standalone command-line tools (not import dependencies), so they
# live outside requirements.txt. Prefer pipx; fall back to the venv for Certipy.
if command -v pipx >/dev/null 2>&1; then
    info "Installing Certipy via pipx..."
    pipx install certipy-ad >/dev/null 2>&1 || pipx upgrade certipy-ad >/dev/null 2>&1 || true
    pipx ensurepath >/dev/null 2>&1 || true
    ok "Certipy installed via pipx (open a new shell if 'certipy' is not yet on PATH)."
else
    warn "pipx not available - installing Certipy into the virtualenv instead."
    "$VENV_PY" -m pip install certipy-ad
fi

# NetExec ('nxc'): use whatever apt installed; otherwise pull it via pipx.
if command -v nxc >/dev/null 2>&1 || command -v netexec >/dev/null 2>&1; then
    ok "NetExec already available ($(command -v nxc 2>/dev/null || command -v netexec))."
elif command -v pipx >/dev/null 2>&1; then
    info "Installing NetExec via pipx (from GitHub)..."
    NXC_SPEC="git+https://github.com/Pennyw0rth/NetExec.git"
    if ! pipx install "$NXC_SPEC" >/dev/null 2>&1; then
        # On bleeding-edge Python (e.g. 3.14) some deps have no wheels and try to
        # build from source, which needs a Rust compiler. python3.12 has
        # prebuilt wheels and avoids the build entirely - retry with it.
        if command -v python3.12 >/dev/null 2>&1; then
            warn "NetExec build failed on default python - retrying with python3.12 (has wheels)..."
            pipx install --python python3.12 "$NXC_SPEC" >/dev/null 2>&1 \
                || warn "NetExec still failing - run 'pipx install $NXC_SPEC 2>&1 | tail' to see why."
        else
            warn "NetExec build failed (default python likely lacks wheels). Fix: install python3.12 then"
            warn "  'pipx install --python python3.12 $NXC_SPEC', or 'apt install rustc cargo' to build on the current python."
        fi
    fi
else
    warn "NetExec not found and pipx unavailable - install it manually (apt install netexec)."
fi

# --- 4. quick availability check -------------------------------------------
# Look on $PATH and in the venv's bin/ (the project's wrappers auto-discover
# both), trying alternate binary names as the startup preflight does.
check_tool() {
    local display="$1"; shift
    local cand
    for cand in "$@"; do
        if command -v "$cand" >/dev/null 2>&1; then
            ok "  $display -> $(command -v "$cand")"; return
        fi
        if [[ -x "$VENV_DIR/bin/$cand" ]]; then
            ok "  $display -> $VENV_DIR/bin/$cand"; return
        fi
    done
    warn "  $display not found (the startup tool preflight will flag it)."
}

info "Tool availability check:"
check_tool nmap              nmap
check_tool NetExec           nxc netexec crackmapexec
check_tool Certipy           certipy certipy-ad
check_tool GetNPUsers        GetNPUsers.py impacket-GetNPUsers
check_tool GetUserSPNs       GetUserSPNs.py impacket-GetUserSPNs
check_tool secretsdump       secretsdump.py impacket-secretsdump

echo
ok "Setup complete."
echo "Next steps:"
echo "  # 'sudo python3 main.py' now re-execs into this venv automatically, so"
echo "  # it works out of the box (no need to spell out the venv python)."
echo "  sudo python3 main.py                       # interactive setup wizard"
echo "  sudo python3 main.py -c config/config.yaml --phase recon"
