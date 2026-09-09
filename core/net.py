"""Small network helpers shared across modules.

Currently exposes :func:`source_ip_for` - the local IPv4 the kernel would
use to reach a given target. The SOC activity log records this as the
*source* (attacker) address of every test so a blue team can correlate the
tool's traffic against their EDR/SIEM telemetry by IP.
"""

from __future__ import annotations

import socket


def source_ip_for(target: str | None, fallback: str = "") -> str:
    """Return the local IPv4 the kernel routes to ``target``.

    Uses the standard UDP-connect routing trick: ``connect()`` on a
    ``SOCK_DGRAM`` socket sends no packet - it only resolves which local
    interface/IP an outbound flow to ``target`` would use, which
    ``getsockname()`` then exposes. This is robust on multi-homed hosts
    (dual-homed lab boxes, WSL2) because the address returned is the one
    that actually routes to the target rather than a guessed primary NIC.

    ``target`` should be a host inside the engagement (a DC/target IP).
    When omitted, a public-internet probe gives the primary egress IP.
    Returns ``fallback`` (default empty string) when no route exists.
    """
    dest = (target or "").strip() or "8.8.8.8"
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect((dest, 53))
        return sock.getsockname()[0]
    except OSError:
        return fallback
    finally:
        try:
            sock.close()
        except OSError:
            pass
