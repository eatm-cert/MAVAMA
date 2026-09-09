"""Smoke test for the Phase 1 orchestrator (``ReconEngine``).

End-to-end flow is covered by the integration test; here we only verify
that the engine chains its submodules in the right order and uses the
configuration properly.

The phase is now expressed as a list of steps (see ``utils.step_runner``):
host discovery is split into per-technique steps (``arp_scan`` /
``ping_sweep`` / ``tcp_ping``) and the downstream steps self-skip when no
host is alive. ``execution_mode`` defaults to ``auto`` so the steps run
back-to-back without any prompt."""

from __future__ import annotations

from io import StringIO
from unittest.mock import patch

from rich.console import Console

from core.target_manager import Finding
from modules.recon.recon import ReconEngine, render_summary


def _plain_console() -> Console:
    """A wide, colour-free console that records output to a string buffer."""
    return Console(file=StringIO(), width=200, color_system=None, soft_wrap=True)


def _minimal_cfg() -> dict:
    return {
        "scope": {"targets": ["10.0.0.0/30"], "exclude": []},
        "domain": "lab.local",
        "interface": None,
        "recon": {
            "host_discovery": {"arp_scan": False, "ping_sweep": True, "tcp_ping_ports": [445]},
            "port_scan": {"ports": [389, 445]},
            "anon_enum": {"smb_null_session": True, "ldap_anonymous_bind": True,
                          "rid_bruteforce": True, "rid_range": [500, 600]},
            "user_enum": {"enabled": True, "userlist": None, "threads": 2},
        },
    }


def test_engine_stops_when_no_live_host(tm):
    cfg = _minimal_cfg()
    engine = ReconEngine(config=cfg, tm=tm)
    # ping_sweep + tcp_ping report nothing -> no live host -> downstream
    # steps must self-skip without calling their underlying runners.
    with patch("modules.recon.recon.HostDiscovery.ping_sweep", return_value=set()), \
         patch("modules.recon.recon.HostDiscovery.tcp_ping", return_value=set()), \
         patch("modules.recon.recon.HostDiscovery._resolve_hostnames"), \
         patch("modules.recon.recon.ServiceEnum.run") as se, \
         patch("modules.recon.recon.DCFinder.run") as dcf, \
         patch("modules.recon.recon.AnonEnum.run") as ae, \
         patch("modules.recon.recon.UserEnum.run") as ue:
        completed = engine.run()

    assert completed is True
    se.assert_not_called()
    dcf.assert_not_called()
    ae.assert_not_called()
    ue.assert_not_called()


def test_engine_runs_full_sequence_when_dc_found(tm):
    cfg = _minimal_cfg()
    engine = ReconEngine(config=cfg, tm=tm)

    def _prime_dc(*_a, **_kw):
        # Simulate service_enum populating a DC in TargetManager.
        h = tm.add_host("10.0.0.2", is_dc=True, domain="lab.local")
        h.add_service(port=389, name="ldap")
        h.add_service(port=445, name="smb")
        return None

    with patch("modules.recon.recon.HostDiscovery.ping_sweep", return_value={"10.0.0.1", "10.0.0.2"}), \
         patch("modules.recon.recon.HostDiscovery.tcp_ping", return_value=set()), \
         patch("modules.recon.recon.HostDiscovery._resolve_hostnames"), \
         patch("modules.recon.recon.ServiceEnum.run", side_effect=_prime_dc) as se, \
         patch("modules.recon.recon.DCFinder.run", return_value=["10.0.0.2"]) as dcf, \
         patch("modules.recon.recon.AnonEnum.run") as ae, \
         patch("modules.recon.recon.UserEnum.run", return_value={"valid": ["alice"], "asreproastable": [], "disabled": []}) as ue:
        completed = engine.run()

    assert completed is True
    se.assert_called_once()
    dcf.assert_called_once()
    ae.assert_called_once()
    ue.assert_called_once()


# ---------------------------------------------------------------------------
# render_summary — reusable recap (also used for the authed-recon restart)
# ---------------------------------------------------------------------------

def test_render_summary_marks_new_findings_and_delta(tm):
    tm.add_host("10.0.0.10", is_dc=True, domain="lab.local")
    tm.add_finding(Finding(id="OLD-1", title="old finding", severity="low", host="10.0.0.10"))
    tm.add_finding(Finding(id="NEW-1", title="new finding", severity="high", host="10.0.0.10"))

    console = _plain_console()
    render_summary(
        tm, console, title="Recap",
        new_finding_ids={"NEW-1"}, new_users={"alice"}, show_delta_note=True,
    )
    out = console.file.getvalue()

    assert "old finding" in out and "new finding" in out
    assert "NEW" in out                       # the new finding is flagged
    assert "HIGH" in out and "LOW" in out      # per-severity labels rendered
    assert "+1 new finding(s)" in out and "+1 new user(s)" in out
    assert "alice" in out                      # new user surfaced


def test_render_summary_reports_nothing_new(tm):
    tm.add_host("10.0.0.10", is_dc=True, domain="lab.local")
    console = _plain_console()
    render_summary(tm, console, title="Recap", show_delta_note=True)
    assert "No new findings or users" in console.file.getvalue()
