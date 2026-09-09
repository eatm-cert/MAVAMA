"""Orchestrator credential selection.

``_pick_first_credential`` feeds authenticated recon (Phase 1b). It must never
hand back a credential whose only ``nt_hash`` is a stashed ``$krb5*`` roast
blob, because that blob is not authentication material and would be forwarded
to nxc as a malformed ``-H $krb5...`` argument.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from core.orchestrator import Orchestrator
from core.target_manager import Credential


def _orch(tmp_path: Path) -> Orchestrator:
    cfg = {
        "engagement": {"name": "pick"},
        "scope": {"targets": ["10.0.0.0/24"]},
        "domain": "rootme.local",
        "logging": {
            "log_dir": str(tmp_path / "logs"),
            "loot_dir": str(tmp_path / "loot"),
        },
    }
    p = tmp_path / "cfg.yaml"
    p.write_text(yaml.safe_dump(cfg), encoding="utf-8")
    return Orchestrator(p)


def test_pick_first_credential_skips_roast_blob(tmp_path):
    orch = _orch(tmp_path)
    orch.tm.add_credential(Credential(
        username="svc", domain="rootme.local",
        nt_hash="$krb5asrep$23$svc@ROOTME:abcdef", source="asreproast",
    ))
    assert orch._pick_first_credential() is None


def test_pick_first_credential_prefers_password_then_real_hash(tmp_path):
    orch = _orch(tmp_path)
    blob = Credential(
        username="b", domain="d",
        nt_hash="$krb5tgs$23$*b$D$abcdef", source="kerberoast",
    )
    real = Credential(username="r", domain="d", nt_hash="cd" * 16, source="dcsync")
    orch.tm.add_credential(blob)
    orch.tm.add_credential(real)
    assert orch._pick_first_credential() is real


def test_maybe_run_authed_recon_skips_when_only_roast_blob(tmp_path, monkeypatch):
    """A $krb5* blob makes tm.credentials non-empty but carries no auth secret.
    The gate must NOT announce/launch authed recon on a blob-only state."""
    orch = _orch(tmp_path)
    orch.tm.add_credential(Credential(
        username="missandei", domain="essos.local",
        nt_hash="$krb5asrep$23$missandei@ESSOS:abcdef", source="asreproast",
    ))
    called = {"authed": False}
    monkeypatch.setattr(orch, "run_authed_recon", lambda: called.__setitem__("authed", True))
    # Non-interactive: black-box path, no prompt.
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    orch._maybe_run_authed_recon()
    assert called["authed"] is False


def test_maybe_run_authed_recon_runs_with_real_credential(tmp_path, monkeypatch):
    orch = _orch(tmp_path)
    orch.tm.add_credential(Credential(
        username="jaime.lannister", domain="sevenkingdoms.local",
        password="cersei", source="provided",
    ))
    called = {"authed": False}
    monkeypatch.setattr(orch, "run_authed_recon", lambda: called.__setitem__("authed", True))
    orch._maybe_run_authed_recon()
    assert called["authed"] is True
