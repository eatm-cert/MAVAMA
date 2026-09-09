"""Unit tests for ``modules.credentials.cred_manager.CredentialManager``.

The full ``run()`` path delegates to four wrappers - those have their
own dedicated tests. Here we exercise the orchestration logic only:

* domain / KDC IP / credential resolution from the engagement state;
* enabled / disabled toggles in the YAML config;
* the safe-mode bypass for active components.

Wrappers are stubbed out so the manager exercise stays cheap.
"""

from __future__ import annotations

import pytest

from core.target_manager import Credential
from modules.credentials.cred_manager import CredentialManager
from modules.credentials.dumping import DumpResult
from modules.credentials.roasting import RoastResult
from modules.credentials.spraying import SprayResult


def _seed_goad_mini(tm):
    tm.add_host(
        ip="192.168.56.10",
        is_dc=True,
        domain="sevenkingdoms.local",
    )
    tm.add_user("jon.snow")
    tm.add_user("robb.stark")


def _make(tm, **cred_overrides):
    cfg = {
        "engagement": {"safe_mode": cred_overrides.pop("safe_mode", False)},
        "domain": cred_overrides.pop("domain", "sevenkingdoms.local"),
        "logging": {"loot_dir": "./loot"},
        "credentials": cred_overrides,
    }
    return CredentialManager(config=cfg, tm=tm)


# ---------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------


def test_kdc_ip_falls_back_to_first_dc(tm):
    _seed_goad_mini(tm)
    mgr = _make(tm)
    assert mgr._kdc_ip() == "192.168.56.10"


def test_kdc_ip_explicit_override(tm):
    _seed_goad_mini(tm)
    mgr = _make(tm, kdc_ip="10.0.0.1")
    assert mgr._kdc_ip() == "10.0.0.1"


def test_pick_credential_prefers_password_over_hash(tm):
    _seed_goad_mini(tm)
    tm.add_credential(Credential(
        username="hash_user", domain="d", nt_hash="aa" * 16, source="x",
    ))
    tm.add_credential(Credential(
        username="pwd_user", domain="d", password="x", source="y",
    ))
    mgr = _make(tm)
    cred = mgr._pick_credential()
    assert cred is not None
    assert cred.username == "pwd_user"


def test_pick_credential_uses_yaml_block(tm):
    _seed_goad_mini(tm)
    mgr = _make(tm, credential={
        "username": "manual",
        "password": "p",
        "domain": "d",
    })
    cred = mgr._pick_credential()
    assert cred.username == "manual"
    assert cred.source == "config"


def test_pick_credential_returns_none_when_empty(tm):
    _seed_goad_mini(tm)
    mgr = _make(tm)
    assert mgr._pick_credential() is None


def test_pick_credential_skips_roast_blob(tm):
    """A $krb5* roast blob lives in nt_hash but cannot authenticate, so the
    picker must not return it - doing so would feed a malformed -hashes
    argument to kerberoast / dumping."""
    _seed_goad_mini(tm)
    tm.add_credential(Credential(
        username="svc_sql", domain="d",
        nt_hash="$krb5tgs$23$*svc_sql$D$abcdef", source="kerberoast",
    ))
    mgr = _make(tm)
    assert mgr._pick_credential() is None


def test_pick_credential_prefers_real_hash_over_blob(tm):
    _seed_goad_mini(tm)
    tm.add_credential(Credential(
        username="roasted", domain="d",
        nt_hash="$krb5asrep$23$roasted@D:abcdef", source="asreproast",
    ))
    real = Credential(
        username="dumped", domain="d", nt_hash="aa" * 16, source="dcsync",
    )
    tm.add_credential(real)
    mgr = _make(tm)
    assert mgr._pick_credential() is real


# ---------------------------------------------------------------------
# Sub-runs - enabled / disabled gating
# ---------------------------------------------------------------------


def test_asreproast_disabled_returns_none(tm, monkeypatch):
    _seed_goad_mini(tm)
    mgr = _make(tm, asreproast={"enabled": False})
    assert mgr._run_asreproast() is None


def test_asreproast_enabled_invokes_wrapper(tm, monkeypatch):
    _seed_goad_mini(tm)
    sentinel = RoastResult(status="completed", attack="asreproast")
    captured: dict = {}

    class _FakeRoaster:
        def __init__(self, **kw):
            captured.update(kw)
        def run(self):
            return sentinel

    monkeypatch.setattr(
        "modules.credentials.cred_manager.ASREPRoaster", _FakeRoaster
    )
    mgr = _make(tm, asreproast={"enabled": True, "timeout": 90})
    assert mgr._run_asreproast() is sentinel
    assert captured["domain"] == "sevenkingdoms.local"
    assert captured["kdc_ip"] == "192.168.56.10"
    assert captured["timeout"] == 90


def test_kerberoast_skipped_without_credential(tm, monkeypatch):
    _seed_goad_mini(tm)
    called: list = []
    monkeypatch.setattr(
        "modules.credentials.cred_manager.Kerberoaster",
        lambda **kw: called.append(kw) or None,
    )
    mgr = _make(tm, kerberoast={"enabled": True})
    assert mgr._run_kerberoast() is None
    assert called == []          # wrapper never instantiated


def test_kerberoast_runs_when_credential_available(tm, monkeypatch):
    _seed_goad_mini(tm)
    tm.add_credential(Credential(
        username="robb.stark", domain="sevenkingdoms.local",
        password="winter", source="spray",
    ))
    sentinel = RoastResult(status="completed", attack="kerberoast")
    monkeypatch.setattr(
        "modules.credentials.cred_manager.Kerberoaster",
        lambda **kw: type("Stub", (), {"run": lambda self: sentinel})(),
    )
    mgr = _make(tm, kerberoast={"enabled": True})
    assert mgr._run_kerberoast() is sentinel


def test_spraying_disabled_by_default(tm):
    _seed_goad_mini(tm)
    mgr = _make(tm)
    assert mgr._run_spray() is None


def test_spraying_empty_users_list_falls_back_to_tm(tm, monkeypatch):
    """Regression: ``users: []`` in the YAML used to short-circuit the
    wrapper with 'no users'. It must instead fall back to the recon-
    discovered list."""
    _seed_goad_mini(tm)
    captured: dict = {}

    class _FakeSprayer:
        def __init__(self, **kw):
            captured.update(kw)
        def run(self):
            return SprayResult(status="completed")

    monkeypatch.setattr(
        "modules.credentials.cred_manager.PasswordSprayer", _FakeSprayer
    )
    mgr = _make(
        tm,
        spraying={
            "enabled": True,
            "passwords": ["x"],
            "users": [],   # <- the regression case
        },
    )
    mgr._run_spray()
    # ``None`` lets PasswordSprayer fall back to ``tm.users`` itself.
    assert captured["users"] is None


def test_spraying_runs_when_enabled(tm, monkeypatch):
    _seed_goad_mini(tm)
    sentinel = SprayResult(status="completed")
    captured: dict = {}

    class _FakeSprayer:
        def __init__(self, **kw):
            captured.update(kw)
        def run(self):
            return sentinel

    monkeypatch.setattr(
        "modules.credentials.cred_manager.PasswordSprayer", _FakeSprayer
    )
    mgr = _make(
        tm,
        spraying={
            "enabled": True,
            "passwords": ["Password1"],
            "lockout_threshold": 7,
        },
    )
    assert mgr._run_spray() is sentinel
    # Targets default to discovered DCs.
    assert captured["targets"] == ["192.168.56.10"]
    assert captured["lockout_threshold"] == 7


def test_dumping_disabled_by_default(tm):
    _seed_goad_mini(tm)
    mgr = _make(tm)
    assert mgr._run_dumps() == []


def test_dumping_runs_each_operation(tm, monkeypatch):
    _seed_goad_mini(tm)
    tm.add_credential(Credential(
        username="Administrator", domain="sevenkingdoms.local",
        nt_hash="aa" * 16, source="dcsync-prep",
    ))
    seen: list[dict] = []

    class _FakeDumper:
        def __init__(self, **kw):
            seen.append(kw)
        def run(self):
            return DumpResult(status="completed", mode=seen[-1]["mode"].value)

    monkeypatch.setattr(
        "modules.credentials.cred_manager.SecretsDumper", _FakeDumper
    )
    mgr = _make(
        tm,
        dumping={
            "enabled": True,
            "operations": [
                {"mode": "dcsync"},
                {"mode": "local", "target": "192.168.56.20"},
            ],
        },
    )
    results = mgr._run_dumps()
    assert len(results) == 2
    # DCSYNC default target is the first known DC.
    assert seen[0]["target"] == "192.168.56.10"
    assert seen[1]["target"] == "192.168.56.20"


def test_dumping_skips_unknown_mode(tm, monkeypatch):
    _seed_goad_mini(tm)
    monkeypatch.setattr(
        "modules.credentials.cred_manager.SecretsDumper",
        lambda **kw: pytest.fail(f"should not instantiate: {kw}"),
    )
    mgr = _make(tm, dumping={
        "enabled": True,
        "operations": [{"mode": "phantom-mode"}],
    })
    assert mgr._run_dumps() == []


# ---------------------------------------------------------------------
# Safe mode propagation
# ---------------------------------------------------------------------


def test_safe_mode_propagates_to_wrappers(tm, monkeypatch):
    _seed_goad_mini(tm)
    captured: dict = {}

    class _FakeRoaster:
        def __init__(self, **kw):
            captured.update(kw)
        def run(self):
            return RoastResult(status="skipped", attack="asreproast")

    monkeypatch.setattr(
        "modules.credentials.cred_manager.ASREPRoaster", _FakeRoaster
    )
    mgr = _make(tm, safe_mode=True, asreproast={"enabled": True})
    mgr._run_asreproast()
    assert captured["safe_mode"] is True
