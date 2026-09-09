"""Per-engagement workspace isolation.

Each engagement gets its own ``loot/<slug>/`` and ``logs/<slug>/`` so one
engagement never loads another's ``state.json`` (credentials, users, findings).
The slug is ``<name>-<hash of scope+domain>`` so two engagements that share a
name but target different environments stay separate, while re-running the same
config resolves to the same workspace (resume).
"""

from __future__ import annotations

from pathlib import Path

import yaml

from core.orchestrator import Orchestrator


def _cfg(tmp_path: Path, fname: str, name: str, targets, domain=None) -> Path:
    cfg = {
        "engagement": {"name": name},
        "scope": {"targets": targets},
        "domain": domain,
        "logging": {"log_dir": str(tmp_path / "logs"), "loot_dir": str(tmp_path / "loot")},
    }
    p = tmp_path / fname
    p.write_text(yaml.safe_dump(cfg), encoding="utf-8")
    return p


def test_same_name_different_scope_are_isolated(tmp_path):
    o1 = Orchestrator(_cfg(tmp_path, "a.yaml", "client-audit", ["192.168.56.0/24"], "essos.local"))
    o2 = Orchestrator(_cfg(tmp_path, "b.yaml", "client-audit", ["10.10.0.0/24"], "rootme.local"))
    assert o1.tm.loot_dir != o2.tm.loot_dir
    assert Path(o1.tm.loot_dir).name.startswith("client-audit-")
    assert Path(o2.tm.loot_dir).name.startswith("client-audit-")


def test_same_config_resumes_same_workspace(tmp_path):
    cfg = _cfg(tmp_path, "c.yaml", "audit", ["192.168.56.0/24"], "essos.local")
    assert Orchestrator(cfg).tm.loot_dir == Orchestrator(cfg).tm.loot_dir


def test_fresh_archives_existing_state(tmp_path):
    cfg = _cfg(tmp_path, "e.yaml", "audit", ["192.168.56.0/24"], "essos.local")
    orch = Orchestrator(cfg)
    state = Path(orch.tm.loot_dir) / "state.json"
    state.write_text('{"hosts": {}}', encoding="utf-8")

    fresh = Orchestrator(cfg, fresh=True)
    assert not state.exists()  # archived, not loaded
    backups = list(Path(fresh.tm.loot_dir).glob("state.*.bak.json"))
    assert len(backups) == 1


def test_workspace_lives_under_base_loot_dir(tmp_path):
    orch = Orchestrator(_cfg(tmp_path, "d.yaml", "x", ["1.2.3.0/24"]))
    assert str(orch.tm.loot_dir).startswith(str(tmp_path / "loot"))
    # logging.loot_dir is rewritten so every manager inherits the scoped path.
    assert orch.config["logging"]["loot_dir"] == str(orch.tm.loot_dir)
