"""Tests for the report-generation toggle on ``Orchestrator.run_report``.

``reporting.enabled: false`` skips the automatic end-of-phase report; the
explicit ``--phase report`` (``force=True``) overrides that.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from core.orchestrator import Orchestrator


def _make_orchestrator(tmp_path: Path, *, enabled: bool) -> Orchestrator:
    cfg = {
        "engagement": {"name": "t", "operator": "op"},
        "scope": {"targets": ["10.0.0.0/30"]},
        "logging": {
            "log_dir": str(tmp_path / "logs"),
            "loot_dir": str(tmp_path / "loot"),
        },
        "reporting": {"enabled": enabled, "output_dir": str(tmp_path / "reports")},
    }
    cfg_path = tmp_path / "cfg.yaml"
    cfg_path.write_text(yaml.safe_dump(cfg), encoding="utf-8")
    orch = Orchestrator(config_path=cfg_path)
    # A host so the report has content and does not try to load state.json.
    orch.tm.add_host("10.0.0.1", is_dc=True, domain="lab.local")
    return orch


def _reports(tmp_path: Path) -> list[Path]:
    return list((tmp_path / "reports").glob("*.html"))


def test_report_skipped_when_disabled(tmp_path):
    orch = _make_orchestrator(tmp_path, enabled=False)
    orch.run_report()  # automatic call, not forced
    assert _reports(tmp_path) == []


def test_force_overrides_disabled(tmp_path):
    orch = _make_orchestrator(tmp_path, enabled=False)
    orch.run_report(force=True)
    assert len(_reports(tmp_path)) == 1


def test_report_generated_when_enabled(tmp_path):
    orch = _make_orchestrator(tmp_path, enabled=True)
    orch.run_report()
    assert len(_reports(tmp_path)) == 1
