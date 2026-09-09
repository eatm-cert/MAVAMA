"""Tests for the SOC detection-test activity log.

Covers the three new pieces that make the engagement auditable by a blue
team: the MITRE ATT&CK catalog (:mod:`core.attack_catalog`), the
``TargetManager.record_activity`` recording API (live CSV + state
persistence), and the CSV exporter (:mod:`modules.reporting.soc_report`).
"""

from __future__ import annotations

import csv
from datetime import datetime, timezone

import pytest

from core import attack_catalog
from core.net import source_ip_for
from core.target_manager import (
    ACTIVITY_CSV_COLUMNS,
    TargetManager,
)
from modules.reporting import soc_report


# ---------------------------------------------------------------------------
# MITRE ATT&CK catalog
# ---------------------------------------------------------------------------

def test_catalog_resolves_known_technique():
    tech = attack_catalog.lookup("kerberoast")
    assert tech.mitre_id == "T1558.003"
    assert tech.tactic == "Credential Access"
    assert "Kerberoasting" in tech.name


def test_catalog_unknown_key_returns_placeholder_not_error():
    tech = attack_catalog.lookup("does-not-exist")
    assert tech.mitre_id == "T0000"
    assert tech.tactic == "Unknown"


def test_every_catalog_entry_has_id_tactic_and_name():
    for key in attack_catalog.known_keys():
        tech = attack_catalog.lookup(key)
        assert tech.mitre_id.startswith("T")
        assert tech.tactic
        assert tech.name


# ---------------------------------------------------------------------------
# record_activity
# ---------------------------------------------------------------------------

def test_record_activity_fills_mitre_fields_from_catalog(tm: TargetManager):
    tm.add_host("192.168.56.10", hostname="kingslanding", is_dc=True)
    act = tm.record_activity(
        "kerberoast", "192.168.56.10", phase="Phase 3", status="completed",
    )
    assert act.mitre_id == "T1558.003"
    assert act.mitre_tactic == "Credential Access"
    assert act.target_host == "kingslanding"   # filled from the known host
    assert act.port == 88                        # catalog default
    assert act.protocol == "kerberos"
    assert act.status == "completed"
    assert act.event_id == "EVT-000001"


def test_record_activity_timestamp_is_utc_iso8601(tm: TargetManager):
    act = tm.record_activity("dc-discovery")
    parsed = datetime.fromisoformat(act.timestamp)
    assert parsed.tzinfo is not None
    assert parsed.utcoffset() == timezone.utc.utcoffset(None)


def test_record_activity_event_ids_are_monotonic(tm: TargetManager):
    a1 = tm.record_activity("dc-discovery")
    a2 = tm.record_activity("service-enum", "192.168.56.10")
    assert (a1.event_id, a2.event_id) == ("EVT-000001", "EVT-000002")


def test_explicit_overrides_win_over_catalog_defaults(tm: TargetManager):
    act = tm.record_activity(
        "adcs-enum", "10.0.0.1", port=443, protocol="https",
        tool="certipy", source_ip="10.0.0.250",
    )
    assert act.port == 443
    assert act.protocol == "https"
    assert act.source_ip == "10.0.0.250"


def test_record_activity_streams_csv_with_header(tm: TargetManager):
    tm.record_activity("llmnr-poisoning", source_ip="10.0.0.250")
    tm.record_activity("coercion", "192.168.56.12", source_ip="10.0.0.250")

    assert tm.soc_csv_path.exists()
    with tm.soc_csv_path.open() as fh:
        rows = list(csv.DictReader(fh))
    assert len(rows) == 2
    assert list(rows[0].keys()) == ACTIVITY_CSV_COLUMNS
    assert rows[1]["mitre_id"] == "T1187"
    assert rows[1]["target_ip"] == "192.168.56.12"


def test_multi_host_activity_records_target_set(tm: TargetManager):
    # A sweep has no single target IP but must record the scope it covered.
    act = tm.record_activity(
        "host-discovery-arp", targets="192.168.56.0/24", source_ip="10.0.0.1",
    )
    assert act.target_ip == ""
    assert act.targets == "192.168.56.0/24"

    # A single-host activity keeps target_ip and leaves the set empty.
    single = tm.record_activity("service-enum", "192.168.56.10")
    assert single.target_ip == "192.168.56.10"
    assert single.targets == ""


def test_record_activity_never_raises_on_csv_failure(tm: TargetManager, monkeypatch):
    def boom(_activity):
        raise OSError("disk full")

    monkeypatch.setattr(tm, "_append_activity_csv", boom)
    # Must still record in-memory and return without raising.
    act = tm.record_activity("dcsync", "192.168.56.10")
    assert act in tm.activities


# ---------------------------------------------------------------------------
# Persistence round-trip
# ---------------------------------------------------------------------------

def test_activities_survive_save_and_reload(tm: TargetManager, tmp_path):
    tm.record_activity("kerberoast", "192.168.56.10", phase="Phase 3")
    tm.record_activity("dcsync", "192.168.56.10", phase="Phase 4")
    state_file = tm.save()

    restored = TargetManager(loot_dir=str(tmp_path / "loot2"))
    assert restored.load_from_json(state_file) is True
    assert len(restored.activities) == 2
    # The event sequence resumes so a later phase keeps unique ids.
    nxt = restored.record_activity("bloodhound", "192.168.56.10")
    assert nxt.event_id == "EVT-000003"


# ---------------------------------------------------------------------------
# CSV exporter
# ---------------------------------------------------------------------------

def test_export_sorts_by_timestamp_and_keeps_all_columns(tm: TargetManager, tmp_path):
    tm.record_activity("kerberoast", "192.168.56.10")
    tm.record_activity("coercion", "192.168.56.12")
    out = soc_report.generate_from_target_manager(tm, tmp_path / "soc.csv")

    with out.open() as fh:
        reader = csv.DictReader(fh)
        assert reader.fieldnames == ACTIVITY_CSV_COLUMNS
        rows = list(reader)
    assert len(rows) == 2
    timestamps = [r["timestamp"] for r in rows]
    assert timestamps == sorted(timestamps)


def test_export_from_state_file_tolerates_missing_columns(tmp_path):
    # A legacy row missing newer columns must still export cleanly.
    state = {"activities": [{"event_id": "EVT-000001", "timestamp": "2026-06-19T10:00:00+00:00",
                             "mitre_id": "T1046", "technique": "Network Service Discovery"}]}
    import json
    state_path = tmp_path / "state.json"
    state_path.write_text(json.dumps(state), encoding="utf-8")

    out = soc_report.generate_from_state_file(state_path, tmp_path / "soc.csv")
    with out.open() as fh:
        rows = list(csv.DictReader(fh))
    assert len(rows) == 1
    assert rows[0]["target_ip"] == ""   # filled as empty, not crashing


# ---------------------------------------------------------------------------
# Source IP helper
# ---------------------------------------------------------------------------

def test_source_ip_for_returns_ipv4_or_fallback():
    ip = source_ip_for("192.168.56.10", fallback="0.0.0.0")
    # Either a routable local IP, or the fallback when no route exists.
    assert ip == "0.0.0.0" or ip.count(".") == 3
