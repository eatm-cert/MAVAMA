"""SOC detection-test log - CSV exporter.

The engagement streams every test it fires to a live CSV in the loot dir
(``TargetManager._append_activity_csv``) so the log survives a crash. This
module produces the *finalized* copy dropped into ``reports/`` at the end of
the run: the same schema, sorted by timestamp, ready for a SOC to ingest into
their SIEM/EDR and correlate alerts against the tool's activity by time +
source/target IP + MITRE ATT&CK technique.

The column schema lives in :mod:`core.target_manager` (``ACTIVITY_CSV_COLUMNS``)
so the live writer and this exporter never drift apart.

Usage (standalone)::

    python3 -m modules.reporting.soc_report loot/state.json reports/soc_log.csv
"""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

from core.target_manager import ACTIVITY_CSV_COLUMNS


def _ts_key(row: dict) -> str:
    """Sort key: UTC timestamp, falling back to the raw string."""
    return str(row.get("timestamp") or "")


def write_soc_csv(activities: list[dict], output_path: str | Path) -> Path:
    """Write ``activities`` (list of dicts) to a SOC CSV, sorted by time."""
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    rows = sorted(activities, key=_ts_key)
    with out.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=ACTIVITY_CSV_COLUMNS, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            # Guarantee every declared column is present even for older rows.
            writer.writerow({col: row.get(col, "") for col in ACTIVITY_CSV_COLUMNS})
    return out


def generate_from_state_file(
    state_path: str | Path, output_path: str | Path
) -> Path:
    """Load a ``state.json`` and export its activities to a SOC CSV."""
    with Path(state_path).open("r", encoding="utf-8") as fh:
        state = json.load(fh)
    return write_soc_csv(state.get("activities", []) or [], output_path)


def generate_from_target_manager(tm: Any, output_path: str | Path) -> Path:
    """Export the SOC CSV directly from a live ``TargetManager``."""
    return write_soc_csv(tm.to_dict().get("activities", []) or [], output_path)


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print(
            "Usage: python3 -m modules.reporting.soc_report "
            "<state.json> [output.csv]",
            file=sys.stderr,
        )
        raise SystemExit(2)

    src = sys.argv[1]
    dst = sys.argv[2] if len(sys.argv) > 2 else "reports/soc_detection_log.csv"
    path = generate_from_state_file(src, dst)
    print(f"[+] SOC detection-test log written to {path}")
