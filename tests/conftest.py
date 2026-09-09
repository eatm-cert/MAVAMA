"""Shared pytest fixtures and path setup for the Mavama test suite."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

# Make the project root importable so `core.*` / `modules.*` resolve
# without requiring an installed package.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core.logger import AuditLogger  # noqa: E402
from core.target_manager import TargetManager  # noqa: E402


@pytest.fixture(autouse=True)
def _init_logger(tmp_path):
    """Reset the shared logger to a throwaway directory per test."""
    AuditLogger.init(log_dir=str(tmp_path / "logs"), level="DEBUG")
    yield


@pytest.fixture
def tm(tmp_path) -> TargetManager:
    """Clean TargetManager backed by a temporary loot directory."""
    return TargetManager(loot_dir=str(tmp_path / "loot"))


@pytest.fixture
def fixtures_dir() -> Path:
    return PROJECT_ROOT / "tests" / "fixtures"
