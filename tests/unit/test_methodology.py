"""Unit tests for ``core.methodology`` (the "how it was found" catalog)."""

from __future__ import annotations

import pytest

from core.methodology import _CATALOG, Methodology, explain
from core.target_manager import Finding


# ---------------------------------------------------------------------------
# Prefix matching
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "finding_id,expected_prefix",
    [
        ("SMB-NULL-10.0.0.1", "SMB-NULL"),
        ("SMB-READ-10.0.0.1-NETLOGON", "SMB-READ"),
        ("SMB-SIGN-10.0.0.1", "SMB-SIGN"),
        ("LDAP-ANON-10.0.0.1", "LDAP-ANON"),
        ("LDAP-SIGN-10.0.0.1", "LDAP-SIGN"),
        ("RID-BRUTE-10.0.0.1", "RID-BRUTE"),
        ("ASREP-robb.stark", "ASREP"),
        ("ADCS-WEB-10.0.0.1", "ADCS-WEB"),
        ("NOPAC-10.0.0.1", "NOPAC"),
        ("ZEROLOGON-10.0.0.1", "ZEROLOGON"),
        ("DCSYNC-10.0.0.1", "DCSYNC"),
    ],
)
def test_explain_matches_known_prefixes(finding_id, expected_prefix):
    finding = Finding(id=finding_id, title="t", severity="high")
    result = explain(finding)
    assert result == _CATALOG[expected_prefix]
    assert result.short and result.detail


def test_more_specific_prefix_wins_over_generic():
    """ADCS-WEB must win over the generic ADCS entry."""
    web = explain(Finding(id="ADCS-WEB-10.0.0.1", title="t", severity="info"))
    esc = explain(Finding(id="ADCS-ESC1-VulnTemplate", title="t", severity="high"))
    assert web == _CATALOG["ADCS-WEB"]
    assert esc == _CATALOG["ADCS"]
    assert web != esc


def test_unknown_id_returns_fallback():
    result = explain(Finding(id="TOTALLY-UNKNOWN-X", title="t", severity="info"))
    assert "recorded automatically" in result.detail.lower()
    assert result.short


# ---------------------------------------------------------------------------
# Explicit method override
# ---------------------------------------------------------------------------

def test_explicit_method_overrides_catalog():
    finding = Finding(
        id="SMB-NULL-10.0.0.1",
        title="t",
        severity="medium",
        method="Custom probe X ran. It returned Y, proving Z.",
    )
    result = explain(finding)
    assert result.detail == "Custom probe X ran. It returned Y, proving Z."
    # short is the first sentence of the explicit method.
    assert result.short == "Custom probe X ran"


def test_explicit_method_short_is_truncated_when_long():
    long_method = "A" * 300
    result = explain(Finding(id="X", title="t", severity="info", method=long_method))
    assert len(result.short) <= 160
    assert result.short.endswith("...")
    assert result.detail == long_method


# ---------------------------------------------------------------------------
# Works on serialized dicts (the report path)
# ---------------------------------------------------------------------------

def test_explain_accepts_serialized_dict():
    finding = Finding(id="LDAP-ANON-10.0.0.1", title="t", severity="low")
    as_dict = {
        "id": finding.id,
        "title": finding.title,
        "severity": finding.severity,
        "method": "",
    }
    assert explain(as_dict) == explain(finding) == _CATALOG["LDAP-ANON"]


def test_all_catalog_entries_have_both_levels():
    for prefix, meth in _CATALOG.items():
        assert isinstance(meth, Methodology), prefix
        assert meth.short.strip(), prefix
        assert meth.detail.strip(), prefix
        # The terminal line stays compact.
        assert len(meth.short) <= 160, prefix
