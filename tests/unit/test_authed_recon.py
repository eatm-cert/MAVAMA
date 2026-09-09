"""Unit tests for the Phase 1b authenticated-recon fail-fast login probe.

These guard the behaviour that stops Phase 1b from grinding through ~10
long-running nxc calls when the credential is wrong or the DC is unreachable.
"""

from __future__ import annotations

import subprocess
from unittest.mock import MagicMock, call, patch

from core.logger import get_logger
from core.target_manager import Credential, Finding
from modules.recon.authed_recon import AuthedRecon, _ADVANCED_NXC_MODULES


def _runner(tm, **kw) -> AuthedRecon:
    cred = Credential(username="pentest", domain="rootme.local", password="pw")
    return AuthedRecon(
        tm=tm, credential=cred, domain="rootme.local", dc_ip="10.0.0.1",
        loot_dir=str(tm.loot_dir), nxc_binary="nxc", **kw,
    )


def _completed(stdout: str = "", stderr: str = "") -> MagicMock:
    m = MagicMock()
    m.stdout = stdout
    m.stderr = stderr
    return m


# ---------------------------------------------------------------------------
# _validate_login
# ---------------------------------------------------------------------------

def test_validate_login_rejects_bad_credential(tm):
    runner = _runner(tm)
    out = "SMB 10.0.0.1 445 DC [-] rootme.local\\pentest:pw STATUS_LOGON_FAILURE"
    with patch("modules.recon.authed_recon.subprocess.run", return_value=_completed(out)):
        ok, detail = runner._validate_login()
    assert ok is False
    assert "rejected" in detail.lower() or "logon failure" in detail.lower()


def test_validate_login_detects_unreachable_timeout(tm):
    runner = _runner(tm)
    with patch(
        "modules.recon.authed_recon.subprocess.run",
        side_effect=subprocess.TimeoutExpired(cmd="nxc", timeout=45),
    ):
        ok, detail = runner._validate_login()
    assert ok is False
    assert "unreachable" in detail.lower() or "slow" in detail.lower()


def test_validate_login_accepts_good_credential(tm):
    runner = _runner(tm)
    out = "SMB 10.0.0.1 445 DC [+] rootme.local\\pentest:pw"
    with patch("modules.recon.authed_recon.subprocess.run", return_value=_completed(out)):
        ok, detail = runner._validate_login()
    assert ok is True


def test_probe_uses_short_timeout(tm):
    # The probe must cap at min(timeout, 45), regardless of the per-call timeout.
    runner = _runner(tm, timeout=300)
    with patch("modules.recon.authed_recon.subprocess.run", return_value=_completed("[+] ok")) as run_mock:
        runner._validate_login()
    assert run_mock.call_args.kwargs["timeout"] == 45


# ---------------------------------------------------------------------------
# Roast-blob guard: a $krb5* blob in nt_hash must never reach nxc's -H
# ---------------------------------------------------------------------------

def _blob_runner(tm) -> AuthedRecon:
    cred = Credential(
        username="svc", domain="rootme.local",
        nt_hash="$krb5tgs$23$*svc$ROOTME$abcdef", source="kerberoast",
    )
    return AuthedRecon(
        tm=tm, credential=cred, domain="rootme.local", dc_ip="10.0.0.1",
        loot_dir=str(tm.loot_dir), nxc_binary="nxc",
    )


def test_auth_args_omits_H_for_roast_blob(tm):
    assert "-H" not in _blob_runner(tm)._auth_args()


def test_auth_args_emits_H_for_real_hash(tm):
    cred = Credential(username="u", domain="rootme.local", nt_hash="ab" * 16)
    runner = AuthedRecon(
        tm=tm, credential=cred, domain="rootme.local", dc_ip="10.0.0.1",
        loot_dir=str(tm.loot_dir), nxc_binary="nxc",
    )
    args = runner._auth_args()
    assert "-H" in args
    assert args[args.index("-H") + 1] == "ab" * 16


def test_check_prerequisites_rejects_roast_blob_only(tm):
    ok, reason = _blob_runner(tm).check_prerequisites()
    assert ok is False
    assert "NT hash" in reason


# ---------------------------------------------------------------------------
# run() aborts fast on auth failure
# ---------------------------------------------------------------------------

def test_run_aborts_before_enumeration_on_auth_failure(tm):
    tm.add_host("10.0.0.1", is_dc=True, domain="rootme.local")
    runner = _runner(tm)
    with patch(
        "modules.recon.authed_recon.subprocess.run",
        return_value=_completed("[-] STATUS_LOGON_FAILURE"),
    ) as run_mock, \
         patch.object(AuthedRecon, "_domain_enum") as de, \
         patch.object(AuthedRecon, "_vuln_checks") as vc, \
         patch.object(AuthedRecon, "_ldap_recon") as lr, \
         patch.object(AuthedRecon, "_certipy_find") as cf:
        result = runner.run()

    assert result.status == "auth-failed"
    # Only the login probe ran; none of the heavy enumeration steps were reached.
    de.assert_not_called()
    vc.assert_not_called()
    lr.assert_not_called()
    cf.assert_not_called()
    assert run_mock.call_count == 1


# ---------------------------------------------------------------------------
# [MODIF] – _enum_users_with_fallback
# ---------------------------------------------------------------------------

def _nxc_run_factory(responses: list):
    """Return a side_effect list for subprocess.run producing given outputs."""
    results = []
    for r in responses:
        m = MagicMock()
        m.stdout = r
        m.stderr = ""
        m.returncode = 0
        results.append(m)
    return results


def test_enum_users_null_session_succeeds(tm):
    """First attempt (null-session --users) returns users → no further calls."""
    runner = _runner(tm)
    nxc_output = (
        "SMB 10.0.0.1 445 DC01  -Username-      -Last PW Set-  -BadPW-\n"
        "SMB 10.0.0.1 445 DC01  robb.stark      2026-01-01     0\n"
    )
    proc = MagicMock(stdout=nxc_output, stderr="", returncode=0)
    with patch("modules.recon.authed_recon.subprocess.run", return_value=proc) as run_mock:
        users, method, raw = runner._enum_users_with_fallback("10.0.0.1")

    assert "robb.stark" in users
    assert "null session" in method
    assert "robb.stark" in raw
    # Only one subprocess.run call (the null-session --users attempt).
    assert run_mock.call_count == 1


def test_enum_users_fallback_to_rid_brute(tm):
    """Null-session --users returns nothing → fallback to null-session --rid-brute."""
    runner = _runner(tm)
    empty = MagicMock(stdout="SMB 10.0.0.1 445 DC01 (no users)", stderr="", returncode=0)
    rid_output = MagicMock(
        stdout="SMB 10.0.0.1 445 DC01  ROOTME\\robb.stark (SidTypeUser)\n",
        stderr="", returncode=0,
    )
    with patch("modules.recon.authed_recon.subprocess.run", side_effect=[empty, rid_output]):
        users, method, raw = runner._enum_users_with_fallback("10.0.0.1")

    assert "robb.stark" in users
    assert "rid-brute" in method


def test_enum_users_fallback_to_credentialed(tm):
    """Both null methods fail → fall back to credentialed --users via _nxc."""
    runner = _runner(tm)
    empty = MagicMock(stdout="nothing", stderr="", returncode=0)
    cred_output = (
        "SMB 10.0.0.1 445 DC01  -Username-      -Last PW Set-  -BadPW-\n"
        "SMB 10.0.0.1 445 DC01  eddard.stark    2026-01-01     0\n"
    )
    cred_proc = MagicMock(stdout=cred_output, stderr="", returncode=0)
    with patch("modules.recon.authed_recon.subprocess.run",
               side_effect=[empty, empty, cred_proc]):
        users, method, raw = runner._enum_users_with_fallback("10.0.0.1")

    assert "eddard.stark" in users
    assert "credentialed" in method


def test_enum_users_all_methods_exhausted(tm):
    """All methods return nothing → empty set with descriptive method string."""
    runner = _runner(tm)
    empty = MagicMock(stdout="nothing", stderr="", returncode=0)
    with patch("modules.recon.authed_recon.subprocess.run", return_value=empty):
        users, method, raw = runner._enum_users_with_fallback("10.0.0.1")

    assert users == set()
    assert "exhausted" in method


def test_enum_users_raw_output_stored_in_result(tm):
    """Raw nxc output must be preserved in result.raw_outputs['smb_users'], not discarded."""
    runner = _runner(tm)
    nxc_output = (
        "SMB 10.0.0.1 445 DC  -Username-      -Last PW Set-  -BadPW-\n"
        "SMB 10.0.0.1 445 DC  robb.stark      2026-01-01     0\n"
    )
    from modules.recon.authed_recon import AuthedReconResult
    result = AuthedReconResult()
    proc = MagicMock(stdout=nxc_output, stderr="", returncode=0)
    with patch("modules.recon.authed_recon.subprocess.run", return_value=proc), \
         patch.object(runner, "_nxc", return_value=""):
        runner._domain_enum(result)

    raw = result.raw_outputs.get("smb_users", "")
    assert "robb.stark" in raw, "Raw nxc output must appear in smb_users loot entry"


def test_domain_enum_records_finding_with_method(tm):
    """_domain_enum must record a USER-ENUM finding that names the method used."""
    runner = _runner(tm)
    null_out = (
        "SMB 10.0.0.1 445 DC  -Username-      -Last PW Set-  -BadPW-\n"
        "SMB 10.0.0.1 445 DC  robb.stark      2026-01-01     0\n"
    )
    from modules.recon.authed_recon import AuthedReconResult
    result = AuthedReconResult()
    proc = MagicMock(stdout=null_out, stderr="", returncode=0)
    with patch("modules.recon.authed_recon.subprocess.run", return_value=proc), \
         patch.object(runner, "_nxc", return_value="") as _nxc_mock:
        runner._domain_enum(result)

    finding_ids = {f.id for f in tm.findings}
    assert "USER-ENUM-10.0.0.1" in finding_ids
    ue_finding = next(f for f in tm.findings if f.id == "USER-ENUM-10.0.0.1")
    assert "null session" in ue_finding.title.lower()


def test_domain_enum_no_result_when_all_fail(tm):
    """When no users are returned by any method, no_result must be called."""
    runner = _runner(tm)
    log = get_logger()
    no_result_calls: list[str] = []
    original = log.no_result
    log.no_result = lambda msg: no_result_calls.append(msg)  # type: ignore[method-assign]
    try:
        empty = MagicMock(stdout="nothing", stderr="", returncode=0)
        from modules.recon.authed_recon import AuthedReconResult
        result = AuthedReconResult()
        with patch("modules.recon.authed_recon.subprocess.run", return_value=empty), \
             patch.object(runner, "_nxc", return_value=""):
            runner._domain_enum(result)
    finally:
        log.no_result = original  # type: ignore[method-assign]

    assert any("user enum" in m.lower() or "no users" in m.lower()
               for m in no_result_calls), f"Expected no_result for user enum; got: {no_result_calls}"


# ---------------------------------------------------------------------------
# [MODIF] – _advanced_module_audit
# ---------------------------------------------------------------------------

def test_advanced_module_audit_emits_finding_on_positive(tm):
    """A positive petitpotam result must create a PETITPOTAM finding."""
    runner = _runner(tm)
    tm.add_host("10.0.0.1", is_dc=True)
    h = tm.get_host("10.0.0.1")
    h.add_service(port=445, name="smb")

    positive_output = "SMB 10.0.0.1 445 DC [+] PetitPotam: vulnerable"

    from modules.recon.authed_recon import AuthedReconResult
    result = AuthedReconResult()
    with patch.object(runner, "_nxc", return_value=positive_output):
        runner._advanced_module_audit(result)

    finding_ids = {f.id for f in tm.findings}
    assert "PETITPOTAM-10.0.0.1" in finding_ids


def test_advanced_module_audit_no_result_on_clean(tm):
    """When all modules report clean, no_result must be called for each."""
    runner = _runner(tm)
    tm.add_host("10.0.0.1", is_dc=True)
    h = tm.get_host("10.0.0.1")
    h.add_service(port=445, name="smb")

    log = get_logger()
    no_result_calls: list[str] = []
    original = log.no_result
    log.no_result = lambda msg: no_result_calls.append(msg)  # type: ignore[method-assign]
    try:
        clean_output = "SMB 10.0.0.1 445 DC [+] No vulnerability detected"
        from modules.recon.authed_recon import AuthedReconResult
        result = AuthedReconResult()
        with patch.object(runner, "_nxc", return_value=clean_output):
            runner._advanced_module_audit(result)
    finally:
        log.no_result = original  # type: ignore[method-assign]

    assert len(no_result_calls) >= 1, "Expected at least one no_result call for clean modules"
    assert not any(f.id.startswith("PETITPOTAM-") for f in tm.findings)


def test_advanced_module_audit_gpp_password_finding(tm):
    """A gpp_password positive result must create a GPP-PASSWORD finding."""
    runner = _runner(tm)
    tm.add_host("10.0.0.1", is_dc=True)
    h = tm.get_host("10.0.0.1")
    h.add_service(port=445, name="smb")

    gpp_output = (
        "SMB 10.0.0.1 445 DC [+] Found SYSVOL share\n"
        "SMB 10.0.0.1 445 DC [!] Found Username: svc_gpp\n"
        "SMB 10.0.0.1 445 DC [!] Decrypted password: Welcome1\n"
    )
    from modules.recon.authed_recon import AuthedReconResult
    result = AuthedReconResult()

    def _mock_nxc(proto, targets, extra):
        if extra == ["-M", "gpp_password"]:
            return gpp_output
        return "SMB 10.0.0.1 445 DC [+] No issue"

    with patch.object(runner, "_nxc", side_effect=_mock_nxc):
        runner._advanced_module_audit(result)

    finding_ids = {f.id for f in tm.findings}
    assert "GPP-PASSWORD-10.0.0.1" in finding_ids


def test_advanced_module_audit_stores_raw_output(tm):
    """Raw output for each advanced module must be stored in result.raw_outputs."""
    runner = _runner(tm)
    tm.add_host("10.0.0.1", is_dc=True)
    h = tm.get_host("10.0.0.1")
    h.add_service(port=445, name="smb")

    from modules.recon.authed_recon import AuthedReconResult
    result = AuthedReconResult()
    with patch.object(runner, "_nxc", return_value="SMB 10.0.0.1 not vulnerable"):
        runner._advanced_module_audit(result)

    for module, *_ in _ADVANCED_NXC_MODULES:
        assert f"adv_{module}" in result.raw_outputs, \
            f"raw_outputs missing key adv_{module}"


def test_advanced_module_audit_runs_after_vuln_checks(tm):
    """_advanced_module_audit must be called during a successful run()."""
    tm.add_host("10.0.0.1", is_dc=True, domain="rootme.local")
    runner = _runner(tm)
    good_login = "SMB 10.0.0.1 445 DC [+] rootme.local\\pentest:pw"
    with patch("modules.recon.authed_recon.subprocess.run",
               return_value=MagicMock(stdout=good_login, stderr="", returncode=0)), \
         patch.object(AuthedRecon, "_domain_enum"), \
         patch.object(AuthedRecon, "_vuln_checks"), \
         patch.object(AuthedRecon, "_ldap_recon"), \
         patch.object(AuthedRecon, "_certipy_find"), \
         patch.object(AuthedRecon, "_advanced_module_audit") as adv_mock:
        runner.run()

    adv_mock.assert_called_once()


# ---------------------------------------------------------------------------
# [MODIF] – no_result logger method
# ---------------------------------------------------------------------------

def test_logger_no_result_format():
    """no_result must emit a message containing the cyan checkmark markup."""
    log = get_logger()
    messages: list[str] = []
    with patch.object(log._logger, "info", side_effect=lambda m: messages.append(m)):
        log.no_result("test message")

    assert messages, "no_result must call _logger.info"
    assert "[cyan]" in messages[0] or "✓" in messages[0], \
        f"Expected cyan or checkmark in no_result output; got: {messages[0]}"


# ---------------------------------------------------------------------------
# enum_av parser
# ---------------------------------------------------------------------------

def test_parse_av_products_skips_auth_line_and_credential():
    """The nxc auth-success line `[+] domain\\user:secret` must NOT be parsed as
    an AV product - that produced a bogus finding and leaked the credential."""
    out = (
        "SMB 192.168.56.10 445 KINGSLANDING [+] sevenkingdoms.local\\jaime.lannister:cersei\n"
        "SMB 192.168.56.10 445 KINGSLANDING [+] Windows Defender Antivirus - enabled\n"
        "SMB 192.168.56.10 445 KINGSLANDING [+] sevenkingdoms.local\\admin:pw (Pwn3d!)\n"
    )
    products = AuthedRecon._parse_av_products(out)
    assert products == ["Windows Defender Antivirus - enabled"]
    assert not any("cersei" in p or "jaime" in p or "\\" in p for p in products)


# ---------------------------------------------------------------------------
# GPP credential parsers
# ---------------------------------------------------------------------------

def test_parse_gpp_credentials_extracts_username_and_password(tm):
    """_parse_gpp_credentials must extract username/password from nxc output."""
    runner = _runner(tm)
    output = (
        "SMB 10.0.0.1 445 DC [+] Found credentials in GPP\n"
        "SMB 10.0.0.1 445 DC Username: svc_backup\n"
        "SMB 10.0.0.1 445 DC Password: Backup2024!\n"
        "SMB 10.0.0.1 445 DC Domain:   ROOTME\n"
        "SMB 10.0.0.1 445 DC GPO:      Default Domain Policy\n"
    )
    creds = runner._parse_gpp_credentials(output)
    assert len(creds) >= 1
    assert creds[0]["username"] == "svc_backup"
    assert creds[0]["password"] == "Backup2024!"
    assert creds[0].get("domain") == "ROOTME"


def test_parse_gpp_autologin_extracts_credentials(tm):
    """_parse_gpp_autologin must extract username/password from nxc autologin output."""
    runner = _runner(tm)
    output = (
        "SMB 10.0.0.1 445 DC [+] Found autologin credentials\n"
        "SMB 10.0.0.1 445 DC DefaultDomainName: ROOTME\n"
        "SMB 10.0.0.1 445 DC DefaultUserName:   administrator\n"
        "SMB 10.0.0.1 445 DC DefaultPassword:   Admin123!\n"
    )
    creds = runner._parse_gpp_autologin(output)
    assert len(creds) >= 1
    assert creds[0]["username"] == "administrator"
    assert creds[0]["password"] == "Admin123!"


def test_handle_gpp_credentials_stores_in_tm(tm):
    """_handle_gpp_credentials must store the recovered credential in tm.credentials."""
    runner = _runner(tm)
    output = (
        "SMB 10.0.0.1 445 DC [+] Found credentials in GPP\n"
        "SMB 10.0.0.1 445 DC Username: svc_backup\n"
        "SMB 10.0.0.1 445 DC Password: Backup2024!\n"
        "SMB 10.0.0.1 445 DC Domain:   ROOTME\n"
    )
    runner._handle_gpp_credentials(output, "10.0.0.1")
    assert any(c.username == "svc_backup" for c in tm.credentials), \
        "GPP credential must be added to tm.credentials"
    cred = next(c for c in tm.credentials if c.username == "svc_backup")
    assert cred.password == "Backup2024!"
    assert "GPP-SYSVOL" in cred.source


def test_handle_gpp_autologin_stores_in_tm(tm):
    """_handle_gpp_autologin must store the recovered credential in tm.credentials."""
    runner = _runner(tm)
    output = (
        "SMB 10.0.0.1 445 DC [+] Found autologin credentials\n"
        "SMB 10.0.0.1 445 DC DefaultUserName:   administrator\n"
        "SMB 10.0.0.1 445 DC DefaultPassword:   Admin123!\n"
    )
    runner._handle_gpp_autologin(output, "10.0.0.1")
    assert any(c.username == "administrator" for c in tm.credentials)
    cred = next(c for c in tm.credentials if c.username == "administrator")
    assert cred.password == "Admin123!"
    assert "GPP-AUTOLOGIN" in cred.source


def test_advanced_module_audit_stores_gpp_credentials_in_tm(tm):
    """Full pipeline: gpp_password positive → credential stored in tm."""
    runner = _runner(tm)
    tm.add_host("10.0.0.1", is_dc=True)
    h = tm.get_host("10.0.0.1")
    h.add_service(port=445, name="smb")

    # Use output that matches the stricter _module_is_positive rules (found username/password).
    gpp_out = (
        "SMB 10.0.0.1 445 DC [+] Found SYSVOL share\n"
        "SMB 10.0.0.1 445 DC [!] Found Username: svc_backup\n"
        "SMB 10.0.0.1 445 DC [!] Found Password: Backup2024!\n"
        "SMB 10.0.0.1 445 DC [!] Found Domain:   ROOTME\n"
    )
    from modules.recon.authed_recon import AuthedReconResult
    result = AuthedReconResult()

    def _mock_nxc(proto, targets, extra):
        return gpp_out if extra == ["-M", "gpp_password"] else "SMB 10.0.0.1 not vulnerable"

    with patch.object(runner, "_nxc", side_effect=_mock_nxc):
        runner._advanced_module_audit(result)

    assert any(c.username == "svc_backup" for c in tm.credentials), \
        "svc_backup must appear in tm.credentials after GPP audit"


# ---------------------------------------------------------------------------
# _ldap_relay_protections - LDAP signing / LDAPS channel binding (EPA) check
# ---------------------------------------------------------------------------

def _cb_findings(tm, dc_ip, nxc_output):
    from modules.recon.authed_recon import AuthedReconResult
    runner = _runner(tm)
    runner.dc_ip = dc_ip
    with patch.object(runner, "_nxc", return_value=nxc_output):
        runner._ldap_relay_protections(AuthedReconResult())
    return {f.id for f in tm.findings}


def test_ldap_checker_flags_signing_and_channel_binding(tm):
    tm.add_host("10.0.0.1")
    out = (
        'LDAP Signing NOT Enforced!\n'
        'LDAPS Channel Binding is set to "Never" - Vulnerable!'
    )
    ids = _cb_findings(tm, "10.0.0.1", out)
    assert "LDAP-SIGNING-10.0.0.1" in ids
    assert "LDAP-CB-10.0.0.1" in ids
    tags = tm.hosts["10.0.0.1"].tags
    assert "relay-target-ldap" in tags and "relay-target-ldaps" in tags


def test_ldap_checker_enforced_raises_nothing(tm):
    tm.add_host("10.0.0.2")
    # "Not vulnerable" must NOT be mis-parsed as vulnerable via the word
    # "vulnerable"; "Always" is the safe channel-binding value.
    out = (
        'LDAP Signing IS Enforced\n'
        'LDAPS Channel Binding is set to "Always" - Not vulnerable'
    )
    assert _cb_findings(tm, "10.0.0.2", out) == set()


def test_ldap_checker_channel_binding_when_supported_is_vulnerable(tm):
    tm.add_host("10.0.0.3")
    out = (
        'LDAP Signing IS Enforced\n'
        'LDAPS Channel Binding is set to "When Supported"'
    )
    ids = _cb_findings(tm, "10.0.0.3", out)
    assert ids == {"LDAP-CB-10.0.0.3"}
