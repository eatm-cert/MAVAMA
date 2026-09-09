# Mavama

Active Directory offensive audit orchestrator. Automates the early internal
attack chain: reconnaissance (with and without credentials) -> credential
harvesting -> reporting.

> Strictly authorized use only: lab environments or contracted penetration
> tests.

## Status

| Phase | Description                                                  | State                                  |
|------:|--------------------------------------------------------------|----------------------------------------|
| 1     | Reconnaissance & enumeration without credentials             | **validated** (unit tests + lab)       |
| 1b    | Authenticated recon (NetExec enum + detection-only vuln checks + Certipy) | **implemented**           |
| 3     | Credential harvesting (ASREProast, Kerberoast, NetExec spray) | **implemented**                       |
| 6     | Reporting - standalone HTML report + SOC detection-test log  | **implemented**                        |

### Cross-cutting features

- **Two execution modes** - `auto` (run a phase end-to-end) and `step`
  (semi-automatic: review results after each step, then continue / skip /
  stop, with an optional progress save). See *Operating Modes*.
- **Black box / grey box** - start with no credentials (full auto-discovery)
  or pre-load known accounts; grey box auto-triggers authenticated recon.
- **Safe mode** and **stealth mode** flags (`--safe`, `--stealth`).
- **Interactive setup wizard** - builds a config YAML when no `--config` is
  given (execution mode, scope, engagement mode, Kerberos wordlist, Phase 3
  spraying, ...).
- **Startup tool preflight** - prune the external-tool set, then a fast
  availability check on what remains.
- **Finding methodology** - every finding records *how* it was found (one
  line in the terminal, a full paragraph + captured evidence in the report).
- **Severity colour coding** - findings are colour-coded by severity in the
  terminal (`[X] CRITICAL`, `[!] HIGH`, `[>] MEDIUM`, `[-] LOW`, `[i] INFO`),
  mirroring the HTML report; the glyphs stay readable without colour.
- **Optional report** - choose whether the HTML report is auto-generated
  (wizard question / `reporting.enabled` / `--no-report`).
- **SOC detection-test log** - every test is logged with timestamp (UTC),
  source/target IP and a MITRE ATT&CK mapping to a CSV a blue team can ingest
  to validate EDR/SIEM detection (`reporting.soc_log`). See *SOC detection-test
  log*.
- **Non-blocking prompts** - the black-box "add a credential?" offer
  auto-resolves to *no* after 30s so an unattended auto run never stalls.

## Installation

The quickest path is the bundled setup script (Debian / Kali), which installs
the system packages, creates the `.venv`, installs the pinned requirements, and
installs Certipy:

```bash
./setup.sh                 # full setup (apt + venv + requirements + certipy)
./setup.sh --no-apt        # skip system packages (already installed / non-Debian)
```

`setup.sh` is re-runnable (existing venv and packages are reused) and ends with
a quick tool-availability check. Afterwards:

```bash
source .venv/bin/activate
sudo python3 main.py        # interactive setup wizard
```

<details>
<summary>Manual installation (equivalent steps)</summary>

```bash
# System tools (NetExec ships as 'nxc'; pre-installed on Kali).
sudo apt install -y nmap samba-common-bin impacket-scripts netexec

python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# AD CS enumeration (Phase 1b), not on PyPI under a pip name.
pipx install certipy-ad
```
</details>

The **startup tool preflight** (see *Operating Modes*) verifies these binaries
on `$PATH` before a run and reports anything missing, so you do not have to
hunt through phase logs to discover an absent tool.

Two tools are **not on PyPI** and are installed separately (setup.sh does this
automatically):

- **`netexec`** (`nxc`) - Phase 1b authenticated enumeration and Phase 3
  spraying. Pre-installed on Kali; otherwise `apt install netexec` or
  `pipx install git+https://github.com/Pennyw0rth/NetExec.git`.
- **`certipy-ad`** - AD CS enumeration (Phase 1b), via `pipx`.

The ASREProast / Kerberoast / dumping wrappers (Phase 3) drive the Impacket
scripts (`GetNPUsers.py`, `GetUserSPNs.py`, `secretsdump.py`) shipped by the
`impacket` package. Each wrapper auto-discovers its binary from `$PATH`, the
active virtualenv (`./.venv/bin/<tool>`) and pipx layouts; if a binary is
missing, the audit log emits an actionable install hint instead of crashing.

## Usage

```bash
# Whole implemented pipeline (recon -> credentials -> report).
sudo python3 main.py --config config/config.yaml --phase all

# Single phase (assumes a prior state.json is present for credentials/report):
sudo python3 main.py --config config/config.yaml --phase recon
sudo python3 main.py --config config/config.yaml --phase authed-recon
sudo python3 main.py --config config/config.yaml --phase credentials
sudo python3 main.py --config config/config.yaml --phase report

# No --config: the interactive setup wizard creates one.
sudo python3 main.py

# Quick override without editing the YAML (CIDR or range accepted):
sudo python3 main.py --targets 192.168.56.0/24 --domain lab.local

# Semi-automatic run: pause after each recon step to review and decide.
sudo python3 main.py --config config/config.yaml --step

# Safe mode (enumeration only) and/or stealth mode (slower nmap, AS-REQ jitter).
sudo python3 main.py --safe
sudo python3 main.py --stealth

# Skip the startup tool-preflight prompt + check.
sudo python3 main.py --no-tool-check

# Do not auto-generate the HTML report ('--phase report' still forces one).
sudo python3 main.py --no-report
```

Phases (`--phase`): `recon`, `authed-recon`, `credentials`, `report`, `all`.
Flags: `--targets`, `--exclude`, `--domain`, `--interface/-i`, `--safe`,
`--stealth`, `--step`, `--no-tool-check`, `--no-report`, `--no-banner`.

The effective merged configuration (YAML + CLI overrides + tool-preflight
decisions) is written next to the config as `.effective.yaml`, so the
orchestrator and the audit trail consume exactly the same values.

Output lives in:
- `logs/audit_<timestamp>.log` - full timestamped journal;
- `loot/state.json`            - serialized engagement state (hosts, services, credentials, findings, activities);
- `reports/mavama_report_<timestamp>.html` - standalone HTML report;
- `reports/mavama_soc_log_<timestamp>.csv` - SOC detection-test log (see below);
- `loot/soc_detection_log.csv` - live SOC log, streamed as tests fire (survives a crash).

### SOC detection-test log (blue-team correlation)

Every test the tool fires at the network is recorded as a precise,
machine-readable row so a **SOC can validate their EDR/SIEM detection
coverage**: *when* (UTC + local, millisecond precision), from *which source
IP*, against *which target IP/host*, *which test* (named **and mapped to a
MITRE ATT&CK** technique id + tactic), with *which tool/command*, and the
*outcome*. Analysts ingest the CSV and correlate their alerts back to a
concrete TTP by timestamp + IP + technique.

The log is **streamed live** to `loot/<engagement>/soc_detection_log.csv` as
each test runs (so a crashed engagement still leaves a complete trail), and a
finalized, time-sorted copy is written to `reports/mavama_soc_log_*.csv` at
the end of the run. Columns:

```
event_id, timestamp (UTC), timestamp_local, phase, mitre_id, mitre_tactic,
technique, technique_key, source_ip, target_ip, targets, target_host, port,
protocol, tool, command, status, details
```

`target_ip` holds the single host an activity targets (the correlation key).
For multi-host operations (nmap / ARP / ICMP / TCP sweeps, `--shares` across
the scope) `target_ip` is empty and `targets` carries the set in the form the
operator declared it - a CIDR (`192.168.56.0/24`), a range, or a
comma-separated IP list - so the report shows where a scan ran without
expanding it to hundreds of rows.

Coverage spans every implemented phase: host discovery / service enum / DC
discovery (T1018, T1046), anonymous + authenticated enumeration (T1087, T1135,
T1201, T1595.002), roasting / spraying / dumping (T1558, T1110.003, T1003).
The MITRE mapping lives in `core/attack_catalog.py`. Disable the finalized
export with `reporting.soc_log: false` (the live CSV is always written).
Regenerate from a saved state with:

```bash
python3 -m modules.reporting.soc_report loot/<engagement>/state.json reports/soc_log.csv
```

## Operating Modes

### Auto vs step-by-step execution

`engagement.execution_mode` (YAML) or `--step` (CLI) selects the pacing:

- **`auto`** (default) - each phase runs end-to-end without pausing.
- **`step`** - semi-automatic. Phase 1 is split into reviewable steps (ARP
  scan, ping sweep, TCP ping, service enum, DC identification, anonymous
  enumeration, Kerberos user-enum). After each step the tool prints what it
  found and asks whether to **continue**, **skip** the next step, or **stop**.
  On stop (or Ctrl+C) it offers to **save progress** to a filename you choose
  (default `loot/state.json`). Stopping early skips authenticated recon and the
  report - resume later with `--phase authed-recon` / `--phase report`.

Step mode requires an interactive terminal; on a non-TTY run it transparently
falls back to `auto`.

### Black box vs grey box

- **Black box** (default) - no credentials up front; full auto-discovery. After
  Phase 1 (on a TTY) the tool offers to inject a credential so authenticated
  recon can run. That offer **auto-resolves to "no" after 30s** of no input, so
  an unattended auto run is never blocked. Restarting later with a credential
  (`--phase authed-recon`) re-displays the Phase 1 recap and flags any **new**
  findings/users it uncovers (or states that none turned up).
- **Grey box** - set `credentials_file` to a YAML listing known accounts (copy
  `config/credentials.template.yaml`). Loaded credentials enter the engagement
  state before Phase 1 and auto-trigger authenticated recon (Phase 1b).

> `config/credentials.yaml` (and any `config/credentials.*.yaml`) is **never**
> committed - only `config/credentials.template.yaml` is.

### Safe mode & stealth mode

- **`--safe`** (`engagement.safe_mode`) - enumeration only: no spraying or
  dumping.
- **`--stealth`** (`engagement.stealth_mode`) - slower nmap timing (`-T2`),
  jitter between Kerberos AS-REQ probes, and at most one password per spray
  round.

## Interactive Setup Wizard

Running `main.py` with no `--config` launches a guided wizard
(`utils/cli_setup.py`) that either loads an existing config or builds a new one.
It collects: engagement name/operator, **execution mode** (auto / step), scope
(CIDR or range, comma-separated, with exclusions), the network interface
(auto-detected for the first target subnet), domain hint, **engagement mode**
(black / grey box + credentials), the **Kerberos user-enum wordlist** source
(bundled default / custom file / none), Phase 3 spraying, whether to
**auto-generate the HTML report**, and log verbosity.

## Startup Tool Preflight

Before any phase, `utils/tool_preflight.py` runs a **prune-then-verify** check:

1. It asks which external tools to **remove** from this engagement (checkbox,
   none by default) - there is no point warning about a tool you do not have or
   do not want to use.
2. It then verifies *only the remaining* tools with a fast `$PATH` lookup and
   prints a present / missing / removed summary.

Removed tools are persisted under `tools.disabled` in the config. On a non-TTY
run the prompt is skipped and the check honours whatever `tools.disabled`
already contains. Use `--no-tool-check` to bypass the preflight entirely.

## Layout

```
mavama/
├── config/
│   ├── config.yaml           # Default config.
│   └── credentials.template.yaml  # Grey-box credentials template (real file never committed).
├── core/
│   ├── logger.py             # Centralised logger (rich + file).
│   ├── target_manager.py     # Engagement state (hosts, services, users, credentials, findings, activities).
│   ├── methodology.py        # "How it was found" catalog (terminal + report).
│   ├── attack_catalog.py     # MITRE ATT&CK mapping for the SOC detection-test log.
│   ├── net.py                # Source-IP resolution (attacker IP per target).
│   └── orchestrator.py       # Phase chaining.
├── utils/
│   ├── cli_setup.py          # Interactive setup wizard.
│   ├── step_runner.py        # Auto / step-by-step phase execution controller.
│   ├── tool_preflight.py     # Startup tool prune-then-verify check.
│   └── timed_prompt.py       # Yes/no prompt with auto-timeout (non-blocking).
├── modules/
│   ├── recon/                # Phase 1 / 1b.
│   │   ├── host_discovery.py # ARP / ICMP / TCP ping.
│   │   ├── service_enum.py   # nmap + NSE (SMB signing, ldap-rootdse, ...).
│   │   ├── dc_finder.py      # DNS SRV / LDAP RootDSE / NetBIOS.
│   │   ├── anon_enum.py      # null-session / anon-bind / RID brute.
│   │   ├── user_enum.py      # Kerberos AS-REQ (kerbrute-like).
│   │   ├── authed_recon.py   # Phase 1b: NetExec enum + detection-only vuln checks + Certipy.
│   │   └── recon.py          # Phase 1 orchestrator (step-aware).
│   ├── credentials/          # Phase 3.
│   │   ├── roasting.py       # ASREProast + Kerberoast.
│   │   ├── spraying.py       # Password spray with lockout protection.
│   │   ├── dumping.py        # secretsdump (local / dcsync / ntds-offline).
│   │   └── cred_manager.py   # Phase 3 orchestrator.
│   ├── exploitation/         # ADCS enumeration helper used by Phase 1b.
│   │   └── certipy.py        # ADCS enumeration (certipy find).
│   └── reporting/            # Phase 6.
│       ├── phase1_report.py  # Standalone HTML report generator.
│       └── soc_report.py     # SOC detection-test CSV exporter (MITRE-tagged).
├── templates/report_template.html
├── wordlists/users.txt
├── tests/unit/
├── requirements.txt
├── setup.sh                 # one-shot environment setup (apt + venv + tools).
└── main.py
```

## Attack Chain

The orchestrator chains the implemented phases: from *no credentials* on a flat
AD network it maps the environment, harvests credentials, and renders an HTML
report.

### Phase 1 - Reconnaissance

1. **Host discovery**: ARP scan (scapy, requires root), ping sweep,
   TCP probes on 445/135/3389 for ICMP-filtered hosts.
2. **Service enumeration**: `nmap -sV` on the AD ports, NSE scripts
   (`smb2-security-mode`, `smb-os-discovery`, `ldap-rootdse`,
   `ssl-cert`, `rdp-ntlm-info`, `ms-sql-info`).
3. **DC finder**: DNS SRV lookups for `_ldap._tcp.dc._msdcs.<domain>`,
   anonymous LDAP bind to confirm `defaultNamingContext`, NetBIOS `<1C>`
   fallback.
4. **Anonymous enumeration**: null SMB sessions, anonymous LDAP bind,
   RID bruteforce (SAMR) on `[500..1500]`.
5. **Kerberos user enumeration**: AS-REQ without pre-auth per candidate
   user (wordlist `wordlists/users.txt`). Distinguishes `valid`,
   `asreproastable`, `disabled`, `unknown` - without triggering
   account lockouts.

Notable findings (SMB signing not required, anonymous LDAP, RID brute
success, ASREProastable accounts, ...) land in `TargetManager.findings`
with severity, description, remediation - and a methodology record (see
*Reporting*).

### Phase 1b - Authenticated Reconnaissance

As soon as a credential is known (grey box, or injected after Phase 1 on
black box), `modules/recon/authed_recon.py` deepens the picture with a valid
account. It is **enumeration / detection only** - nothing is exploited here:

- **NetExec domain enumeration**: users, groups, shares (`--shares`), and the
  password policy (`--pass-pol`). A disabled lockout policy is itself a
  `PASS-POL-*` finding.
- **Detection-only vulnerability checks** (`nxc smb -M ...`): `nopac`
  (CVE-2021-42278/42287), `zerologon` (CVE-2020-1472), `coerce_plus` (exposed
  coercion RPC), `spooler` (Print Spooler). Positive checks raise findings; no
  account is created and nothing is exploited.
- **LDAP recon**: MachineAccountQuota (`-M maq`), LAPS readability (`-M laps`).
- **LDAP relay protections** (`-M ldap-checker`): checks both LDAP signing and
  **LDAPS channel binding (EPA)** enforcement, raising an `LDAP-CB-*` finding
  where appropriate.
- **Certipy** (`certipy find`): AD CS template misconfigurations (ESC1-ESC8),
  enumeration only - no certificate is requested.

In a multi-domain forest the recon matches each credential against a DC of its
own domain. Run standalone with `--phase authed-recon` (it restores
`loot/state.json` first).

### Phase 3 - Credential Harvesting

Once any credential is in the state (grey-box account, asreproast crack, ...)
Phase 3 broadens the foothold:

- **ASREProast** (`GetNPUsers.py`): enumerate accounts with
  `UF_DONT_REQUIRE_PREAUTH` and dump `$krb5asrep$` hashes for offline
  cracking. Runs unauthenticated when a userlist is provided.
- **Kerberoast** (`GetUserSPNs.py -request`): request service tickets
  for every SPN-bearing account and dump `$krb5tgs$` hashes. Requires
  a domain credential. The wrapper synchronises the clock against the DC
  (`ntpdate`) before the roast to avoid `KRB_AP_ERR_SKEW` (run as root).
- **Password spraying** (`netexec` / `crackmapexec`): spray a small
  password list against discovered users, with two layers of lockout
  protection - a hard cap derived from the configured lockout
  threshold and a best-effort policy probe via the DC. Opt-in
  (`credentials.spraying.enabled`); disabled in safe mode.
- **Credential dumping** (`secretsdump.py`): three modes - local SAM/LSA
  on a member server, DCSync against a DC, or offline NTDS.dit parsing.
  Opt-in; disabled in safe mode.

ASREProast and Kerberoast run by default; spraying and dumping are opt-in.

### Phase 6 - Reporting

`modules/reporting/phase1_report.py` renders the engagement state into a
single, dependency-free HTML page (`reports/mavama_report_<timestamp>.html`)
with embedded CSS - open it in any browser or share it as a standalone
artefact. It is produced automatically at the end of Phase 1 and can be
re-generated from a saved state with `--phase report`.

Report generation is **optional**: set `reporting.enabled: false` (wizard
question, or `--no-report`) to skip the automatic report. The explicit
`--phase report` always forces one, regardless of that setting.

The report covers an overview (host/DC/domain/user/credential/finding counts +
severity breakdown), the forest/domain structure, per-host detail (services,
shares, RID-brute users, signing posture), the user list, harvested
credentials, certificate authorities, and the findings table.

**Finding methodology - "how it was found".** Every finding answers three
questions: *what* is wrong (title/description), *how to fix it* (remediation),
and *how it was discovered*. The methodology is sourced from
`core/methodology.py`, a catalog keyed by finding-ID prefix (an explicit
`Finding.method` overrides it):

- **Terminal** - a compact one-liner is printed the moment the finding is
  recorded, prefixed with a colour-coded severity marker, in context with the
  live scan output
  (`[>] MEDIUM how it was found -> anonymous SMB logon ... was accepted`).
- **Report** - a fuller paragraph naming the protocol/tool used and why the
  observed behaviour proves the weakness, plus any captured raw evidence.

Both the Phase 1 summary table and the authenticated-recon recap colour each
finding by severity (`[X] CRITICAL` / `[!] HIGH` / `[>] MEDIUM` / `[-] LOW` /
`[i] INFO`); the glyph keeps them distinguishable when colour is stripped.

## Tests

```bash
pytest tests/unit/                        # full unit suite
pytest tests/unit/test_recon_engine.py    # Phase 1 orchestrator
pytest tests/unit/test_authed_recon.py    # Phase 1b authenticated recon
pytest tests/unit/test_roasting.py        # ASREProast + Kerberoast wrappers
pytest tests/unit/test_spraying.py        # password spray + lockout protection
pytest tests/unit/test_cred_manager.py    # Phase 3 orchestrator
pytest tests/unit/test_step_runner.py     # auto / step-by-step controller
pytest tests/unit/test_methodology.py     # "how it was found" catalog
pytest tests/unit/test_tool_preflight.py  # startup tool prune-then-verify
pytest tests/unit/test_cli_setup.py       # interactive setup wizard
```

External dependencies (nmap, LDAP, SMB, Kerberos, NetExec) are mocked; the unit
suite exercises only the internal logic (nmap XML parsing, host merging, SMB
signing detection, AS-REQ construction, lockout-cap maths, report rendering).
