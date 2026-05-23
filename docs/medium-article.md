# Operation Desert Hydra: How I Turned Public Threat Intelligence Into 11 Validated Detections

*A complete walkthrough — from raw CTI reports to Kibana proof screenshots, deployed in a reproducible lab*

---

## Table of Contents

1. [Why MuddyWater?](#why-muddywater)
2. [The Pipeline](#the-pipeline)
3. [Phase 1: Source Gathering](#phase-1-source-gathering)
4. [Phase 2: Procedure Dataset](#phase-2-procedure-dataset)
5. [Phase 3: OpenCTI Knowledge Graph](#phase-3-opencti-knowledge-graph)
6. [Phase 4: Detection Atlas](#phase-4-detection-atlas)
7. [Phase 5: Validation Lab](#phase-5-validation-lab)
   - [Step 21 — Spearphishing Delivery Chain](#step-21-det_mw_0001--spearphishing-delivery-chain)
   - [Step 22 — Web Service Shell Spawn](#step-22-det_mw_0002--web-service-shell-spawn)
   - [Step 23 — PowerShell Encoded Command](#step-23-det_mw_0003--powershell-encoded-command)
   - [Step 24 — DLL Side-Loading](#step-24-det_mw_0004--dll-side-loading)
   - [Step 25 — Registry Run Key Persistence](#step-25-det_mw_0005--registry-run-key-persistence)
   - [Step 26 — Scheduled Task (43-Minute Beacon)](#step-26-det_mw_0006--scheduled-task-43-minute-beacon)
   - [Step 27 — RMM Tool Abuse](#step-27-det_mw_0007--rmm-tool-abuse)
   - [Step 28 — Telegram Bot API C2](#step-28-det_mw_0008a--telegram-bot-api-c2)
   - [Step 29 — DNS Tunneling](#step-29-det_mw_0008b--dns-tunneling)
   - [Step 30 — WMI SecurityCenter2 Discovery](#step-30-det_mw_0009--wmi-securitycenter2-discovery)
   - [Step 31 — LSASS Memory Access](#step-31-det_mw_0010--lsass-memory-access)
8. [Validation Results Summary](#phase-5-validation-results-summary)
9. [Phase 6: Coverage Matrix](#phase-6-coverage-matrix)
10. [What Defenders Should Do Right Now](#what-defenders-should-do-right-now)
11. [Reproduce It Yourself](#reproduce-it-yourself)
12. [Next Steps](#next-steps)

---

Most threat actor writeups stop too early. They describe the group, list ATT&CK techniques, and paste some IoCs. Then the report sits in a folder while defenders wonder: *what do I actually do with this on Monday?*

Operation Desert Hydra is an answer to that question.

This article documents a full CTI-to-detection pipeline focused on **MuddyWater** — an Iranian state-linked actor (MOIS) that has been targeting Israeli government, defense, and critical infrastructure organizations since at least 2019. By the end, you'll have 11 detection records, 12 Kibana proof screenshots, and a working lab you can deploy with a single command.

Everything is on GitHub: [github.com/anpa1200/operation-desert-hydra](https://github.com/anpa1200/operation-desert-hydra)

---

## Why MuddyWater?

Three reasons:

1. **Rich public reporting.** CISA, Israel's INCD, ClearSky, Deep Instinct, Mandiant, and Proofpoint have all published detailed technical analysis. This gives enough procedure-level specificity to engineer real detections.

2. **Consistent playbook.** Across five years of reporting, the same pattern recurs: spearphishing → scripting engine → encoded PowerShell → RMM tool. The consistency makes it detectable.

3. **Relevant geography.** The actor consistently targets Israeli organizations — a geography with high analytical value and underserved public detection coverage.

---

## The Pipeline

The project enforces a chain from source to Kibana screenshot:

```
source → claim → procedure → ATT&CK mapping → telemetry requirement
  → detection pseudologic → benign simulation → lab result → coverage score
```

No step is skipped. Every claim has a source. Every detection has a validation case. Every PASS has a screenshot.

---

## Phase 1: Source Gathering

The first step is source discovery, not detection writing.

I used an AI deep-research workflow to generate a candidate source list, then reviewed and promoted each source manually. The quality bar: accessible, specific to MuddyWater, with procedure-level or TTPs-level content.

**Promoted sources (highest weight):**

| Source | What it contributes |
|--------|---------------------|
| CISA AA22-055A (Feb 2022) | Full procedure survey: PowGoop, POWERSTATS, Small Sieve, Mori, Canopy, Marlin; WMI survey script; credential dumping tools |
| INCD 2023 | Israeli campaign specifics: ScreenConnect/SimpleHelp RMM abuse, Egnyte/OneDrive lures, Log4j + Exchange exploitation |
| INCD 2024 | BugSleep analysis: 43-minute scheduled task beacon, VPN exploitation, new RMM tools (Level, PDQConnect) |

Supporting vendor sources: ClearSky, Deep Instinct, Group-IB, Mandiant, Proofpoint, Sekoia.io, Symantec.

**Critical discipline:** AI output was used only for source discovery. Every claim, mapping, and detection record required analyst review before entering the dataset.

---

## Phase 2: Procedure Dataset

From the reviewed sources, I extracted 10 procedure records. Each record captures:

- What the actor specifically did (not what the ATT&CK technique says they could do)
- Which source(s) corroborate it
- A confidence label: *observed / reported / assessed / inferred*
- The candidate ATT&CK mapping with reasoning

| Procedure | Behavior | Confidence |
|-----------|----------|-----------|
| proc_mw_0001 | Email + file-sharing link → wscript/PS spawn | Observed (3 sources) |
| proc_mw_0002 | Web service exploitation → shell spawn | Reported (CISA, INCD) |
| proc_mw_0003 | PowerShell -EncodedCommand / IEX + web request | Observed |
| proc_mw_0004 | GoogleUpdate.exe loading Goopdate.dll from non-Google path | Reported (CISA) |
| proc_mw_0005 | Run key write (OutlookMicrosift) or WSF in Startup | Observed |
| proc_mw_0006 | Scheduled task — 43-minute repeat interval | Observed (INCD 2024) |
| proc_mw_0007 | RMM binary from AppData/Temp/Downloads | Observed (5 sources) |
| proc_mw_0008 | Telegram Bot API C2 / DNS tunneling | Reported (CISA) |
| proc_mw_0009 | WMI query SecurityCenter2\AntiVirusProduct | Observed (CISA script) |
| proc_mw_0010 | LSASS dump via Mimikatz / procdump64; LSA via LaZagne | Observed (CISA) |

---

## Phase 3: OpenCTI Knowledge Graph

The procedure dataset and source register go into a self-hosted OpenCTI 6.2 instance. This creates the analytical record — queryable, relationship-aware, ATT&CK-linked.

### Step 10: Stack Start

```bash
bash start.sh --skip-lab   # starts OpenCTI + Elasticsearch + Kibana only
```

All 12 core containers start: Redis, Elasticsearch, MinIO, RabbitMQ, OpenCTI platform, 3 workers, and the MITRE ATT&CK connector.

![Step 10 — OpenCTI stack running](proofs/phase-3/step-10-stack-start.png)

**Result:** OpenCTI reachable at `http://localhost:8080`. All containers healthy.

### Step 11: MITRE ATT&CK Connector Sync

The MITRE ATT&CK connector loads 846 techniques into the graph. This sync must complete before the import script can link procedures to techniques.

![Step 11 — MITRE connector sync status](proofs/phase-3/step-11-mitre-connector-status.png)

**Result:** 846 ATT&CK patterns loaded. Connector state: ACTIVE.

### Step 12: Import Script

```bash
export OPENCTI_TOKEN=<admin token from stack/.env>
python3 tools/opencti_import.py
```

Creates: 1 Intrusion Set (MuddyWater + all aliases), 9 malware objects, 4 tool objects, 20 reports, 21 ATT&CK technique links.

![Step 12 — Import script output](proofs/phase-3/step-12-import-output-1.png)

![Step 12 — Import object detail](proofs/phase-3/step-12-import-output-2.png)

**Result:** All objects created. Re-run confirms idempotency (no duplicates).

### Step 13: Intrusion Set Verification

![Step 13 — MuddyWater intrusion set](proofs/phase-3/step-13-muddywater-intrusion-set.png)

**Result:** MuddyWater entity with all aliases, Iran MOIS attribution relationship, campaign links, and malware/tool associations confirmed in OpenCTI.

### Step 14: Knowledge Graph

![Step 14 — MuddyWater knowledge graph](proofs/phase-3/step-14-knowledge-graph.png)

**Result:** Graph shows MuddyWater → 9 malware, 4 tools, 3 campaigns, 21 ATT&CK techniques — all with source-annotated relationship edges.

### Step 15: ATT&CK Matrix Coverage

![Step 15 — ATT&CK technique coverage](proofs/phase-3/step-15-attck-matrix.png)

**Result:** 21 techniques highlighted across 8 tactics in the ATT&CK Enterprise matrix.

### Step 16: BugSleep Malware Detail

![Step 16 — BugSleep malware object](proofs/phase-3/step-16-bugsleep-malware-detail.png)

**Result:** BugSleep malware object with INCD 2024 source annotation, T1053.005 relationship (43-minute task), and C2 technique links confirmed.

### Step 17: Reports List

![Step 17 — Report objects](proofs/phase-3/step-17-reports-list.png)

**Result:** 20 report objects, one per promoted source. Each report links to the procedures and techniques it evidences.

### Step 19: OpenCTI Dashboard

![Step 19 — Custom dashboard](proofs/phase-3/step-19-dashboard.png)

**Result:** Custom dashboard showing technique frequency heatmap by source tier — highest-corroborated techniques visible at a glance.

---

## Phase 4: Detection Atlas

The detection atlas translates the procedure dataset into detection pseudologic. Each record contains:

- The specific MuddyWater behavior it targets
- Required log sources and capability gates
- Multi-rule pseudologic (SIEM-agnostic)
- False positive classes
- A `creation_logic` field explaining *why* the rule is designed this way

The analyst review pass (Step 20) fixed operator precedence bugs, tightened the LSASS access mask set, improved T1033 coverage in det_mw_0009 Rule C, and added the Google path allowlist to det_mw_0004.

![Step 20 — Detection review (det_mw_0001)](proofs/phase-3/step-20-det-mw-0001.png)

![Step 20 — Detection review (det_mw_0010)](proofs/phase-3/step-20-det-mw-0010.png)

---

## Phase 5: Validation Lab

### Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        HOST MACHINE (Linux)                              │
│                                                                          │
│  Docker: opencti_network                                                 │
│    Elasticsearch :9200 (exposed) ←── Kibana :5601                       │
│    OpenCTI :8080                                                         │
│                           ↑                                              │
│          Winlogbeat 8.13  │  10.0.2.2:9200 (VirtualBox NAT gateway)     │
│                           │                                              │
│    VirtualBox VM: ws01 (Windows 10 / DESERTWS01)                        │
│      Sysmon 15.x — EID 1, 7, 10, 11, 13, 22                            │
│      PowerShell Script Block Logging — EID 4104                         │
│      Windows Security Auditing — EID 4688, 4698                         │
│      Ansible control: WinRM 127.0.0.1:55985 (NAT port-forward)         │
└─────────────────────────────────────────────────────────────────────────┘
```

### Deploy in One Command

```bash
git clone https://github.com/anpa1200/operation-desert-hydra.git
cd operation-desert-hydra
cp stack/.env.template stack/.env   # fill in passwords
bash start.sh
```

`start.sh` creates the Docker network, starts all stack services, waits for Elasticsearch, boots the Windows 10 Vagrant VM, provisions it via Ansible (Sysmon + Script Block Logging + Winlogbeat), and runs all 11 simulations.

### Simulation Design

Every simulation is **benign-by-design**:
- No live malware, no real C2, no credential exfiltration
- Simulations write benign files (VBScript with `Write-Host` payload), run real Windows binaries with harmless arguments, or use .NET to open process handles with minimal access masks
- All `.dmp` files are deleted immediately after event confirmation
- The VM does not connect to real Telegram infrastructure

The Ansible playbook (`lab/ansible/playbooks/validate.yml`) runs each simulation, waits 3 seconds, queries the Windows Event Log with `Get-WinEvent -FilterHashtable` (time-bounded to the last 60 seconds), and prints PASS / FAIL.

---

### Step 21: det_mw_0001 — Spearphishing Delivery Chain

**What MuddyWater does:** Delivers a ZIP or Office file via email or Egnyte/OneDrive link. The attachment contains a VBScript or WSF file that spawns a hidden encoded PowerShell loader (PowGoop/POWERSTATS).

**Simulation:** `wscript.exe sim_delivery.vbs` → `powershell.exe -WindowStyle Hidden -NonInteractive -EncodedCommand <Base64>`

**KQL proof query:**
```
winlog.event_id: 1
AND winlog.event_data.ParentImage: *wscript.exe*
AND winlog.event_data.Image: *powershell.exe*
AND winlog.event_data.CommandLine: *EncodedCommand*
```

![Step 21 — det_mw_0001 proof](proofs/phase-5/step-21-det-mw-0001.png)

**Result: PASS** — Sysmon EID 1 captured `wscript.exe → powershell.exe -EncodedCommand`. Parent-child chain and Base64 command line both visible in Kibana.

---

### Step 22: det_mw_0002 — Web Service Shell Spawn

**What MuddyWater does:** Exploits Exchange (CVE-2020-0688), IIS, or Log4j (CVE-2021-44228) — web-facing service spawns `cmd.exe` or `powershell.exe` for post-exploitation recon.

**Simulation:** `wscript.exe sim_exploit.vbs` → `cmd.exe /c whoami & hostname & ipconfig /all`

**KQL proof query:**
```
winlog.event_id: 1
AND winlog.event_data.ParentImage: *wscript.exe*
AND winlog.event_data.Image: *cmd.exe*
AND winlog.event_data.CommandLine: (*whoami* OR *hostname* OR *ipconfig*)
```

![Step 22 — det_mw_0002 proof](proofs/phase-5/step-22-det-mw-0002.png)

**Result: PASS** — Sysmon EID 1 captured `wscript.exe → cmd.exe` with recon commands in CommandLine.

---

### Step 23: det_mw_0003 — PowerShell Encoded Command

**What MuddyWater does:** PowGoop uses `-EncodedCommand` for C2 setup. POWERSTATS uses `IEX + (New-Object Net.WebClient).DownloadString(...)` for stager execution.

**Rule A simulation:** `powershell.exe -NonInteractive -e <Base64(Write-Host "test")>`

**KQL — Rule A:**
```
winlog.event_id: 1
AND winlog.event_data.CommandLine: *-e*
AND winlog.event_data.CommandLine: *[A-Za-z0-9+/]{40,}*
```

![Step 23a — det_mw_0003 Rule A proof](proofs/phase-5/step-23a-det-mw-0003-rule-a.png)

**Rule A Result: PASS** — 4 events captured. PowerShell with Base64 blob visible in command line.

**Rule B simulation:** `IEX ((New-Object Net.WebClient).DownloadString('http://127.0.0.1:19999/...'))`

**KQL — Rule B:**
```
winlog.event_id: 4104
AND winlog.event_data.ScriptBlockText: *IEX*
AND winlog.event_data.ScriptBlockText: *DownloadString*
```

![Step 23b — det_mw_0003 Rule B proof](proofs/phase-5/step-23b-det-mw-0003-rule-b.png)

**Rule B Result: PASS** — 16 EID 4104 events. Script Block Logging decoded the IEX + DownloadString pattern.

> **Capability gate:** Script Block Logging (EID 4104) must be explicitly enabled. Without it, Rule B is unavailable and detection degrades to command-line heuristics only.

---

### Step 24: det_mw_0004 — DLL Side-Loading

**What MuddyWater does:** PowGoop drops `Goopdate.dll` alongside a copy of `GoogleUpdate.exe` outside the legitimate Google installation path. When GoogleUpdate launches, Windows loads the malicious DLL.

**Simulation:** Copy a benign 4-byte MZ stub as `goopdate.dll` into a test directory alongside a signed binary. Launch the binary.

**Result: PARTIAL** — Sysmon EID 7 (ImageLoad) did not fire. Root cause: a 4-byte MZ stub is not a valid loadable DLL — the Windows loader rejects it before generating an EID 7 event. The Sysmon config and detection rule are correct. **Resolution:** Re-test with a real `GoogleUpdate.exe` (requires Google Chrome installed on lab VM).

---

### Step 25: det_mw_0005 — Registry Run Key Persistence

**What MuddyWater does:** Small Sieve writes `OutlookMicrosift` to `HKCU\...\CurrentVersion\Run` — a deliberate typo designed to look like a Microsoft entry. Canopy drops a `.wsf` file to the Startup folder.

**Rule A simulation:** Write `OutlookMicrosift` = `notepad.exe` to `HKCU\...\Run`

**KQL — Rule A:**
```
winlog.event_id: 13
AND winlog.event_data.TargetObject: *CurrentVersion\Run\OutlookMicrosift*
```

![Step 25a — det_mw_0005 Rule A proof](proofs/phase-5/step-25a-det-mw-0005-rule-a.png)

**Rule A Result: PASS** — 3 Sysmon EID 13 events. `OutlookMicrosift` Run key captured.

**Rule C simulation:** Copy a benign `.wsf` file to `%APPDATA%\...\Start Menu\Programs\Startup\`

**KQL — Rule C:**
```
winlog.event_id: 11
AND winlog.event_data.TargetFilename: *\Startup\*
AND winlog.event_data.TargetFilename: *.wsf*
```

![Step 25c — det_mw_0005 Rule C proof](proofs/phase-5/step-25c-det-mw-0005-rule-c.png)

**Rule C Result: PASS** — 3 Sysmon EID 11 events. WSF file creation in Startup folder captured.

---

### Step 26: det_mw_0006 — Scheduled Task (43-Minute Beacon)

**What MuddyWater does:** BugSleep creates a scheduled task triggered every **43 minutes**. This interval is a BugSleep artifact — not a default, not a round number. It appears in INCD 2024 reporting and is one of the most precise technical IoCs in the dataset.

**Simulation:** `schtasks.exe /create /tn DH-SIM-0006-TestTask /tr notepad.exe /sc MINUTE /mo 43 /f`

**KQL:**
```
winlog.event_id: 1
AND winlog.event_data.Image: *\schtasks.exe*
AND winlog.event_data.CommandLine: */mo 43*
```

![Step 26 — det_mw_0006 proof](proofs/phase-5/step-26-det-mw-0006.png)

**Result: PASS** — 3 Sysmon EID 1 events. `schtasks.exe /mo 43` captured. The 43-minute interval in the command line is the exact BugSleep artifact.

> **Hunt value:** `PT43M` in Task Scheduler Operational logs is a retroactive hunt trigger. One match = investigate immediately. No legitimate software uses this exact interval.

---

### Step 27: det_mw_0007 — RMM Tool Abuse

**What MuddyWater does:** Delivers a legitimate RMM binary (ScreenConnect, SimpleHelp, AteraAgent, Level, PDQConnect) via phishing email or file-sharing link. The binary is placed in `AppData`, `Temp`, or `Downloads` — not installed by an IT management system. This is documented in all five government source tiers.

**Simulation:** Copy `ScreenConnect.ClientService.exe` to `C:\Temp\dh-lab\` and launch it.

**KQL:**
```
winlog.event_id: 1
AND winlog.event_data.Image: *\Temp\ScreenConnect*
```

![Step 27 — det_mw_0007 proof](proofs/phase-5/step-27-det-mw-0007.png)

**Result: PASS** — 6 Sysmon EID 1 events. RMM binary executing from `\Temp\` captured.

> **Production requirement:** This detection requires a baseline of authorized RMM deployments per endpoint. Without the baseline, it generates noise. With it, any out-of-baseline RMM execution is an immediate high-confidence alert.

---

### Step 28: det_mw_0008a — Telegram Bot API C2

**What MuddyWater does:** Small Sieve uses the Telegram Bot API (`api.telegram.org:443`) for C2 over HTTPS. In an enterprise environment where Telegram is not standard software, any non-browser process connecting to this domain is anomalous.

**Simulation:** `powershell.exe` makes an HTTP request to `https://api.telegram.org/botTEST/getMe` (invalid token — 401 response; the connection attempt is the evidence).

**Result: FAIL** — Sysmon EID 3 (NetworkConnect) did not fire. Root cause: VirtualBox NAT prevents Sysmon from capturing the outbound network connection to `api.telegram.org` in the lab environment. The Sysmon rule config is correct. **Resolution:** Re-test with a host-only NIC that provides direct internet access.

---

### Step 29: det_mw_0008b — DNS Tunneling

**What MuddyWater does:** Mori uses DNS tunneling for C2. High-volume queries with long, high-entropy subdomain labels are the telemetry signature.

**Simulation:** 60 `Resolve-DnsName` queries with 42-character random labels against `*.test.internal`.

**KQL:**
```
winlog.event_id: 22
AND winlog.event_data.QueryName: *.test.internal*
```

![Step 29 — det_mw_0008b proof](proofs/phase-5/step-29-det-mw-0008b.png)

**Result: PASS** — 180 Sysmon EID 22 events captured. 42-character random labels visible in QueryName field. Volume threshold (Rule A) and label-length threshold (Rule B) would both trigger in a production deployment.

---

### Step 30: det_mw_0009 — WMI SecurityCenter2 Discovery

**What MuddyWater does:** CISA AA22-055A documents a post-access survey script that queries `root\SecurityCenter2\AntiVirusProduct` via WMI — enumerating the installed AV product before deciding how to proceed. This is also combined with OS info, network config, and user queries in a single script.

**Simulation (Rule A):** `Get-WmiObject -Namespace root/SecurityCenter2 -Class AntiVirusProduct`

**KQL — Rule A:**
```
winlog.event_id: 4104
AND winlog.event_data.ScriptBlockText: *SecurityCenter2*
```

![Step 30a — det_mw_0009 Rule A proof](proofs/phase-5/step-30a-det-mw-0009-rule-a.png)

**Rule A Result: PASS** — 21 PS EID 4104 events. `SecurityCenter2` visible in decoded ScriptBlockText.

> **Detection value:** SecurityCenter2 + AntiVirusProduct is one of the highest-specificity behavioral signals in this dataset. Its legitimate caller population is tiny: only AV management consoles and a few inventory tools query this namespace. A PowerShell process making this query outside those exceptions warrants immediate investigation.

---

### Step 31: det_mw_0010 — LSASS Memory Access

**What MuddyWater does:** Uses Mimikatz, procdump64.exe, and LaZagne to dump LSASS memory and extract credentials. CISA AA22-055A names all three tools.

**Rule A simulation:** .NET `OpenProcess(PROCESS_QUERY_INFORMATION, lsass.pid)` — opens a handle to lsass.exe with a minimal access mask, triggering Sysmon EID 10.

**KQL — Rule A:**
```
winlog.event_id: 10
AND winlog.event_data.TargetImage: *lsass.exe*
AND winlog.event_data.GrantedAccess: 0x1400
```

![Step 31a — det_mw_0010 Rule A proof](proofs/phase-5/step-31a-det-mw-0010-rule-a.png)

**Rule A Result: PASS** — 3,398 Sysmon EID 10 events with `GrantedAccess: 0x1400` and `TargetImage: lsass.exe`. The high event count is expected — LSASS receives many legitimate handle requests from AV, EDR, and Windows system processes. Production deployment requires an allowlist of known-good callers.

**Rule C simulation:** Write a 4-byte MDMP header as `lsass_test.dmp` to `C:\Temp\dh-lab\` — triggers Sysmon EID 11.

**KQL — Rule C:**
```
winlog.event_id: 11
AND winlog.event_data.TargetFilename: *.dmp*
AND winlog.event_data.TargetFilename: *Temp*
```

![Step 31c — det_mw_0010 Rule C proof](proofs/phase-5/step-31c-det-mw-0010-rule-c.png)

**Rule C Result: PASS** — 6 Sysmon EID 11 events. `C:\Temp\dh-lab\lsass_test.dmp` creation captured.

> **Lab safety:** The `.dmp` file was deleted immediately after event confirmation. No credential material exists in the file — it was a 4-byte header stub. No real LSASS dump was performed.

---

## Phase 5 Validation Results Summary

Full run: `ansible-playbook playbooks/validate.yml` — **ok=70 changed=42 failed=0**

| Step | Detection | Rule | Result |
|------|-----------|------|--------|
| 21 | det_mw_0001 | Process spawn | **PASS** |
| 22 | det_mw_0002 | Shell from service | **PASS** |
| 23 | det_mw_0003 | Rule A (-e + Base64) | **PASS** |
| 23 | det_mw_0003 | Rule B (IEX + DownloadString) | **PASS** |
| 24 | det_mw_0004 | EID 7 ImageLoad | **PARTIAL** |
| 25 | det_mw_0005 | Rule A (OutlookMicrosift) | **PASS** |
| 25 | det_mw_0005 | Rule C (WSF in Startup) | **PASS** |
| 26 | det_mw_0006 | schtasks /mo 43 | **PASS** |
| 27 | det_mw_0007 | Rule A (RMM from \Temp\) | **PASS** |
| 27 | det_mw_0007 | Rule B (RMM from PS parent) | **PASS** |
| 28 | det_mw_0008a | EID 3 Telegram | **FAIL** |
| 29 | det_mw_0008b | EID 22 DNS tunneling | **PASS** |
| 30 | det_mw_0009 | Rule A (SecurityCenter2 EID 4104) | **PASS** |
| 30 | det_mw_0009 | Rule B (wmic SecurityCenter2) | **PASS** |
| 31 | det_mw_0010 | Rule A (LSASS EID 10) | **PASS** |
| 31 | det_mw_0010 | Rule C (.dmp EID 11) | **PASS** |

**13 PASS / 1 PARTIAL / 1 FAIL** across 16 rule checks.

---

## Phase 6: Coverage Matrix

Of 22 ATT&CK techniques documented in the source set:

- **15 techniques (68%)** — score 5, fully lab-validated
- **2 techniques (9%)** — score 4, correlated and validated via fallback
- **4 techniques (18%)** — score 3, rule present but validation incomplete
- **7 techniques** — score 0, no detection (Lateral Movement, Collection, Exfiltration, Impact)

**The six capability gates** that determine your effective coverage floor:

| Gate | Unlocks | Without it |
|------|---------|-----------|
| PowerShell Script Block Logging (EID 4104) | det_mw_0003 Rule B, det_mw_0009 Rules A/C | Detection degrades to command-line heuristics |
| Sysmon EID 10 (ProcessAccess) | det_mw_0010 Rule A (tool-agnostic LSASS) | Falls back to binary name only — misses custom dumpers |
| Sysmon EID 7 (ImageLoad) | det_mw_0004 (DLL side-loading) | DLL loads are invisible |
| DNS resolver logging (full QNAME) | det_mw_0008b (DNS tunneling) | Mori C2 channel invisible |
| Network flow / proxy logs | det_mw_0007 Rule C, det_mw_0008a | RMM and Telegram C2 network-layer coverage lost |
| Email gateway telemetry (SEG) | det_mw_0001 full correlated logic | Email-to-endpoint correlation unavailable |

---

## What Defenders Should Do Right Now

**1. Baseline your RMM deployments.**
det_mw_0007 is the most consistently documented MuddyWater technique across all five source tiers. It fires on ScreenConnect, SimpleHelp, AteraAgent, Level, and PDQConnect from non-standard paths. But it needs a baseline of authorized deployments first. Build the baseline; the detection logic is already written.

**2. Enable PowerShell Script Block Logging fleet-wide.**
One Group Policy change:
```
Computer Configuration → Administrative Templates → Windows Components
→ Windows PowerShell → Turn on PowerShell Script Block Logging → Enabled
```
This unlocks det_mw_0003 Rule B and all three det_mw_0009 rules. No other change required.

**3. Configure Sysmon ProcessAccess against lsass.exe.**
Without it, LSASS credential dumping detection is binary-name-only. Renamed Mimikatz and custom C++ dumpers are invisible. Add `<ProcessAccess onmatch="include">` targeting `lsass.exe` to `sysmon.xml`.

**4. Hunt for PT43M now.**
Query your Task Scheduler Operational logs for any task with a `RepetitionInterval` of `PT43M`. If you find one you didn't create, that is BugSleep. No other legitimate software uses this interval.

---

## Reproduce It Yourself

```bash
git clone https://github.com/anpa1200/operation-desert-hydra.git
cd operation-desert-hydra
cp stack/.env.template stack/.env
# fill in ELASTIC_PASSWORD, OPENCTI_ADMIN_PASSWORD, OPENCTI_ADMIN_TOKEN
bash start.sh
# → OpenCTI: http://localhost:8080
# → Kibana:  http://localhost:5601
# → All 11 simulations run automatically
```

Prerequisites: Docker, VirtualBox, Vagrant, Ansible, Python 3 + pywinrm.

Full project documentation: `docs/article-step-0-project-scenario.md`
Detection records: `data/detections.yaml`
Validation playbook: `lab/ansible/playbooks/validate.yml`

---

## What This Project Is Not

This is not a red team toolkit. The lab produces benign telemetry for detection validation — no live malware, no real C2, no credential theft. The detection pseudologic is SIEM-agnostic and requires production translation and tuning before deployment. Coverage scores are conservative: 5 requires a Kibana screenshot, not just passing logic.

The source base is entirely public. The actor's actual TTPs may be more sophisticated than what is documented. Treat the coverage matrix as a floor, not a ceiling.

---

## Next Steps

1. Close the two open gaps: det_mw_0004 (needs real GoogleUpdate.exe) and det_mw_0008a (needs direct internet NIC)
2. Translate pseudologic to Sigma rules for community sharing
3. Lateral movement source review — T1021.001 (RDP) and T1550.002 (Pass the Hash) are the most likely gaps based on actor profile
4. Extend to TA453 (Charming Kitten) — overlapping initial access techniques support a comparative detection track

---

*All code, data, and proof screenshots are version-controlled at [github.com/anpa1200/operation-desert-hydra](https://github.com/anpa1200/operation-desert-hydra)*
