---
id: production-scars
title: Production Scars
sidebar_label: Production Scars
---

Everything above describes what the project looks like after it worked. This section documents what broke, in what order, and what was actually fixed — the kind of detail that gets cut from writeups but is the most useful part for anyone trying to reproduce this.

---

## Scar 1: The Simulations Were Faking It

The first validation attempt used synthetic event markers. The simulation playbook injected a `DH-SIM-0001` string into the `CommandLine` field, then the Kibana queries looked for that exact string:

```
winlog.event_id: 1 AND winlog.event_data.CommandLine: *DH-SIM-0001*
```

This produces a screenshot. It does not prove a detection works.

The problem is fundamental: a query that looks for a marker you injected proves that injection works, not that a detection fires on real attacker behavior. If MuddyWater runs `wscript.exe` and spawns `powershell.exe -EncodedCommand`, the DH-SIM-0001 query returns nothing. The detection coverage number was meaningless.

**What was fixed:** All simulations were rewritten to produce realistic execution chains — `wscript.exe` spawning `powershell.exe -EncodedCommand <base64>`, `schtasks.exe /create /sc minute /mo 43`, `lsass.exe` being accessed by a test process with the correct `GrantedAccess` mask. All KQL queries were rewritten to use real field-based conditions: `winlog.event_data.ParentImage`, `winlog.event_data.GrantedAccess`, `winlog.event_data.TargetObject`, `winlog.event_data.ScriptBlockText`. Every proof screenshot now shows a real field value, not a synthetic marker.

**The lesson:** A proof screenshot is only as good as the conditions that trigger it. If the simulation writes what the query reads, you have a tautology, not a detection.

---

## Scar 2: det_mw_0004 — The DLL That Wouldn't Load

The simulation for det_mw_0004 (DLL side-loading) created a 4-byte MZ-header stub file named `Goopdate.dll` in a temp directory alongside `GoogleUpdate.exe`, then waited for Sysmon Event ID 7 (ImageLoad) to fire.

It never fired.

Root cause: a 4-byte MZ stub is not a valid PE binary. The Windows loader parses the PE header before loading — the stub fails the loader's structural validation and is rejected before the load event is generated. Sysmon only generates EID 7 for DLLs that actually get mapped into process memory. A file that fails to load produces no EID 7.

The Sysmon configuration was correct. The detection rule was correct. The simulation was wrong.

**Result: PARTIAL** — coverage score 3 instead of 5.

**What it would take to fix:** The test needs a real, valid DLL — even an empty DLL compiled from a single `DllMain` that returns `TRUE`. Alternatively, installing the actual Google Chrome on the lab VM provides a real `Goopdate.dll` at the expected path, which could then be copied to a non-standard location. Neither was done in this iteration due to lab scope constraints (no internet access on the VM for Chrome installation, no compiler toolchain in the lab).

**The lesson:** When validating EID 7 detections, your test artifact must be a valid loadable PE. A stub file saves time and produces nothing.

---

## Scar 3: det_mw_0008a — VirtualBox NAT Ate the Telegram Traffic

The simulation for det_mw_0008a (Telegram Bot API C2) made an outbound HTTPS connection to `api.telegram.org` from PowerShell and waited for Sysmon Event ID 3 (NetworkConnect) to fire.

It never fired.

Root cause: VirtualBox NAT performs network address translation at the hypervisor level. Sysmon captures network connections at the Windows kernel level. With NAT, the connection from the VM's perspective terminates at the NAT gateway (`10.0.2.2`), not at `api.telegram.org`. Sysmon sees a connection to `10.0.2.2:443`, not `api.telegram.org:443`. The detection rule looking for `api.telegram.org` as the destination found nothing.

There was an additional layer: VirtualBox NAT does not forward arbitrary outbound HTTPS traffic by default in this lab configuration — the VM had no direct internet path, only access to the host's `10.0.2.2` gateway. Even fixing the Sysmon observation problem would require a working internet path from the VM.

**Result: FAIL** — coverage score 3 instead of 5.

**What it would take to fix:** Add a host-only or bridged network adapter to the VM that provides direct internet access, and confirm Sysmon captures the connection with the external destination. Alternatively, run a local HTTPS server on the host at `api.telegram.org` via a hosts file override, which would make the destination resolvable within the lab and catchable by Sysmon.

**The lesson:** VirtualBox NAT is the right choice for lab isolation (the VM cannot reach the internet accidentally), but it is the wrong choice if you need to validate detections based on external destination hostnames. Design the network topology before writing detection validation cases.

---

## Scar 4: Kibana Showed Nothing — Wrong Time Window

After running the SecurityCenter2 WMI discovery simulation (Step 30), the Kibana query returned zero results.

The query was correct. The simulation had run correctly. The events were in Elasticsearch.

Root cause: Kibana's default time window was set to "Last 15 minutes." The simulation had run in a previous lab session, and Winlogbeat had shipped the events to Elasticsearch during that session. The events existed — they were just outside the current time window.

**What was fixed:** Changed the time filter to "Last 24 hours." Events appeared immediately.

**The lesson:** When a Kibana proof shows no results, the first diagnostic step is the time filter, not the query. This is obvious in retrospect and a consistent source of false "detection failed" conclusions during initial validation runs.

---

## Scar 5: Detection Design Bugs Found in Review (Before Validation)

Before running any simulations, every detection record went through a structured review pass. Four real bugs were found:

**det_mw_0010 Rule B — Operator precedence error.** The original pseudologic was:

```
event_type = process_create AND
image IMATCHES "mimikatz\.exe" OR
image ENDSWITH "procdump64.exe" OR
command_line IMATCHES "(sekurlsa|lsadump|privilege::debug)"
```

Without explicit parentheses, `OR` has lower precedence than `AND` in most query languages. The `command_line IMATCHES` clause was evaluated independently of the `event_type` guard, meaning the rule would fire on any event (not just process_create) where the command line contained `sekurlsa`. In a SIEM with millions of events per day, this generates noise and potentially masks the real signal. The fix added explicit brackets to keep all `OR` branches inside the `event_type = process_create` guard.

**det_mw_0009 Rule C — T1033 was not covered.** The initial Rule C matched `SecurityCenter2`, `Win32_NetworkAdapterConfiguration`, and `Win32_OperatingSystem` — covering T1518.001, T1016, and T1082. The documented CISA script also collects the username via `Win32_ComputerSystem`. T1033 (System Owner/User Discovery) was missing. Fixed by adding `Win32_ComputerSystem|Win32_UserAccount|UserName` to the pattern match.

**det_mw_0004 Rule A — Missing x86 Google path.** The initial allowlist only contained the x64 path `C:\Program Files\Google\`. On 64-bit Windows, the 32-bit Google Update installs to `C:\Program Files (x86)\Google\`. Without the x86 path in the allowlist, any `Goopdate.dll` load from the legitimate 32-bit Google installation would fire the detection. Added both paths.

**det_mw_0010 Rule A — Access mask set too narrow.** The initial mask set covered standard Mimikatz masks (0x1010, 0x1410, 0x1438) but missed `0x1fffff` (PROCESS_ALL_ACCESS, used by custom C++ dumpers and some loaders) and `0x1f0fff` (another all-access variant observed in field reporting). A detection that only catches stock Mimikatz masks is bypassed by any custom implementation. Extended the mask set to cover known custom-dumper variants.

**The lesson:** Writing pseudologic in a YAML field with no syntax validation means operator precedence bugs survive until someone reads the logic carefully. Structured peer review — ideally by someone who will try to break the rule — catches these before they hit production.

---

## Scar 6: The OpenCTI Stack Was in a Different Repository

The original project structure had the OpenCTI Docker Compose stack in a separate repository (`opencti-intelligent-shield`) that was not included in the desert-hydra repo. The `start.sh` script referenced the external repo with a hardcoded path. Cloning `operation-desert-hydra` and running `start.sh` failed immediately on any machine other than the development machine.

**What was fixed:** The entire stack — `docker-compose.yml`, `docker-compose.kibana.yml`, and `.env.template` — was copied into `stack/` inside the desert-hydra repo. All path references were updated. The repo is now fully self-contained: `git clone` + `cp .env.template .env` + `bash start.sh` works from a clean machine with no external dependencies beyond Docker, Vagrant, VirtualBox, Ansible, and pywinrm.

**The lesson:** A reproducibility claim requires everything needed to reproduce to be in the same repository. External path dependencies are invisible during development and obvious on first external clone.

---

## Scar 7: MITRE Connector Timing

The import script (`tools/opencti_import.py`) creates `MuddyWater → uses → ATT&CK technique` relationships by looking up techniques that the MITRE ATT&CK connector has synced into OpenCTI. The connector takes several minutes to complete its initial sync of 846 techniques.

If the import script runs before the connector finishes, the technique lookup returns nothing — the techniques don't exist yet. The original script failed silently on these lookups and skipped the relationship creation.

**What was fixed:** The script was updated with `find_or_create_attack_pattern()`: if a technique is not yet in OpenCTI, create a stub `AttackPattern` object with the correct `x_mitre_id`. When the MITRE connector eventually syncs that technique, OpenCTI's deduplication logic merges the stub with the connector's fully populated object. All relationships that were created against the stub are preserved and now point to the enriched object. Running the script a second time after the connector finishes confirms existing objects rather than creating duplicates.

**The lesson:** Any script that creates relationships against objects populated by a connector needs to handle the case where the connector has not finished. Fail loudly or create stubs — don't skip silently.

---

## Surviving Gaps

Two failures from Phase 5 remain open:

**det_mw_0004** — DLL side-loading detection (EID 7) is not lab-validated. The detection rule is sound; the simulation needs a valid PE DLL. Coverage score stays at 3 until the lab is extended with a compiled test DLL.

**det_mw_0008a** — Telegram Bot API connection detection (EID 3) is not lab-validated. The detection rule is sound; the lab network topology prevents capturing external destination hostnames via NAT. Coverage score stays at 3 until the VM has a direct internet path or a local HTTPS proxy target.

These are documented as open items, not dismissed as "out of scope." The coverage score scale is designed to reflect this: a score of 3 means "behavioral detection, no lab proof" — it is honest about the gap rather than claiming coverage that was not validated.

**Seven ATT&CK techniques have zero detection coverage.** Lateral movement (T1021.001 RDP, T1550.002 Pass the Hash), Collection (T1005, T1039), Exfiltration (T1041), and Impact (T1486 ransomware, T1490 shadow copy deletion from DarkBit). These are acknowledged in the coverage matrix, not hidden. The actor uses them. The public source base documents them. The detection coverage does not exist in this iteration.

*All code, data, and proof screenshots are version-controlled at [github.com/anpa1200/operation-desert-hydra](https://github.com/anpa1200/operation-desert-hydra)*
