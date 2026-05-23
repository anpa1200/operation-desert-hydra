---
id: phase-6-coverage-matrix
title: "Phase 6: Coverage Matrix"
sidebar_label: Coverage Matrix
---

**28 ATT&CK techniques** documented across all sources: 21 formalized into the procedure dataset, 7 from the broader source analysis without procedures written.

Of the **21 techniques in the procedure dataset:**

- **16 techniques (76%)** — score 5, fully lab-validated with Kibana proof
- **1 technique (5%)** — score 4, lab-validated, single-source (corroborate before production)
- **3 techniques (14%)** — score 3, detection written but validation incomplete or failed
- **1 technique (5%)** — score 0, in procedures but no detection written (T1534)

**Plus 7 techniques from the source set with no detection coverage** (see Zero-Coverage table below).

**Effective coverage (score ≥ 4):** 17/21 procedure techniques (81%)

## The Six Capability Gates

These capability gates determine your effective coverage floor:

| Capability Gate | Unlocks | Without It |
|----------------|---------|------------|
| **PowerShell Script Block Logging (EID 4104)** | det_mw_0003 Rule B and det_mw_0009 Rules A/C | Detection degrades to command-line heuristics only |
| **Sysmon EID 10 (ProcessAccess)** | det_mw_0010 Rule A (tool-agnostic LSASS access) | Falls back to binary name matching, misses custom dumpers |
| **Sysmon EID 7 (ImageLoad)** | det_mw_0004 (DLL side-loading) | DLL loads are completely invisible |
| **DNS resolver logging (full QNAME)** | det_mw_0008b (DNS tunneling) | Mori C2 channel is invisible |
| **Network flow / proxy logs** | det_mw_0007 Rule C and det_mw_0008a | RMM and Telegram C2 network-layer coverage lost |
| **Email gateway telemetry (SEG)** | det_mw_0001 full correlated logic | Email-to-endpoint correlation unavailable |

## ATT&CK Coverage by Tactic

| Tactic | Technique | Score | Detection |
|--------|-----------|-------|-----------|
| Initial Access | T1566.001 Spearphishing Attachment | 5 | det_mw_0001 |
| Initial Access | T1566.002 Spearphishing Link | 5 | det_mw_0001 |
| Initial Access | T1190 Exploit Public-Facing Application | 5 | det_mw_0002 |
| Execution | T1059.001 PowerShell | 5 | det_mw_0003 |
| Execution | T1027 Obfuscated Files or Information | 5 | det_mw_0003 |
| Execution | T1047 Windows Management Instrumentation | 5 | det_mw_0009 |
| Persistence | T1574.002 DLL Side-Loading | 3 | det_mw_0004 |
| Persistence | T1547.001 Registry Run Keys / Startup Folder | 5 | det_mw_0005 |
| Persistence | T1053.005 Scheduled Task | 4 | det_mw_0006 |
| Defense Evasion | T1102 Web Service | 3 | det_mw_0008a |
| Discovery | T1082 System Information Discovery | 5 | det_mw_0009 |
| Discovery | T1016 System Network Configuration Discovery | 5 | det_mw_0009 |
| Discovery | T1033 System Owner/User Discovery | 5 | det_mw_0009 |
| Discovery | T1518.001 Security Software Discovery | 5 | det_mw_0009 |
| Command & Control | T1219 Remote Access Software | 5 | det_mw_0007 |
| Command & Control | T1071.001 Web Protocols | 3 | det_mw_0008a |
| Command & Control | T1572 Protocol Tunneling | 5 | det_mw_0008b |
| Credential Access | T1003.001 LSASS Memory | 5 | det_mw_0010 |
| Credential Access | T1003.004 LSA Secrets | 5 | det_mw_0010 |
| Credential Access | T1003.005 Cached Domain Credentials | 5 | det_mw_0010 |

## Zero-Coverage Techniques

Eight ATT&CK techniques have zero detection coverage. These are acknowledged in the coverage matrix, not hidden.

| Tactic | Technique | Source | Note |
|--------|-----------|--------|------|
| Initial Access | T1534 Internal Spearphishing | proc_mw_0001 | In procedure dataset; requires compromised-account telemetry beyond project scope |
| Lateral Movement | T1021.001 Remote Desktop Protocol | Source set | Not formalized into a procedure |
| Lateral Movement | T1550.002 Pass the Hash | Source set | Post-exploitation, source set only |
| Collection | T1005 Data from Local System | Source set | Not formalized into a procedure |
| Collection | T1039 Data from Network Shared Drive | Source set | Not formalized into a procedure |
| Exfiltration | T1041 Exfiltration Over C2 Channel | Source set | Not formalized into a procedure |
| Impact | T1486 Data Encrypted for Impact (DarkBit) | INCD 2023 | DarkBit operation; outside MuddyWater core playbook scope |
| Impact | T1490 Inhibit System Recovery (shadow copy deletion) | INCD 2023 | DarkBit operation; outside MuddyWater core playbook scope |

The actor uses these techniques. The public source base documents them. The detection coverage does not exist in this iteration. The coverage matrix is a floor, not a ceiling.
