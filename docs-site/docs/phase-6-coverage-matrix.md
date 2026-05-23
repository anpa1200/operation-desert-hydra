---
id: phase-6-coverage-matrix
title: "Phase 6: Coverage Matrix"
sidebar_label: Coverage Matrix
---

Of 22 ATT&CK techniques documented in the source set:

- **15 techniques (68%)** — score 5, fully lab-validated
- **2 techniques (9%)** — score 4, correlated and validated via fallback
- **4 techniques (18%)** — score 3, rule present but validation incomplete
- **7 techniques** — score 0, no detection (Lateral Movement, Collection, Exfiltration, Impact)

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

Seven ATT&CK techniques have zero detection coverage. These are acknowledged in the coverage matrix, not hidden.

| Tactic | Technique | Source |
|--------|-----------|--------|
| Lateral Movement | T1021.001 Remote Desktop Protocol | Documented in sources |
| Lateral Movement | T1550.002 Pass the Hash | Post-exploitation technique |
| Collection | T1005 Data from Local System | Documented in sources |
| Collection | T1039 Data from Network Shared Drive | Documented in sources |
| Exfiltration | T1041 Exfiltration Over C2 Channel | Documented in sources |
| Impact | T1486 Data Encrypted for Impact (DarkBit) | INCD 2023 |
| Impact | T1490 Inhibit System Recovery (shadow copy deletion) | INCD 2023 |

The actor uses these techniques. The public source base documents them. The detection coverage does not exist in this iteration. The coverage matrix is a floor, not a ceiling.
