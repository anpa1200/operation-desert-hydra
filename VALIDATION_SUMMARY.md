# Validation Summary — Operation Desert Hydra

## Overall Results

**14 PASS / 1 PARTIAL / 1 FAIL** across 16 rule checks (Phase 5)

Ansible run: `ok=70 changed=42 failed=0`

---

## Results by Detection

| Step | Detection | Rule | Result | Kibana Proof |
|------|-----------|------|--------|-------------|
| 21 | det_mw_0001 | Process spawn (EID 1) | PASS | step-21-det-mw-0001.png |
| 22 | det_mw_0002 | Shell from service (EID 1) | PASS | step-22-det-mw-0002.png |
| 23 | det_mw_0003 | Rule A (-e + Base64) | PASS | step-23a-det-mw-0003-rule-a.png |
| 23 | det_mw_0003 | Rule B (IEX + DownloadString) | PASS | step-23b-det-mw-0003-rule-b.png |
| 24 | det_mw_0004 | EID 7 ImageLoad | PARTIAL | *(environmental constraint — see below)* |
| 25 | det_mw_0005 | Rule A (OutlookMicrosift Run key) | PASS | step-25a-det-mw-0005-rule-a.png |
| 25 | det_mw_0005 | Rule C (WSF in Startup folder) | PASS | step-25c-det-mw-0005-rule-c.png |
| 26 | det_mw_0006 | schtasks /mo 43 (EID 1) | PASS | step-26-det-mw-0006.png |
| 27 | det_mw_0007 | Rule A (RMM from \Temp\) | PASS | step-27-det-mw-0007.png |
| 27 | det_mw_0007 | Rule B (RMM from PS parent) | PASS | step-27-det-mw-0007.png |
| 28 | det_mw_0008a | EID 3 Telegram | FAIL | *(lab architecture constraint — see below)* |
| 29 | det_mw_0008b | EID 22 DNS tunneling | PASS | step-29-det-mw-0008b.png |
| 30 | det_mw_0009 | Rule A (SecurityCenter2 EID 4104) | PASS | step-30a-det-mw-0009-rule-a.png |
| 30 | det_mw_0009 | Rule B (wmic SecurityCenter2) | PASS | *(same step, same screenshot)* |
| 31 | det_mw_0010 | Rule A (LSASS EID 10) | PASS | step-31a-det-mw-0010-rule-a.png |
| 31 | det_mw_0010 | Rule C (.dmp EID 11) | PASS | step-31c-det-mw-0010-rule-c.png |

---

## PARTIAL — det_mw_0004 (DLL Side-Loading)

**Root cause:** A 4-byte MZ stub is not a valid loadable DLL. The Windows loader rejects it before generating a Sysmon EID 7 event. The detection rule and Sysmon configuration are correct.

**Fix path:** Use a real compiled DLL (e.g., install Google Chrome to provide `Goopdate.dll`) or compile a minimal valid DLL with the correct export table. Coverage score: 3.

---

## FAIL — det_mw_0008a (Telegram Bot API C2)

**Root cause:** VirtualBox NAT translates all outbound connections. Sysmon EID 3 captures a connection to `10.0.2.2:443` (the NAT gateway), not `api.telegram.org:443`. The detection rule and Sysmon configuration are correct.

**Fix path:** Configure the VM with a host-only or bridged NIC that has direct internet access, or use a network proxy that preserves the original destination hostname in the EID 3 event. Coverage score: 3.

---

## Coverage by ATT&CK Technique

| Technique | Detection | Score | Validation |
|-----------|-----------|:-----:|-----------|
| T1566.001 Spearphishing Attachment | det_mw_0001 | 5 | PASS |
| T1566.002 Spearphishing Link | det_mw_0001 | 5 | PASS |
| T1190 Exploit Public-Facing Application | det_mw_0002 | 5 | PASS |
| T1059.001 PowerShell | det_mw_0003 | 5 | PASS |
| T1027 Obfuscated Files or Information | det_mw_0003 | 5 | PASS |
| T1047 WMI | det_mw_0009 | 5 | PASS |
| T1574.002 DLL Side-Loading | det_mw_0004 | 3 | PARTIAL |
| T1547.001 Registry Run Keys | det_mw_0005 | 5 | PASS |
| T1053.005 Scheduled Task | det_mw_0006 | 4 | PASS |
| T1102 Web Service | det_mw_0008a | 3 | FAIL |
| T1082 System Information Discovery | det_mw_0009 | 5 | PASS |
| T1016 System Network Configuration Discovery | det_mw_0009 | 5 | PASS |
| T1033 System Owner/User Discovery | det_mw_0009 | 5 | PASS |
| T1518.001 Security Software Discovery | det_mw_0009 | 5 | PASS |
| T1219 Remote Access Software | det_mw_0007 | 5 | PASS |
| T1071.001 Web Protocols | det_mw_0008a | 3 | FAIL |
| T1572 Protocol Tunneling | det_mw_0008b | 5 | PASS |
| T1003.001 LSASS Memory | det_mw_0010 | 5 | PASS |
| T1003.004 LSA Secrets | det_mw_0010 | 5 | PASS |
| T1003.005 Cached Domain Credentials | det_mw_0010 | 5 | PASS |
| T1534 Internal Spearphishing | *(none)* | 0 | Not validated |

---

## Coverage Score Scale

- **5** = lab-validated with Kibana screenshot, multi-source corroboration
- **4** = lab-validated, single-source only (corroborate before production)
- **3** = detection written, validation incomplete or failed (documented reason)
- **0** = no detection written for this procedure
