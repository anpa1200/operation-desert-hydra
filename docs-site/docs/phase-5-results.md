---
id: phase-5-results
title: "Phase 5: Validation Results Summary"
sidebar_label: Validation Results
---

![Phase 5: Validation Results Summary — 14 PASS / 1 PARTIAL / 1 FAIL across 16 rule checks](/img/validation-results-infographic.png)

Full run: `ansible-playbook playbooks/validate.yml` — **ok=70 changed=42 failed=0**

| Step | Detection | Rule | Result |
|------|-----------|------|--------|
| 21 | **det_mw_0001** | Process spawn | **PASS** |
| 22 | **det_mw_0002** | Shell from service | **PASS** |
| 23 | **det_mw_0003** | Rule A (-e + Base64) | **PASS** |
| 23 | **det_mw_0003** | Rule B (IEX + DownloadString) | **PASS** |
| 24 | **det_mw_0004** | EID 7 ImageLoad | **PARTIAL** |
| 25 | **det_mw_0005** | Rule A (OutlookMicrosift) | **PASS** |
| 25 | **det_mw_0005** | Rule C (WSF in Startup) | **PASS** |
| 26 | **det_mw_0006** | schtasks /mo 43 | **PASS** |
| 27 | **det_mw_0007** | Rule A (RMM from \Temp\) | **PASS** |
| 27 | **det_mw_0007** | Rule B (RMM from PS parent) | **PASS** |
| 28 | **det_mw_0008a** | EID 3 Telegram | **FAIL** |
| 29 | **det_mw_0008b** | EID 22 DNS tunneling | **PASS** |
| 30 | **det_mw_0009** | Rule A (SecurityCenter2 EID 4104) | **PASS** |
| 30 | **det_mw_0009** | Rule B (wmic SecurityCenter2) | **PASS** |
| 31 | **det_mw_0010** | Rule A (LSASS EID 10) | **PASS** |
| 31 | **det_mw_0010** | Rule C (.dmp EID 11) | **PASS** |

**14 PASS / 1 PARTIAL / 1 FAIL** across 16 rule checks.

## PARTIAL — det_mw_0004 (DLL Side-Loading)

Root cause: a 4-byte MZ stub is not a valid loadable DLL — the Windows loader rejects it before generating an EID 7 event. The detection rule and Sysmon config are correct. Fix requires a real compiled DLL or Google Chrome installed on the lab VM to provide a genuine `Goopdate.dll`. Coverage score: 3.

## FAIL — det_mw_0008a (Telegram Bot API C2)

Root cause: VirtualBox NAT translates outbound connections — Sysmon captures a connection to `10.0.2.2:443`, not `api.telegram.org:443`. The detection rule is correct. Fix requires a host-only or bridged NIC with direct internet access on the VM. Coverage score: 3.
