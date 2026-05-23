---
id: limitations
title: Limitations
sidebar_label: Limitations
---

This page documents the known limitations of the detection engineering pipeline, lab validation, and coverage claims. Limitations are documented, not hidden.

---

## Lab Validation Scope

Lab simulations validate that the detection stack captures the right telemetry events for each simulated behavior. They do **not** prove:

- That detection rules are evasion-proof against real attacker tooling
- That the behavior observed matches what the actor does in live operations
- That the benign simulation payloads are equivalent to actor-specific malware
- That rules will not generate false positives in your specific environment

Real attacker tools include obfuscation, timing variation, LOLBin chaining, and environment-specific behavior not replicated in these simulations.

---

## Known Validation Failures

### det_mw_0004 — DLL Side-Loading (PARTIAL)

**Root cause:** The lab simulates DLL side-loading using a 4-byte MZ stub. The Windows loader rejects this before generating a Sysmon EID 7 event. The detection rule and Sysmon configuration are correct.

**Fix path:** Use a real compiled DLL (e.g., install Google Chrome to provide a genuine `Goopdate.dll`) or compile a minimal valid DLL with the correct export table. Coverage score: 3.

### det_mw_0008a — Telegram Bot API C2 (FAIL)

**Root cause:** VirtualBox NAT translates outbound connections. Sysmon EID 3 captures a connection to `10.0.2.2:443` (the NAT gateway), not `api.telegram.org:443`. The detection rule is correct.

**Fix path:** Configure the VM with a host-only or bridged NIC with direct internet access, or use a network proxy that preserves the destination hostname. Coverage score: 3.

---

## Source Limitations

- All 8 promoted sources are public — no classified, restricted, or paid-subscription sources were used.
- Government advisories (CISA AA22-055A, INCD 2023, INCD 2024) describe actor behavior at a campaign level; individual technique claims reflect analyst interpretation of published language.
- Evidence labels (Observed / Reported / Assessed) reflect the analyst's reading of source language, not independent verification.

---

## ATT&CK Mapping Limitations

All ATT&CK technique mappings are analyst candidates. They reflect the most likely mapping given the available evidence — not confirmed actor behavior:

- Technique mappings reflect public source claims filtered through analyst judgment
- Mappings do not constitute attribution evidence — shared technique use does not identify an actor
- Multiple techniques may describe the same behavior at different abstraction levels

---

## Coverage Gap Acknowledgment

- **8 ATT&CK techniques** have zero detection coverage (see [Coverage Matrix](./phase-6-coverage-matrix))
- 3 detections have coverage score 3 (validation incomplete or failed — documented reason in each)
- 1 procedure technique (T1534 Internal Spearphishing) has no detection written — requires compromised-account telemetry outside the lab scope
- The coverage matrix is a floor, not a ceiling

---

## Capability Gates

Detection coverage depends on telemetry that may not exist in every environment:

| Gate | Without It |
|------|-----------|
| PowerShell Script Block Logging (EID 4104) | det_mw_0003 Rule B and det_mw_0009 Rules A/C degrade to command-line heuristics |
| Sysmon EID 10 (ProcessAccess) | det_mw_0010 Rule A falls back to binary name matching; custom dumpers invisible |
| Sysmon EID 7 (ImageLoad) | det_mw_0004 (DLL side-loading) invisible |
| DNS resolver logging (full QNAME) | det_mw_0008b (DNS tunneling) invisible |
| Network flow / proxy logs | det_mw_0007 Rule C and det_mw_0008a network coverage lost |
| Email gateway telemetry (SEG) | det_mw_0001 correlated logic unavailable |

---

## What This Project Is Not

- Not a threat attribution report — it does not claim to independently verify actor identity
- Not an incident response playbook — simulations use benign payloads, not real actor tools
- Not a red-team exercise — the lab validates detection telemetry capture, not attacker tradecraft
- Not a production-ready detection rule set — rules require baseline tuning before deployment
