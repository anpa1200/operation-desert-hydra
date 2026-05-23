---
id: intro
title: Why MuddyWater?
sidebar_label: Introduction
---

Most threat actor writeups stop too early. They describe the group, list ATT&CK techniques, and paste some IoCs. Then the report sits in a folder while defenders wonder: *what do I actually do with this on Monday?*

Operation Desert Hydra is an answer to that question.

This documentation covers a full CTI-to-detection pipeline focused on **MuddyWater / Seedworm** — widely reported by government and vendor sources as Iran-linked activity associated with MOIS, targeting Israeli government, defense, and critical infrastructure organizations since at least 2019. By the end, you'll have 11 detection records, 12 Kibana proof screenshots, and a working lab you can deploy with a single command.

Everything is on GitHub: [github.com/anpa1200/operation-desert-hydra](https://github.com/anpa1200/operation-desert-hydra)

---

## Why MuddyWater?

Three reasons:

1. **Rich public reporting.** CISA, Israel's INCD, ClearSky, Deep Instinct, Mandiant, and Proofpoint have all published detailed technical analysis. This gives enough procedure-level specificity to engineer real detections.

2. **Consistent playbook.** Across five years of reporting, the same pattern recurs: spearphishing → scripting engine → encoded PowerShell → RMM tool. The consistency makes it detectable.

3. **Relevant geography.** The actor consistently targets Israeli organizations — a geography with high analytical value and underserved public detection coverage.

---

## Hiring Manager Review Path

Start with the path that matches what you are evaluating:

**CTI tradecraft:** [Phase 1 — Source Gathering](./phase-1-source-gathering) → [Phase 2 — Procedure Dataset](./phase-2-procedure-dataset)

**Detection engineering:** [Phase 4 — Detection Atlas](./phase-4-detection-atlas) → [Phase 5 — Validation Results](./phase-5-results) → [Phase 6 — Coverage Matrix](./phase-6-coverage-matrix)

**OpenCTI / STIX:** [Phase 3 — OpenCTI](./phase-3-opencti)

**Lab / infrastructure:** [Phase 5 — Validation Lab](./phase-5-validation-lab) → [Reproduce](./reproduce)

---

## What This Project Proves — and Doesn't

**Proves:**
- A public-source CTI pipeline can be traced from raw source through evidence label, procedure record, ATT&CK candidate mapping, detection pseudologic, and lab validation proof — every step documented
- 11 detection records with SIEM-agnostic pseudologic, coverage scores, and false-positive class documentation
- 14 of 16 rule checks pass lab validation; 2 failures are documented with root cause and fix path, not hidden
- The detection stack (Sysmon + Winlogbeat + Kibana) captures the right telemetry events for 16 of 21 ATT&CK techniques in the procedure dataset

**Does not prove:**
- That detection rules are evasion-proof against real attacker tooling — simulations use benign payloads, not actor malware
- That ATT&CK technique mappings are confirmed actor behavior — all mappings are analyst candidates based on public source claims
- That rules are production-ready without baseline tuning in your specific environment
- Attribution beyond what is stated in the public source base

All validation failures and coverage gaps are acknowledged explicitly in [Phase 6: Coverage Matrix](./phase-6-coverage-matrix) and [Phase 5: Validation Results](./phase-5-results).
