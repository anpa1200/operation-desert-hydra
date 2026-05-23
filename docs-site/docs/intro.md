---
id: intro
title: Why MuddyWater?
sidebar_label: Introduction
---

Most threat actor writeups stop too early. They describe the group, list ATT&CK techniques, and paste some IoCs. Then the report sits in a folder while defenders wonder: *what do I actually do with this on Monday?*

Operation Desert Hydra is an answer to that question.

This documentation covers a full CTI-to-detection pipeline focused on **MuddyWater** — an Iranian state-linked actor (MOIS) that has been targeting Israeli government, defense, and critical infrastructure organizations since at least 2019. By the end, you'll have 11 detection records, 12 Kibana proof screenshots, and a working lab you can deploy with a single command.

Everything is on GitHub: [github.com/anpa1200/operation-desert-hydra](https://github.com/anpa1200/operation-desert-hydra)

---

## Why MuddyWater?

Three reasons:

1. **Rich public reporting.** CISA, Israel's INCD, ClearSky, Deep Instinct, Mandiant, and Proofpoint have all published detailed technical analysis. This gives enough procedure-level specificity to engineer real detections.

2. **Consistent playbook.** Across five years of reporting, the same pattern recurs: spearphishing → scripting engine → encoded PowerShell → RMM tool. The consistency makes it detectable.

3. **Relevant geography.** The actor consistently targets Israeli organizations — a geography with high analytical value and underserved public detection coverage.
