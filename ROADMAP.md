# Roadmap — Operation Desert Hydra

These are the documented next steps for future iterations. Items are roughly priority-ordered within each category.

---

## Detection Coverage Gaps

- **det_mw_0004 (DLL Side-Loading)** — Fix PARTIAL validation by using a real compiled DLL. Options: install Google Chrome on the lab VM for `Goopdate.dll`, or compile a minimal DLL with a valid export table. Upgrade coverage score from 3 to 5.
- **det_mw_0008a (Telegram Bot API)** — Fix FAIL validation by reconfiguring the lab VM with a host-only or bridged NIC, or using a network proxy that preserves the destination hostname in Sysmon EID 3. Upgrade coverage score from 3 to 5.
- **T1534 Internal Spearphishing** — Write a detection record (det_mw_0011). Requires compromised-account telemetry (mailbox audit logs, login anomaly detection) not present in the current lab scope.

## Zero-Coverage Techniques

These techniques are documented in the source set but have no detection written. Priority order based on actor playbook relevance:

1. T1021.001 — Remote Desktop Protocol (Lateral Movement)
2. T1550.002 — Pass the Hash (Lateral Movement / Credential Access)
3. T1005 — Data from Local System (Collection)
4. T1039 — Data from Network Shared Drive (Collection)
5. T1041 — Exfiltration Over C2 Channel
6. T1486 — Data Encrypted for Impact (DarkBit — separate operation, out of MuddyWater core scope)
7. T1490 — Inhibit System Recovery (DarkBit — same constraint)

---

## Lab Improvements

- Add a second VM (e.g., domain controller `dc01`) to enable lateral movement simulations (T1021.001, T1550.002)
- Enable full network isolation mode option — block all external connectivity from `ws01` and validate that no simulations require it
- Add a `Makefile` target for single-step validation of an individual detection (currently the playbook runs all 11)
- Add Elastic/Kibana detection rule import (currently KQL queries are run manually in Kibana Dev Tools)

---

## Data Pipeline

- Add `claims.yaml` export to the public repo (currently referenced in README but not committed — deduplicate or create a sanitized version)
- Add a machine-readable coverage report generator (Python script that reads `detections.yaml` and `procedures.yaml` and outputs a coverage gap table)
- Version-lock the Sysmon config (currently pulled at deploy time — pin to a specific hash for reproducibility)

---

## Documentation

- Add a "Deploy to production" guide with recommended baseline tuning steps for each detection
- Add a per-detection tuning guide (environment-specific false-positive baseline methodology)
- Add a SOC handoff package template (incident ticket format, alert context, investigation starting points)

---

## Out of Scope

These items are explicitly excluded from future iterations of this specific project:

- Live malware execution
- Real C2 infrastructure
- Credential exfiltration capability
- Attribution findings beyond what is documented in public government and vendor sources
- DarkBit-specific detections (separate threat actor, separate operation)
