# Changelog — Operation Desert Hydra

## v1.0.0 — 2026-05-23

### Initial public release

**Pipeline complete:**
- Phase 1: Source register — 71 AI-generated candidates reviewed, 8 promoted (CISA AA22-055A, INCD 2023, INCD 2024, and 5 vendor sources)
- Phase 2: Procedure dataset — 10 procedure records with Observed/Reported/Assessed evidence labels, Admiralty source reliability (A-F/1-6), and ATT&CK candidate mapping
- Phase 3: OpenCTI 6.2 knowledge graph — MuddyWater intrusion set, 9 malware families, 4 tools, 21 ATT&CK techniques, 20 source reports; pycti import script
- Phase 4: Detection atlas — 11 detection records with SIEM-agnostic pseudologic (Sigma, KQL, Elastic JSON, SPL), coverage scores, false-positive classes, and design rationale
- Phase 5: Validation lab — Docker + VirtualBox + Vagrant + Ansible; **14 PASS / 1 PARTIAL / 1 FAIL** across 16 rule checks; 12 Kibana proof screenshots
- Phase 6: Coverage matrix — 21 procedure techniques (16 fully validated, 76%), 6 capability gates, zero-coverage acknowledgment
- Phase 7: Full methodology report (`docs/medium-article.md`)
- Phase 8: Executive summary

**Review and accuracy fixes applied before release:**
- Corrected PASS count from 13 to 14 (det_mw_0009 Rules A and B both validated)
- Corrected ATT&CK technique count from 22 to 21 (deduplicated from procedures.yaml)
- Fixed det_mw_0003 creation_logic stale text (coverage_score correctly reported as 5 with full lab validation)
- Fixed det_mw_0008a validation_status from `partially_validated` to `lab_failed` (root cause: VirtualBox NAT)
- Added validation_status schema enum comment to detections.yaml
- Fixed STIX 2.1 semantic error in opencti_import.py: added analyst identity; all `createdBy` references now use analyst identity, not the threat actor (MOIS)
- Added T1534 Internal Spearphishing to zero-coverage table (was in procedure dataset but missing from coverage matrix)

**New files added at release:**
- `LIMITATIONS.md` — known validation failures, source limitations, coverage gaps, capability gates
- `SECURITY_MODEL.md` — lab design principles, what runs and what does not, `.dmp` file handling
- `VALIDATION_SUMMARY.md` — tabular 14 PASS / 1 PARTIAL / 1 FAIL results with ATT&CK coverage
- `HIRING_MANAGER_REVIEW_PATH.md` — suggested review order by evaluator role
- `CHANGELOG.md` — this file
- `ROADMAP.md` — documented future work items

**Docusaurus site updated:**
- Coverage matrix corrected to 21 procedure techniques + 7 source-set techniques
- Zero-coverage table expanded to include T1534
- Validation results infographic alt text corrected to 14 PASS
- Pipeline overview table corrected

**Attribution language standardized throughout:**
- All references changed from "MuddyWater (Iranian MOIS)" to "MuddyWater / Seedworm — widely reported by government and vendor sources as Iran-linked activity associated with MOIS"
