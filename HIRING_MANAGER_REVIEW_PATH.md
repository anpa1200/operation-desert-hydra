# Hiring Manager Review Path — Operation Desert Hydra

Suggested review order depending on what you are evaluating.

---

## If You Are Evaluating CTI Tradecraft

1. **[Phase 1: Source Gathering](https://anpa1200.github.io/operation-desert-hydra/docs/phase-1-source-gathering)** — how 71 AI-generated candidate sources were evaluated and 8 promoted using explicit promotion criteria
2. **[Phase 2: Procedure Dataset](https://anpa1200.github.io/operation-desert-hydra/docs/phase-2-procedure-dataset)** — 10 procedure records with Observed / Reported / Assessed evidence labels, Admiralty source reliability, and ATT&CK candidate mapping
3. **[data/sources.yaml](data/sources.yaml)** and **[data/procedures.yaml](data/procedures.yaml)** — structured records to verify evidence-to-procedure traceability
4. **[Medium article — Phases 1–2](https://medium.com/@1200km/operation-desert-hydra-ai-assisted-cti-pipeline-muddywater-to-kibana-34da7917acf0)** — methodology rationale

---

## If You Are Evaluating Detection Engineering

1. **[Phase 4: Detection Atlas](https://anpa1200.github.io/operation-desert-hydra/docs/phase-4-detection-atlas)** — 11 detection records with SIEM-agnostic pseudologic, coverage scores, false-positive classes, and design rationale
2. **[Phase 5: Validation Results](https://anpa1200.github.io/operation-desert-hydra/docs/phase-5-results)** — 14 PASS / 1 PARTIAL / 1 FAIL with Kibana screenshots; failures documented with root cause and fix path
3. **[Phase 6: Coverage Matrix](https://anpa1200.github.io/operation-desert-hydra/docs/phase-6-coverage-matrix)** — technique coverage by tactic, 6 capability gates, zero-coverage acknowledgment
4. **[data/detections.yaml](data/detections.yaml)** — machine-readable detection records with validation_status enum and coverage scores
5. **[VALIDATION_SUMMARY.md](VALIDATION_SUMMARY.md)** — tabular results with root-cause documentation for failures

---

## If You Are Evaluating OpenCTI / STIX Work

1. **[Phase 3: OpenCTI](https://anpa1200.github.io/operation-desert-hydra/docs/phase-3-opencti)** — OpenCTI 6.2 knowledge graph: MuddyWater intrusion set, 9 malware, 4 tools, 21 ATT&CK techniques, 20 source reports
2. **[tools/opencti_import.py](tools/opencti_import.py)** — pycti import script with idempotent read-before-create, STIX 2.1 createdBy referencing the analyst identity (not the threat actor), TLP:WHITE marking
3. **Proof screenshots** in `docs-site/static/img/proofs/` — step-13 through step-19 show the knowledge graph, malware detail, ATT&CK matrix, and dashboard

---

## If You Are Evaluating Lab / Infrastructure Work

1. **[Phase 5: Validation Lab](https://anpa1200.github.io/operation-desert-hydra/docs/phase-5-validation-lab)** — Docker + VirtualBox + Vagrant + Ansible architecture
2. **[lab/ansible/playbooks/validate.yml](lab/ansible/playbooks/validate.yml)** — 11 benign simulation tasks with per-task comments explaining what event each one targets
3. **[SECURITY_MODEL.md](SECURITY_MODEL.md)** — what the lab does and does not do; `.dmp` file handling; isolation constraints
4. **`bash start.sh`** — one-command deployment from a clean clone (prerequisites: Docker, VirtualBox, Vagrant, Ansible, Python 3 + pywinrm)

---

## Quick Links

| What | Where |
|------|-------|
| Docusaurus site | https://anpa1200.github.io/operation-desert-hydra/ |
| GitHub repo | https://github.com/anpa1200/operation-desert-hydra |
| Medium article | https://medium.com/@1200km/operation-desert-hydra-ai-assisted-cti-pipeline-muddywater-to-kibana-34da7917acf0 |
| Detection Atlas | https://anpa1200.github.io/operation-desert-hydra/docs/phase-4-detection-atlas |
| Validation Results | https://anpa1200.github.io/operation-desert-hydra/docs/phase-5-results |
| Coverage Matrix | https://anpa1200.github.io/operation-desert-hydra/docs/phase-6-coverage-matrix |
| Limitations | [LIMITATIONS.md](LIMITATIONS.md) |
| Security Model | [SECURITY_MODEL.md](SECURITY_MODEL.md) |
| Validation Summary | [VALIDATION_SUMMARY.md](VALIDATION_SUMMARY.md) |
