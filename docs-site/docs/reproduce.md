---
id: reproduce
title: Reproduce It Yourself
sidebar_label: Reproduce It
---

The entire project is on GitHub: [**github.com/anpa1200/operation-desert-hydra**](https://github.com/anpa1200/operation-desert-hydra)

One repository contains everything: Docker Compose stack (OpenCTI + Elasticsearch + Kibana), Vagrant lab VM, Ansible provisioning playbooks, detection rules in four formats (Sigma, KQL, Elastic JSON, SPL), structured intelligence datasets (YAML), and all 12 proof screenshots.

## Deploy

```bash
git clone https://github.com/anpa1200/operation-desert-hydra.git
cd operation-desert-hydra
cp stack/.env.template stack/.env
# fill in ELASTIC_PASSWORD, OPENCTI_ADMIN_PASSWORD, OPENCTI_ADMIN_TOKEN
bash start.sh
# → OpenCTI: http://localhost:8080
# → Kibana:  http://localhost:5601
# → all 11 simulations run automatically (~10 min)
```

## Stop / Destroy

```bash
bash stop.sh                # halt VM, keep stack and data
bash stop.sh --destroy-vm   # remove VM disk
bash stop.sh --destroy-stack  # also stop Docker stack
```

## Skip the Lab VM (OpenCTI + Kibana Only)

```bash
bash start.sh --skip-lab
```

## Prerequisites

Docker, VirtualBox, Vagrant, Ansible, Python 3 + pywinrm. Full details in the [README](https://github.com/anpa1200/operation-desert-hydra/blob/main/README.md).

## Key Files

- `docs/article-step-0-project-scenario.md` — full phase-by-phase walkthrough
- `data/detections.yaml` — all 11 detection records with coverage scores
- `lab/ansible/playbooks/validate.yml` — the 11 simulation playbook
- `detections/sigma/`, `detections/kql/`, `detections/elastic/`, `detections/spl/` — rule exports

## What This Project Is Not

This is not a red team toolkit. The lab produces benign telemetry for detection validation — no live malware, no real C2, no credential theft. The detection pseudologic is SIEM-agnostic and requires production translation and tuning before deployment. Coverage scores are conservative: 5 requires a Kibana screenshot, not just passing logic.

The source base is entirely public. The actor's actual TTPs may be more sophisticated than what is documented. Treat the coverage matrix as a floor, not a ceiling.
