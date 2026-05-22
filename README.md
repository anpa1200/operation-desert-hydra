# Operation Desert Hydra

OpenCTI-based CTI-to-Detection Knowledge Graph for Iranian activity against Israeli organizations.

## Purpose

This project is a private working repository for building a structured CTI-to-detection knowledge graph around public-source reporting, evidence handling, OpenCTI objects, ATT&CK candidate mappings, detection opportunities, and SOC-usable outputs.

## Working Principles

- Public-source CTI has source limitations and bias.
- ATT&CK mapping is not attribution evidence.
- Shared tooling does not prove actor identity.
- AI-assisted enrichment is untrusted until analyst-reviewed.
- Confidence reflects evidence quality, corroboration, source access, and analytic consistency.
- Outputs should identify evidence, gaps, assumptions, confidence, and operational use.

## Initial Structure

```text
docs/                 Research notes and methodology
opencti/              OpenCTI object models, import plans, connector notes
detections/           Detection hypotheses and SOC handoff drafts
data/                 Local working data; sensitive/raw data should not be committed
```

## Status

Private project initialized.
