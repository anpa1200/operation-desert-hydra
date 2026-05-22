# AI Hallucination Control

AI-assisted work in this project is limited to analyst decision support.

## Allowed

- Extract candidate entities.
- Extract candidate procedures.
- Suggest candidate ATT&CK mappings.
- Summarize source claims.
- Draft detection logic for analyst review.
- Find possible gaps.
- Normalize YAML.
- Create reviewer checklists.

## Forbidden

- Final attribution.
- Inventing sources.
- Upgrading confidence.
- Merging aliases without source proof.
- Creating unsupported ATT&CK mappings.
- Claiming detection coverage without validation.
- Treating AI output as evidence.

## Required Review Gate

No AI-produced claim enters the graph unless it has:

- `source_id`
- `evidence_label`
- `confidence`
- `review_status`
- `reviewer_note`

## Required Language

Use:

- candidate mapping
- analyst-reviewed enrichment
- decision-support workflow
- structured enrichment and review support

Do not use:

- automated attribution
- high-confidence AI scoring
- AI-generated intelligence
- autonomous CTI
- AI analyst replacement
