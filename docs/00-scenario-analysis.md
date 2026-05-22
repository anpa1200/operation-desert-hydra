# Operation Desert Hydra — Scenario Analysis

## Executive Judgment

This is a strong flagship project if it is built as a CTI-to-detection evidence system, not as another actor profile.

The strongest framing is:

```text
Public-source CTI -> procedure extraction -> evidence labels -> OpenCTI graph -> detection mapping -> safe lab validation -> coverage scoring
```

That gives the project a clear professional identity: converting public CTI into analyst-reviewed, SOC-usable defensive outputs.

## What Makes The Scenario Strong

1. **It is procedure-centered.**
   The project does not stop at "MuddyWater uses PowerShell." It forces each claim into procedures, telemetry requirements, detection logic, validation cases, and coverage scores.

2. **It separates CTI from detection engineering cleanly.**
   OpenCTI should hold CTI entities and relationships. GitHub YAML and Markdown should hold engineering artifacts: detections, validation results, lab notes, coverage scores, and SOC handoff material.

3. **It has evidence discipline built in.**
   The label model is useful and should be mandatory:
   `Observed`, `Reported`, `Assessed`, `Inferred`, `Gap`.

4. **It is defensible for a public portfolio.**
   Safe emulation, no live malware, no unauthorized infrastructure, and no real victim data keep the project inside defensive research boundaries.

5. **It demonstrates CTI platform thinking.**
   OpenCTI makes the graph visible and queryable. The repo makes the engineering layer auditable and version-controlled.

## Hard Boundaries

The project must not imply:

- official intelligence
- complete coverage
- automated attribution
- production-proven detections
- high-confidence detection coverage without validation
- actor equivalence where sources only show alias overlap
- AI-authored intelligence without human review

Use this language instead:

- public-source CTI
- analyst-reviewed
- candidate mapping
- evidence-based
- detection-oriented
- SOC-usable
- lab-validated
- safe emulation
- controlled validation

## Actor Scope Assessment

Primary focus should remain:

```text
MuddyWater / Seedworm / Mango Sandstorm / TA450
```

The secondary actor layer should be explicit comparison only:

```text
APT34
APT35 / Charming Kitten / Mint Sandstorm
CyberAv3ngers
Agrius
```

Do not merge these actors into MuddyWater. Use a separate comparison model:

```yaml
comparison_type: alias_overlap | shared_ttp | shared_sector | shared_infrastructure | source_claim
merge_status: not_merged
reason:
```

## Recommended MVP Scope

The first public-ready version should not try to cover every MuddyWater technique.

MVP should cover 8 to 12 procedures:

1. Spearphishing attachment or link delivery.
2. PowerShell execution.
3. VBScript / JavaScript launcher behavior where source-supported.
4. RMM or remote access software abuse.
5. Discovery command burst.
6. Registry Run key persistence.
7. Scheduled task persistence.
8. File collection and archive behavior.
9. C2 over web protocols.
10. Tool transfer / staged payload behavior.

Each MVP procedure must have:

- source reference
- evidence label
- ATT&CK candidate mapping
- required telemetry
- at least one detection draft
- safe validation plan
- coverage score
- limitations

## Data Model Assessment

### OpenCTI Layer

OpenCTI should model:

- Intrusion Set
- Malware
- Tool
- Attack Pattern
- Report
- Indicator
- Observable
- Sector
- Country
- Organization
- External Reference
- Marking
- Confidence
- Relationships

### Engineering Layer

Keep these outside OpenCTI:

- detection logic
- lab validation cases
- coverage scoring
- false-positive notes
- SOC handoff notes
- telemetry requirements
- detection backlog status

Reason: OpenCTI is the CTI graph. The repo is the detection engineering control plane.

## Evidence Model Refinement

Use this stricter model:

```text
Observed = directly visible in telemetry, sample analysis, logs, screenshots, or source artifact
Reported = stated by a source without adopting the source's conclusion as your own
Assessed = analytic judgment made by a source
Inferred = your conclusion from multiple cited facts
Gap = unknown, unproven, contradictory, or outside source access
```

Add two more fields to every evidence object:

```yaml
review_status: candidate | reviewed | rejected | needs_more_sources
analytic_note:
```

## Detection Atlas Assessment

The detection format is good. Add these fields:

```yaml
status: draft | reviewed | tested | deprecated
data_quality_requirements:
  - process command line must be captured
  - PowerShell script block logging must be enabled
mitre_mapping_status: candidate | reviewed
production_readiness: lab_only | needs_tuning | deployable_with_tuning
```

Do not call anything "production-ready" unless you have production telemetry and tuning evidence.

## Coverage Score Assessment

The 0-5 coverage scale is useful. It needs explicit constraints:

```text
0 = no coverage
1 = IOC only
2 = weak analytic
3 = behavioral analytic
4 = correlated analytic
5 = lab-validated correlated analytic
```

Add a separate field:

```yaml
coverage_scope: lab_only | public_rule | environment_specific
```

This prevents readers from mistaking lab validation for universal coverage.

## AI Workflow Assessment

The AI policy is correct. Make it enforceable through files:

```text
ai/extraction-prompts/
ai/review-prompts/
ai/hallucination-control.md
data/candidate-extractions.yaml
data/review-decisions.yaml
```

AI can create candidate rows. Only reviewed rows can be imported into OpenCTI or linked to detections.

Required rule:

```text
No AI-produced claim enters the graph unless it has a source_id, evidence label, review_status, and reviewer note.
```

## Lab Safety Assessment

The lab scenarios are safe if implemented exactly as benign simulations.

Rules:

- no live malware
- no public C2
- no credential theft
- no real victim brands or infrastructure
- no real phishing delivery
- no external RMM accounts
- no persistence left behind after tests
- no sensitive data in test archives

Use `LAB-SAFE-*` IDs for simulations that produce telemetry but do not emulate payload function.

## Repository Structure Assessment

The proposed structure is sound. Add two directories:

```text
schemas/
scripts/
```

Reason:

- `schemas/` validates YAML before import.
- `scripts/` holds CLI wrappers for validation, import, export, report generation, and coverage calculation.

Recommended final structure:

```text
schemas/
scripts/
data/
docs/
opencti/
detections/
lab/
ai/
reports/
```

## Key Risks

| Risk | Mitigation |
|---|---|
| Scope explosion | Build MVP with 8-12 procedures first. |
| Actor alias confusion | Track aliases and overlaps separately; do not merge without source proof. |
| AI overreach | Candidate-only AI output with mandatory human review. |
| Detection overclaiming | Use lab-only coverage labels unless production telemetry exists. |
| Unsafe emulation | Benign telemetry-only tests; no malware and no public infrastructure. |
| Source bias | Track source type, reliability, publication date, and access date. |
| OpenCTI over-modeling | Keep detection engineering data in YAML/Markdown, not forced into STIX. |

## Recommended Build Phases

### Phase 1 — Project Foundation

- finalize schemas
- create source register
- create evidence model
- create procedure schema
- create detection schema
- create validation schema
- define OpenCTI object mapping

### Phase 2 — MVP Dataset

- collect 10-15 high-quality sources
- extract 8-12 MuddyWater procedures
- assign evidence labels
- map candidate ATT&CK techniques
- identify required telemetry

### Phase 3 — OpenCTI Graph

- create Intrusion Set, Malware, Tool, Attack Pattern, Report, Sector, Country, and relationship objects
- import reviewed data only
- export graph snapshot

### Phase 4 — Detection Atlas

- create Sigma/KQL/SPL/Elastic drafts for MVP procedures
- document false positives
- map telemetry requirements
- mark production readiness as `lab_only`

### Phase 5 — Validation Lab

- run safe emulation cases
- collect expected and observed logs
- record validation results
- calculate coverage scores

### Phase 6 — Publication Package

- final report
- executive summary
- coverage matrix
- Docusaurus site
- Medium article series

## Final Recommendation

Proceed.

This is a credible flagship if the first release is narrow, evidence-labeled, and lab-validated. The project should present itself as a public-source CTI-to-detection engineering system, not as definitive intelligence on Iranian activity.

The sharp positioning:

```text
I do not only describe threat actors.
I convert public CTI into reviewed detection engineering artifacts.
```
