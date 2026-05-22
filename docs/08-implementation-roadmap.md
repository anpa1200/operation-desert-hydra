# Operation Desert Hydra — Implementation Roadmap

## MVP Definition

The first release should prove the full pipeline with a small dataset:

- 10-15 sources
- 8-12 MuddyWater procedures
- 5-8 detections
- 4-6 safe validation cases
- one OpenCTI graph import
- one coverage matrix
- one final report

## Done Means

A procedure is complete only when it has:

- source-backed claim
- evidence label
- ATT&CK candidate mapping
- required telemetry
- detection reference
- validation reference
- coverage score
- limitations

## Phase Checklist

### 1. Foundation

- [ ] Create YAML schemas.
- [ ] Create source register.
- [ ] Create evidence-labeling guide.
- [ ] Create OpenCTI mapping plan.
- [ ] Create detection atlas template.
- [ ] Create validation result template.

### 2. Source Register

- [ ] MITRE ATT&CK MuddyWater.
- [ ] MITRE software pages for POWERSTATS, PowGoop, MuddyViper where source-supported.
- [ ] CISA/FBI/NSA Iran advisories.
- [ ] Microsoft / Mandiant / ESET / Check Point / ClearSky / Unit 42 / Proofpoint / SentinelOne / Recorded Future / INCD sources.

### 3. Procedure Dataset

- [ ] Extract initial-access procedures.
- [ ] Extract execution procedures.
- [ ] Extract persistence procedures.
- [ ] Extract discovery procedures.
- [ ] Extract RMM/tool-transfer procedures.
- [ ] Extract collection/archive procedures.
- [ ] Extract C2 procedures.

### 4. OpenCTI Import

- [ ] Create Intrusion Set object.
- [ ] Create Report objects.
- [ ] Create Malware / Tool objects.
- [ ] Create Attack Pattern objects.
- [ ] Create relationships.
- [ ] Export graph snapshot.

### 5. Detection Atlas

- [ ] Write detection logic drafts.
- [ ] Add telemetry requirements.
- [ ] Add false-positive notes.
- [ ] Add validation plans.
- [ ] Mark status and readiness.

### 6. Lab Validation

- [ ] Configure Windows logging.
- [ ] Configure Sysmon.
- [ ] Configure telemetry stack.
- [ ] Run benign PowerShell simulation.
- [ ] Run benign discovery simulation.
- [ ] Run benign persistence simulation.
- [ ] Run benign archive simulation.
- [ ] Record validation results.

### 7. Publication

- [ ] Final report.
- [ ] Executive summary.
- [ ] Coverage matrix.
- [ ] Docusaurus site.
- [ ] Medium article series outline.

## Release Gates

### Gate 1 — Source Quality

No source enters the dataset without:

- source ID
- publisher
- URL
- publication date
- access date
- source type
- reliability

### Gate 2 — Evidence Quality

No claim enters the procedure dataset without:

- claim ID
- evidence label
- source ID
- confidence
- review status

### Gate 3 — Detection Quality

No detection is marked tested without:

- lab case
- expected logs
- observed logs
- result
- limitations

### Gate 4 — Publication Quality

No public release without:

- limitations section
- AI-use disclosure
- source register
- coverage score definitions
- safety statement
