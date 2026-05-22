# Operation Desert Hydra

## Step 0 — Define The Purpose And Target Output

Most threat actor writeups stop too early.

They describe the actor, list aliases, summarize campaigns, paste ATT&CK techniques, and finish with a few generic recommendations. That is useful background, but it does not answer the operational question a defender has on Monday morning:

```text
What can my SOC hunt, detect, validate, and measure from this intelligence?
```

Operation Desert Hydra is designed to answer that question.

This project is an OpenCTI-based CTI-to-detection knowledge graph focused on Iranian activity against Israeli organizations, with the first research track centered on MuddyWater / Seedworm / Mango Sandstorm / TA450.

The goal is not to build another actor profile.

The goal is to build a repeatable evidence system that turns public-source threat intelligence into detection-ready, SOC-usable defensive outputs.

## Purpose

Operation Desert Hydra exists to connect four worlds that are often handled separately:

1. CTI research.
2. OpenCTI knowledge modeling.
3. Detection engineering.
4. Lab validation.

The project starts with public-source reporting and forces every useful claim through an evidence discipline:

```text
source -> claim -> procedure -> ATT&CK candidate mapping -> required telemetry -> detection idea -> validation case -> coverage score
```

That chain matters because CTI is not operational until a defender can use it.

A report that says an actor uses PowerShell is not enough. The useful output is a procedure-level record that states:

- which source supports the claim
- whether the claim is observed, reported, assessed, inferred, or still a gap
- which ATT&CK technique is a candidate mapping
- which logs are required to see the behavior
- which detection logic can be tested
- how the behavior can be safely simulated
- what coverage exists after validation
- what assumptions and limitations remain

This is the core idea of the project:

```text
I do not only describe threat actors.
I convert public CTI into reviewed detection engineering artifacts.
```

## Target Output

The final output is a defensive research platform, not a single article.

The target graph is:

```text
Actor
  -> Campaign
  -> Procedure
  -> ATT&CK Technique
  -> Observable
  -> Log Source
  -> Detection
  -> Validation
  -> Coverage Score
```

OpenCTI will act as the CTI graph layer. It will hold the intelligence objects and relationships:

- intrusion sets
- reports
- malware
- tools
- attack patterns
- indicators
- observables
- sectors
- countries
- external references
- relationships
- confidence and markings

The GitHub repository will act as the engineering layer. It will hold the material that should remain auditable, testable, and version-controlled:

- source register
- procedure dataset
- detection atlas
- validation results
- coverage matrix
- lab notes
- OpenCTI import/export scripts
- final report
- executive summary

The project should produce these concrete outputs:

## 1. Source Register

A structured list of public sources, each with publisher, URL, date, actor claims, reliability, relevance, and limitations.

This prevents the project from becoming a pile of unattributed claims.

## 2. Procedure Dataset

A procedure-level dataset that turns reporting into structured records.

Each procedure should answer:

```text
What did the source say happened?
Who is the actor context?
What is the evidence label?
Which ATT&CK mapping is only a candidate?
What telemetry is needed?
What detection can be tested?
What validation case proves visibility?
```

## 3. OpenCTI Knowledge Graph

An OpenCTI graph that models the intelligence layer:

```text
MuddyWater uses POWERSTATS
POWERSTATS uses PowerShell
Report references POWERSTATS
Procedure maps to candidate ATT&CK technique
```

The graph is not the whole project. It is the CTI brain.

## 4. Detection Atlas

A detection atlas that maps procedures to candidate detection logic.

The detections should be behavioral where possible, not just IOC matching.

Each detection should include:

- title
- actor context
- technique
- procedure reference
- required log sources
- logic type
- false positives
- validation status
- coverage score
- limitations

## 5. Safe Validation Lab

A controlled lab used to validate visibility and detection behavior.

The lab must use benign simulations only:

- no live malware
- no real victim infrastructure
- no unauthorized systems
- no credential theft
- no public command-and-control
- no real phishing delivery

The purpose is telemetry generation and detection validation, not offensive execution.

## 6. Coverage Matrix

A coverage matrix that shows what is actually covered, what is weak, and what remains a gap.

Coverage must be honest:

```text
0 = no coverage
1 = IOC only
2 = weak analytic
3 = behavioral analytic
4 = correlated analytic
5 = lab-validated correlated analytic
```

Lab validation does not mean universal production readiness. It means the behavior was safely simulated and the expected telemetry/detection path was observed in the lab.

## 7. Final Report

A final report that explains:

- methodology
- source base
- actor scope
- procedure dataset
- OpenCTI model
- detection atlas
- validation results
- coverage score
- limitations
- next work

## 8. Executive Summary

A short version for defenders and decision-makers.

It should explain what the project found, what can be detected, what still needs telemetry, and what defenders should prioritize.

## Guardrails

The project must stay disciplined.

ATT&CK mapping is not attribution evidence.

AI output is untrusted until analyst-reviewed.

Shared tooling does not prove actor identity.

Confidence reflects evidence quality, corroboration, source access, and analytic consistency.

Public-source CTI has limitations and source bias.

Candidate mappings require validation before operational use.

## Source Gathering With AI

The first research action is source discovery, not detection writing.

Use an AI deep-research workflow only to collect candidate sources and summarize what each source may contribute. The AI output is not evidence by itself. Every source, claim, actor alias, ATT&CK mapping, and detection opportunity still requires analyst review before it enters the dataset or OpenCTI graph.

### 1. Run Deep Research

Run a deep-research task with this prompt:

```text
You are a senior CTI researcher and source-validation analyst. For Operation Desert Hydra, gather the best public sources on MuddyWater / Seedworm / Mango Sandstorm / TA450 and related Iranian activity against Israeli organizations. Goal: create a source register for an OpenCTI-based CTI-to-detection knowledge graph: Source → Actor → Campaign → Procedure → ATT&CK Technique → Observable → Log Source → Detection → Validation → Coverage. Search MITRE ATT&CK, CISA/FBI/NSA, Israel National Cyber Directorate, Microsoft, Google/Mandiant, ESET, Check Point, ClearSky, Unit 42, Proofpoint, SentinelOne, Recorded Future, Symantec, Talos, Trend Micro, Kaspersky, Cloudflare/Hunt.io/DomainTools, GitHub, and academic sources. Include secondary comparison actors only as comparison: APT34, APT35/Charming Kitten/Mint Sandstorm, CyberAv3ngers, Agrius. Do not merge actors unless a source explicitly supports overlap.

For every source, return this YAML structure: id, title, publisher, url, direct_download_url, download_type, publication_date, access_date, actor_claims, source_type, reliability, relevance flags for actor_profile/procedures/malware/infrastructure/detections/validation_lab/opencti_modeling, key_entities, key_attck_techniques, source_summary, use_for_project, limitations. Provide direct PDF/STIX/JSON/CSV/GitHub raw links where available; if unavailable write direct_download_url: none_found. Do not invent URLs or dates.

Use evidence labels: Observed = directly shown in telemetry/sample/log/screenshot/source artifact; Reported = stated by source; Assessed = source judgment; Inferred = analyst conclusion from multiple cited facts; Gap = unknown or not proven. Do not upgrade source claims, do not treat ATT&CK mapping as attribution evidence, do not treat shared tooling as actor identity proof, and do not claim detection coverage without validation.

Search exact terms including: MuddyWater Iran MOIS, MuddyWater Seedworm, MuddyWater Mango Sandstorm, MuddyWater TA450, MuddyWater POWERSTATS, PowGoop, MuddyViper, MuddyWater Israel, Israeli organizations, PowerShell, RMM, phishing, spearphishing, Exchange CVE-2020-0688, CVE-2017-0199, MITRE ATT&CK, CISA FBI NSA advisory, Mango Sandstorm Microsoft, TA450 Proofpoint, Seedworm Symantec, ESET, ClearSky, Unit 42, Check Point, Mandiant, SentinelOne, Recorded Future, Talos, Trend Micro, Kaspersky; also APT34 Israel, APT35 Israel, Mint Sandstorm Israel, CyberAv3ngers Israel, Agrius Israel, Iranian threat actors Israeli organizations.

Output only these sections: 1) Executive Source Assessment, 2) High-Priority Source Register with 10-20 best sources in YAML, 3) Extended Source Register, 4) Direct Downloads Table, 5) Actor Alias / Overlap Notes, 6) Procedure Extraction Candidates grouped by tactic with source_ids, evidence_label, ATT&CK candidate, required telemetry, detection opportunity, validation_possible, 7) OpenCTI Modeling Candidates, 8) Detection Engineering Opportunities marked candidate only, 9) Gaps And Manual Review Items. The final output must be usable to seed data/sources.yaml, data/procedures.yaml, docs methodology, OpenCTI import plan, and detection atlas.
```

### 2. Save The Result

Save the raw deep-research result to:

```text
docs/source-gathering/deep-research-raw.md
```

Then create an analyst-reviewed source register from it:

```text
data/sources.yaml
```

The raw AI output stays in `docs/source-gathering/` as working material. Only reviewed sources should be promoted into `data/sources.yaml`.

### 3. Save Parallel Research Results

Keep each model's output as a separate raw artifact. Do not merge the files automatically.

```text
docs/source-gathering/Gemini-research.md
docs/source-gathering/openAI-research.md
```

Short description:

- `Gemini-research.md` stores the first candidate source register from Gemini, including government advisories, vendor reports, actor claims, direct-download links, and relevance flags.
- `openAI-research.md` stores the second candidate source assessment from OpenAI, including executive assessment, high-priority sources, extended sources, direct-download table, extraction candidates, OpenCTI modeling candidates, detection opportunities, and manual review gaps.

These files are research inputs. They are not validated project data.

### 4. Compare And Deduplicate Sources

Compare the Gemini and OpenAI outputs before promotion.

The review should identify:

- duplicate sources with different IDs
- broken or placeholder URLs
- future or uncertain publication dates
- secondary summaries that duplicate primary reports
- sources with missing direct-download links
- conflicting actor aliases or vendor names
- unsupported malware, tool, or campaign names
- detection ideas that are not backed by source evidence

The result should be a clean candidate list for analyst review, not a larger pile of links.

### 5. Acquire Local Copies Of Sources

After the source list is created, download or scrape every listed source into a separate local folder.

Save raw source material under:

```text
docs/source-gathering/raw-sources/
```

Each source should have its own folder:

```text
NN-source-title/
├── metadata.json
├── headers.txt
├── source.html | source.pdf | source.txt
├── source.txt
└── fallback-reader.txt
```

Short description:

- `metadata.json` records the original URL, HTTP status, saved file paths, content type, and extraction status.
- `headers.txt` stores the HTTP response headers.
- `source.html`, `source.pdf`, or `source.txt` stores the raw acquired source.
- `source.txt` stores extracted readable text for review.
- `fallback-reader.txt` stores a reader-mode fallback when a site blocks direct scraping.

This stage is acquisition only. It does not validate the source claims.

### 6. Validate Saved Source Quality

Iterate through every saved source folder and check acquisition quality before analytic validation.

At this stage, validate only whether the saved file is usable:

- the file opens correctly
- the downloaded file is the intended report or article
- PDFs are real PDFs, not HTML block pages saved as `.pdf`
- HTML captures are readable and not only cookie banners, login pages, anti-bot pages, or access-denied pages
- extracted `source.txt` contains meaningful article/report text
- title, publisher, and URL in `metadata.json` match the saved content
- direct-download files are complete enough for review
- fallback-reader text is acceptable when direct scraping is blocked

If a saved file is not correct, try to find and save a better version:

- official PDF mirror
- archived official page
- publisher press-release version
- government mirror
- vendor mirror
- reader-mode extraction
- alternate direct-download URL

Record the result in the source folder metadata or acquisition report.

Quality labels for this stage:

```text
usable        = full/readable source saved
partial       = enough text for review, but not ideal
blocked       = only anti-bot/access-denied/login content saved
wrong_file    = URL saved unrelated content
duplicate     = same source already captured better elsewhere
needs_retry   = alternate version required
```

Do not promote a source into `data/sources.yaml` until its saved copy is `usable` or explicitly accepted as `partial`.

### 7. Promote Reviewed Sources

Promote only reviewed sources into:

```text
data/sources.yaml
```

Each promoted source must have:

- stable source ID
- title, publisher, URL, and access date
- direct download URL where available
- source type and reliability
- actor claims exactly as stated by the source
- relevance flags
- key entities and candidate ATT&CK techniques
- limitations

Do not promote sources that still contain placeholders, unverified dates, invented URLs, or unsupported claims.

### 8. Extract Procedure Candidates

After the source register is reviewed, extract procedure candidates into:

```text
data/procedures.yaml
```

Each procedure should preserve the evidence chain:

```text
source -> claim -> evidence label -> procedure -> candidate ATT&CK mapping -> required telemetry -> detection idea -> validation case
```

This is where the project starts becoming CTI-to-detection work rather than source collection.

## Step 0 Definition Of Done

Step 0 is complete when the project has a clear purpose and declared output:

```text
Purpose:
Convert public-source CTI about Iranian activity against Israeli organizations into analyst-reviewed, detection-oriented, SOC-usable defensive artifacts.

Target output:
An OpenCTI-backed CTI-to-detection knowledge graph with source register, procedure dataset, detection atlas, safe validation results, coverage matrix, final report, and executive summary.
```

Only after this is clear should the project move into source collection.
