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

## Step 0 Definition Of Done

Step 0 is complete when the project has a clear purpose and declared output:

```text
Purpose:
Convert public-source CTI about Iranian activity against Israeli organizations into analyst-reviewed, detection-oriented, SOC-usable defensive artifacts.

Target output:
An OpenCTI-backed CTI-to-detection knowledge graph with source register, procedure dataset, detection atlas, safe validation results, coverage matrix, final report, and executive summary.
```

Only after this is clear should the project move into source collection.
