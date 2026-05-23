---
id: pipeline
title: The Pipeline
sidebar_label: The Pipeline
---

The project enforces a chain from source to Kibana screenshot:

```
source → claim → procedure → ATT&CK mapping → telemetry requirement
  → detection pseudologic → benign simulation → lab result → coverage score
```

No step is skipped. Every claim has a source. Every detection has a validation case. Every PASS has a screenshot.

![The Pipeline — 9-step validation chain](/img/pipeline-infographic.png)

## Pipeline Overview

| Step | Phase | Output |
|------|-------|--------|
| 1–4 | Source Gathering | 71 candidate sources, 8 promoted |
| 5–9 | Procedure Dataset | 10 source-bound procedure records |
| 10–19 | OpenCTI Knowledge Graph | MuddyWater graph, 21 ATT&CK techniques |
| 20 | Detection Review | 11 detection records, 4 bugs fixed |
| 21–31 | Validation Lab | 16 rule checks, 13 PASS / 1 PARTIAL / 1 FAIL |

## Coverage Scores

Coverage scores follow a strict scale:

- **5** = lab-validated with a Kibana screenshot
- **4** = correlated analytic (good logic, single source or partial lab)
- **3** = behavioral detection with partial validation

A score of 5 requires a proof, not just passing pseudologic.
