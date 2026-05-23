---
id: phase-1-source-gathering
title: "Phase 1: Source Gathering"
sidebar_label: Source Gathering
---

The first step is source discovery, not detection writing.

## Traditional Source Gathering — and Why It's Not Enough Alone

The standard workflow for CTI source gathering looks like this: run keyword searches (Google, Google Dorks, site: operators for known vendor blogs), check your Threat Intelligence Platform for existing reports on the actor, subscribe to vendor RSS feeds, pull ISAC/ISAO advisories, and query your organization's TIP for any existing indicator sets or finished intelligence reports tagged to the actor.

For a mature, well-documented actor like MuddyWater this gets you to maybe 15–20 well-known sources quickly — the CISA advisory, the MITRE ATT&CK page, two or three vendor blog posts you already knew about. The problem is coverage holes: you'll reliably find sources that are already in your network's vocabulary and miss the ones that aren't. A CERT-IL PDF published in Hebrew and linked only from a government portal, a Group-IB campaign teardown behind a partial paywall, or a 2020 ClearSky report that predates your current TIP subscription window — all of these can fall out of a manual search pass.

TIPs compound this in a specific way: they surface what has already been ingested and tagged. If a source was never promoted into your TIP (because it was published before the subscription started, or because no analyst had time to import it), it is invisible inside the platform. The TIP is authoritative for what it knows, not for the universe of available sources.

The parallel AI research pass was not a replacement for traditional gathering — it was a coverage supplement. After both approaches ran, the traditional pass and the AI outputs were merged into the same deduplication step. The AI outputs added approximately 40 sources beyond what a manual search surfaced; traditional search added discipline about sources the models hallucinated (fabricated URLs, mis-attributed PDFs). Neither was sufficient alone.

I ran parallel deep-research passes using Gemini and OpenAI, both given the same prompt. Each returned a candidate source register. Both outputs were compared, deduplicated (71 candidates → 8 promoted), and the surviving sources were manually acquired and reviewed before anything entered the dataset.

## The Actual Prompt

This is the exact prompt used — both models received it verbatim:

```
You are a senior CTI researcher and source-validation analyst. For Operation Desert Hydra,
gather the best public sources on MuddyWater / Seedworm / Mango Sandstorm / TA450 and
related Iranian activity against Israeli organizations. Goal: create a source register for
an OpenCTI-based CTI-to-detection knowledge graph:
Source → Actor → Campaign → Procedure → ATT&CK Technique → Observable → Log Source
→ Detection → Validation → Coverage.

Search MITRE ATT&CK, CISA/FBI/NSA, Israel National Cyber Directorate, Microsoft,
Google/Mandiant, ESET, Check Point, ClearSky, Unit 42, Proofpoint, SentinelOne,
Recorded Future, Symantec, Talos, Trend Micro, Kaspersky, Cloudflare/Hunt.io/DomainTools,
GitHub, and academic sources.

Include secondary comparison actors only as comparison: APT34, APT35/Charming Kitten/Mint
Sandstorm, CyberAv3ngers, Agrius. Do not merge actors unless a source explicitly supports
overlap.

For every source, return this YAML structure:
  id, title, publisher, url, direct_download_url, download_type, publication_date,
  access_date, actor_claims, source_type, reliability, relevance flags for
  actor_profile/procedures/malware/infrastructure/detections/validation_lab/opencti_modeling,
  key_entities, key_attck_techniques, source_summary, use_for_project, limitations.

Provide direct PDF/STIX/JSON/CSV/GitHub raw links where available; if unavailable write
direct_download_url: none_found. Do not invent URLs or dates.

Use evidence labels:
  Observed = directly shown in telemetry/sample/log/screenshot/source artifact
  Reported = stated by source
  Assessed = source judgment
  Inferred = analyst conclusion from multiple cited facts
  Gap = unknown or not proven

Do not upgrade source claims, do not treat ATT&CK mapping as attribution evidence, do not
treat shared tooling as actor identity proof, and do not claim detection coverage without
validation.

Search exact terms including:
  MuddyWater Iran MOIS, MuddyWater Seedworm, MuddyWater Mango Sandstorm,
  MuddyWater TA450, MuddyWater POWERSTATS, PowGoop, MuddyViper, MuddyWater Israel,
  Israeli organizations, PowerShell, RMM, phishing, spearphishing, Exchange CVE-2020-0688,
  CVE-2017-0199, MITRE ATT&CK, CISA FBI NSA advisory, Mango Sandstorm Microsoft,
  TA450 Proofpoint, Seedworm Symantec, ESET, ClearSky, Unit 42, Check Point, Mandiant,
  SentinelOne, Recorded Future, Talos, Trend Micro, Kaspersky;
  also: APT34 Israel, APT35 Israel, Mint Sandstorm Israel, CyberAv3ngers Israel,
  Agrius Israel, Iranian threat actors Israeli organizations.

Output only these sections:
  1) Executive Source Assessment
  2) High-Priority Source Register with 10-20 best sources in YAML
  3) Extended Source Register
  4) Direct Downloads Table
  5) Actor Alias / Overlap Notes
  6) Procedure Extraction Candidates grouped by tactic with source_ids, evidence_label,
     ATT&CK candidate, required telemetry, detection opportunity, validation_possible
  7) OpenCTI Modeling Candidates
  8) Detection Engineering Opportunities marked candidate only
  9) Gaps And Manual Review Items

The final output must be usable to seed data/sources.yaml, data/procedures.yaml,
docs methodology, OpenCTI import plan, and detection atlas.
```

## What the Prompt Is Designed to Do

A few decisions worth explaining:

**Output schema in the prompt.** Asking for a specific YAML field list (`id`, `title`, `publisher`, `url`, `direct_download_url`…) forces the model to either produce usable data or leave a visible blank — no vague summaries. `direct_download_url: none_found` is the required answer when a URL doesn't exist, which prevents the model from inventing one.

**Evidence labels baked in.** The five labels (Observed / Reported / Assessed / Inferred / Gap) are defined in the prompt so the model applies them consistently and the output is ready to feed directly into `data/procedures.yaml` without reformatting.

**Explicit anti-hallucination rules.** "Do not invent URLs or dates." "Do not upgrade source claims." "Do not treat ATT&CK mapping as attribution evidence." These are not just principles — they are instructions the model can fail visibly on, which makes QA faster.

**Parallel models, same prompt.** Running Gemini and OpenAI on the same prompt and comparing outputs catches source fabrications: if one model lists a URL the other doesn't, that URL gets verified before it enters the register. Two models that agree independently on a source add confidence; one model alone that lists something unusual is a flag.

## The Review Gate

Every source that came out of the AI output went through this checklist before being promoted into `data/sources.yaml`:

- Is the URL real and accessible?
- Is the publication date accurate?
- Does the content actually describe MuddyWater procedures (not just mention the name)?
- Is there at least one procedure-level claim (not just "actor uses PowerShell")?
- Is the actor identification explicit or inferred from shared tooling only?

71 candidates → 8 government/vendor sources promoted. The rest were duplicates, secondary summaries, or sources that named the actor without procedure-level specificity.

![The Review Gate — 5-point promotion checklist](/img/review-gate-infographic.png)

## Research Artifacts (All in the Repo)

Every file from the source gathering workflow is version-controlled and publicly accessible:

- **[Gemini-research.md](https://github.com/anpa1200/operation-desert-hydra/blob/main/docs/source-gathering/Gemini-research.md)** — Raw Gemini deep-research output: candidate source register in YAML, procedure extraction candidates, OpenCTI modeling candidates, detection opportunities, gaps.
- **[openAI-research.md](https://github.com/anpa1200/operation-desert-hydra/blob/main/docs/source-gathering/openAI-research.md)** — Raw OpenAI deep-research output: executive assessment, high-priority sources, extended source register, direct download list, actor alias notes.
- **[relevant-research-list.md](https://github.com/anpa1200/operation-desert-hydra/blob/main/docs/source-gathering/relevant-research-list.md)** — Deduplicated candidate list after comparing both model outputs: 71 sources, acquisition targets for Step 5.
- **[source-acquisition-report.md](https://github.com/anpa1200/operation-desert-hydra/blob/main/docs/source-gathering/source-acquisition-report.md)** — Results of the automated fetch run: HTTP status, content type, file size, and extraction status for all 71 sources.
- **[source-reliability-evidence-assessment.md](https://github.com/anpa1200/operation-desert-hydra/blob/main/docs/source-gathering/source-reliability-evidence-assessment.md)** — Analyst review notes: reliability ratings, evidence quality, promotion decisions, and limitations per source.
- **[raw-sources/](https://github.com/anpa1200/operation-desert-hydra/tree/main/docs/source-gathering/raw-sources)** — 71 numbered source folders, each containing `metadata.json`, `headers.txt`, the raw source file, extracted `source.txt`, and fallback reader output.

**Promoted sources (highest weight):**

- **CISA AA22-055A (Feb 2022)** — Full procedure survey: PowGoop, POWERSTATS, Small Sieve, Mori, Canopy, Marlin; WMI survey script; credential dumping tools.
- **INCD 2023** — Israeli campaign specifics: ScreenConnect/SimpleHelp RMM abuse, Egnyte/OneDrive lures, Log4j + Exchange exploitation.
- **INCD 2024** — BugSleep analysis: 43-minute scheduled task beacon, VPN exploitation, new RMM tools (Level, PDQConnect).

Supporting vendor sources: ClearSky, Deep Instinct, Group-IB, Mandiant, Proofpoint, Sekoia.io, Symantec.

## Why These Three Have the Highest Weight

The reliability assessment used a two-axis rubric: **Source Reliability (A–F)** separating publication discipline from content, and **Information Credibility (1–6)** rating how well each claim is grounded.

**CISA AA22-055A — Reliability A, Credibility 2**

This is a joint advisory signed by five national authorities: CISA, FBI, CNMF, NCSC-UK, and NSA. That multi-agency co-signature is not ceremonial — each agency must independently agree to the technical content before it publishes. The advisory names specific malware families (PowGoop, POWERSTATS, Small Sieve, Mori, Canopy, Marlin), includes an actual WMI PowerShell survey script attributed to MuddyWater, and lists credential-dumping tool names. Evidence label: `Reported` / `Assessed`. The PDF acquired locally at `raw-sources/07-u-s-cyber-command-defense-media-aa22-055a-pdf-mirror/source.pdf` is the authoritative copy distributed via Defense Media Activity. Credibility is 2, not 1, because the advisory states TTPs based on intelligence assessment rather than a single intercepted artifact — but the authority behind that assessment is as high as public-source CTI gets.

**INCD 2023 (MuddyWater / DarkBit PDF) — Reliability A, Credibility 2**

The Israel National Cyber Directorate is the government authority responsible for civilian cyber defense in Israel, the primary target country for this actor. This report covers a specific Israeli campaign including: tool names (ScreenConnect, SimpleHelp), file-sharing lure services (Egnyte, OneDrive), exploitation of Log4j and Exchange CVE-2020-0688, and deployment of ransomware (DarkBit) as a cover operation. Evidence label: `Observed` / `Reported` / `Assessed`. The "Observed" label means the INCD had direct visibility into the incident — not a secondary summary. This gives procedure-level specificity that generic vendor threat intel doesn't reach. Acquired at `raw-sources/17-israel-national-cyber-directorate-muddywater-darkbit-pdf/source.pdf`.

**INCD 2024 (BugSleep PDF) — Reliability A, Credibility 2**

Same publisher authority as INCD 2023, focused on MuddyWater's 2024 evolution. Key content: BugSleep backdoor analysis, the specific 43-minute scheduled task beacon interval (which became `proc_mw_0006` and `det_mw_0006`), VPN exploitation, and new RMM tools (Level, PDQConnect). The 43-minute interval is a concrete behavioral fingerprint — not a general TTP category — and it came from direct INCD analysis. Evidence label: `Observed` / `Reported` / `Assessed`. Acquired at `raw-sources/18-israel-national-cyber-directorate-technological-advancement-and-evolution-of-muddywater-in/source.pdf`.

The three sources share a common characteristic: they are not secondary aggregators or vendor marketing. They are government authorities with direct incident visibility reporting on specific Israeli campaigns.

## Steps After Deduplication: What Actually Happened to All 71 Sources

After the AI outputs were merged and deduplicated, 71 candidate sources remained. Here is what happened to them across Steps 5–9:

![Steps After Deduplication — Steps 5–9 walkthrough](/img/steps-after-deduplication-infographic.png)

**Step 5 — Automated Acquisition**

`tools/fetch_research_sources.py` ran against all 71 URLs. For each source it created a numbered folder under `docs/source-gathering/raw-sources/` with:

```
raw-sources/
  01-mitre-att-ck-muddywater-g0069/
    metadata.json        # URL, fetch timestamp, HTTP status, content-type, size
    headers.txt          # Raw HTTP response headers
    source.html / source.pdf / source.txt   # Primary file
    source.txt           # Text extract (for PDFs and HTML)
    fallback-reader.txt  # Reader-mode fallback if primary was blocked or JS-rendered
```

Not all fetches succeeded. Some sources returned 403 (vendor gating), some required JS rendering (only fallback text was captured), and two PDFs were corrupted. The acquisition report at `docs/source-gathering/source-acquisition-report.md` records the HTTP status, file size, and extraction status for all 71.

**Step 6 — Reliability and Credibility Rating**

Each acquired source was rated using the two-axis rubric. The full assessment table is in `docs/source-gathering/source-reliability-evidence-assessment.md`. Outcome breakdown:

- Reliability A (government / primary standard): 23 sources
- Reliability B (usually reliable vendor / research publisher): 25 sources
- Reliability C (secondary / news / marketing): 18 sources
- Reliability F (failed acquisition or cannot judge): 5 sources

**Step 7 — Promotion Decision**

Only sources with a combination of Reliability A or B, Credibility 2 or better, a usable acquisition, and at least one procedure-level claim were promoted into `data/sources.yaml`. The rest were assigned one of: `Use as corroboration`, `Use as comparison only`, `Defer`, or `Exclude`.

71 candidates → 8 primary sources promoted into the dataset. The 63 that were not promoted are retained in `raw-sources/` for future work; they are not discarded.

**Step 8 — Claim Extraction**

For each promoted source, specific claims were extracted with source binding and evidence labels. A claim is not "MuddyWater uses PowerShell" — it is: "CISA AA22-055A (AA22-055A PDF, p.4) reports that MuddyWater actors deploy PowGoop, a DLL loader that decrypts and executes a PowerShell backdoor (`Reported`)." This source-bound format prevents claim drift downstream.

**Step 9 — Procedure Candidate Extraction**

From the bound claims, 10 procedure candidates were grouped by tactic: Initial Access, Execution, Persistence, Defense Evasion, Discovery, C2, Credential Access. Each candidate recorded: required telemetry, detection opportunity, whether lab validation was feasible, and whether the procedure appeared in multiple independent sources (a promotion signal for higher confidence scores later).

## The Full 71-Source Candidate List

This is the deduplicated list produced after comparing Gemini and OpenAI outputs. Every source here was an acquisition target for Step 5.

**Core MuddyWater / Seedworm / TA450 / Mango Sandstorm**

1. [MITRE ATT&CK — MuddyWater G0069](https://attack.mitre.org/groups/G0069/)
2. [MITRE ATT&CK — POWERSTATS S0223](https://attack.mitre.org/software/S0223/)
3. [MITRE ATT&CK — PowGoop S1046](https://attack.mitre.org/software/S1046/)
4. [CISA alert — Iranian Government-Sponsored MuddyWater Actors Conducting Malicious Cyber Operations](https://www.cisa.gov/news-events/alerts/2022/02/24/iranian-government-sponsored-muddywater-actors-conducting-malicious)
5. [CISA / FBI / CNMF / NCSC-UK / NSA — AA22-055A advisory page](https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-055a)
6. [CISA / FBI / CNMF / NCSC-UK / NSA — AA22-055A PDF](https://www.cisa.gov/sites/default/files/publications/AA22-055A_Iranian_Government-Sponsored_Actors_Conduct_Cyber_Operations.pdf)
7. [U.S. Cyber Command / Defense media — AA22-055A PDF mirror](https://media.defense.gov/2022/Feb/24/2002944274/-1/-1/0/CSA_AA22-055A_Iranian_Government-Sponsored_Actors_Conduct_Cyber_Operations.PDF)
8. [NCSC-UK — Joint advisory on MuddyWater actor](https://www.ncsc.gov.uk/news/joint-advisory-observes-muddywater-actors-conducting-cyber-espionage)
9. [U.S. Cyber Command / Iran Watch mirror — Iranian intel cyber suite of malware PDF](https://www.iranwatch.org/sites/default/files/cybercom_muddywater_press_release.pdf)
10. [Decipher — US Cyber Command Discloses MuddyWater Malware Samples](https://duo.com/decipher/us-cyber-command-discloses-muddywater-malware-samples)
11. [SentinelOne — Wading Through Muddy Waters](https://www.sentinelone.com/labs/wading-through-muddy-waters-recent-activity-of-an-iranian-state-sponsored-threat-actor/)
12. [Palo Alto Unit 42 — Muddying the Water: Targeted Attacks in the Middle East](https://unit42.paloaltonetworks.com/unit42-muddying-the-water-targeted-attacks-in-the-middle-east/)
13. [CERTFA Radar — MuddyWater Threat Actor Cluster](https://radar.certfa.com/en/insights/cluster/fe272810/)
14. [CERTFA Radar — MuddyWater / Earth Vetala Intrusion](https://radar.certfa.com/en/threats/view/d7c9c420/)
15. [Group-IB — MuddyWater APT Group Profile](https://www.group-ib.com/masked-actors/muddywater/)

**Israel-Focused MuddyWater Sources**

16. [Israel National Cyber Directorate — MuddyWater page](https://www.gov.il/en/pages/_muddywater)
17. [Israel National Cyber Directorate — MuddyWater / DarkBit PDF](https://www.gov.il/BlobFolder/news/_muddywater/en/government%20threat%20actor.pdf)
18. [Israel National Cyber Directorate — Technological Advancement and Evolution of MuddyWater in 2024 PDF](https://www.gov.il/BlobFolder/reports/maddy_water_2024/en/ALERT_CERT_IL_W_1858.pdf)
19. [Israel National Cyber Directorate — Overview of Recent Phishing PDF](https://www.gov.il/BlobFolder/reports/alert_1947/he/ALERT-CERT-IL-W-1947.pdf)
20. [ClearSky — Operation Quicksand: MuddyWater's Offensive Attack Against Israeli Organizations](https://www.clearskysec.com/operation-quicksand/)
21. [ClearSky — Operation Quicksand PDF](https://www.clearskysec.com/wp-content/uploads/2020/10/Operation-Quicksand.pdf)
22. [Microsoft — MERCURY and DEV-1084: Destructive attack on hybrid environment](https://www.microsoft.com/en-us/security/blog/2023/04/07/mercury-and-dev-1084-destructive-attack-on-hybrid-environment/)
23. [Microsoft — Exposing POLONIUM activity and infrastructure targeting Israeli organizations](https://www.microsoft.com/en-us/security/blog/2022/06/02/exposing-polonium-activity-and-infrastructure-targeting-israeli-organizations/)
24. [Proofpoint — TA450 Uses Embedded Links in PDF Attachments in Latest Campaign](https://www.proofpoint.com/us/blog/threat-insight/security-brief-ta450-uses-embedded-links-pdf-attachments-latest-campaign)
25. [HarfangLab — MuddyWater campaign abusing Atera Agents](https://harfanglab.io/insidethelab/muddywater-rmm-campaign/)
26. [Deep Instinct — DarkBeatC2: The Latest MuddyWater Attack Framework](https://www.deepinstinct.com/blog/darkbeatc2-the-latest-muddywater-attack-framework)
27. [SC Media — Novel C2 tool leveraged in latest MuddyWater attacks](https://www.scworld.com/brief/novel-c2-tool-leveraged-in-latest-muddywater-attacks)
28. [Check Point — MuddyWater Threat Group Deploys New BugSleep Backdoor](https://blog.checkpoint.com/research/muddywater-threat-group-deploys-new-bugsleep-backdoor/)
29. [ESET / WeLiveSecurity — MuddyWater: Snakes by the riverbank](https://www.welivesecurity.com/en/eset-research/muddywater-snakes-riverbank/)
30. [ESET press release — Iran's MuddyWater targets critical infrastructure in Israel and Egypt](https://www.eset.com/uk/about/newsroom/press-releases/iran-muddywater-critical-infrastructure-israel-egypt-snake-game-eset-research-uk/)
31. [Security Affairs — MuddyWater strikes Israel with advanced MuddyViper malware](https://securityaffairs.com/185244/apt/muddywater-strikes-israel-with-advanced-muddyviper-malware.html)
32. [The Hacker News — Iran-Linked MuddyWater Deploys Atera for Surveillance in Phishing Attacks](https://thehackernews.com/2024/03/iran-linked-muddywater-deploys-atera.html)

**Recent / Evolving MuddyWater Activity**

33. [Proofpoint — Around the World in 90 Days: State-Sponsored Actors Try ClickFix](https://www.proofpoint.com/us/blog/threat-insight/around-world-90-days-state-sponsored-actors-try-clickfix)
34. [Proofpoint — Crossed Wires: a case study of Iranian espionage and attribution](https://www.proofpoint.com/us/blog/threat-insight/crossed-wires-case-study-iranian-espionage-and-attribution)
35. [Group-IB — Operation Olalampo: Inside MuddyWater's Latest Campaign](https://www.group-ib.com/blog/muddywater-operation-olalampo/)
36. [The Hacker News — MuddyWater Targets MENA Organizations with GhostFetch, CHAR, and HTTP_VIP](https://thehackernews.com/2026/02/muddywater-targets-mena-organizations.html)
37. [Rapid7 — Muddying the Tracks: The State-Sponsored Shadow Behind Chaos Ransomware](https://www.rapid7.com/blog/post/tr-muddying-tracks-state-sponsored-shadow-behind-chaos-ransomware/)
38. [The Hacker News — MuddyWater Uses Microsoft Teams to Steal Credentials in False Flag Ransomware Attack](https://thehackernews.com/2026/05/muddywater-uses-microsoft-teams-to.html)
39. [Rapid7 — Iran Conflict Cyber Threat Intelligence](https://www.rapid7.com/research/iran-conflict-cyber-threats/)
40. [ExtraHop — The Digital Front of Iranian Cyber Offensive and Defensive Response](https://www.extrahop.com/blog/the-digital-front-of-iranian-cyber-offensive-and-defensive-response)
41. [Abnormal Security — Tracking Iran-Aligned Cyber Operations Following U.S.-Israel Strikes](https://abnormal.ai/blog/iran-aligned-cyber-operations-email-threats)
42. [Unit 42 — Boggy Serpens Threat Assessment](https://unit42.paloaltonetworks.com/boggy-serpens-threat-assessment/)
43. [Hive Pro — MuddyWater: Iran's Adaptive Cyber Espionage Machine](https://hivepro.com/threat-advisory/muddywater-irans-adaptive-cyber-espionage-machine/)
44. [Hive Pro — MuddyWater / Operation Olalampo PDF](https://hivepro.com/wp-content/uploads/2026/03/TA2026082.pdf)
45. [Kaspersky ICS CERT — APT and financial attacks on industrial organizations in Q2 2024 PDF](https://ics-cert.kaspersky.com/wp-content/uploads/2024/10/kaspersky-ics-cert-apt-and-financial-attacks-on-industrial-organizations-in-q2-2024-en.pdf)
46. [Kaspersky ICS CERT — APT and financial attacks on industrial organizations in Q2 2025 PDF](https://ics-cert.kaspersky.com/wp-content/uploads/2025/09/kaspersky-ics-cert-apt-and-financial-attacks-on-industrial-organizations-in-q2-2025-en-2.pdf)
47. [Trend Micro — Annual APT Report 2025 PDF](https://documents.trendmicro.com/assets/pdf/Annual_APT_Report_2025.pdf)
48. [Intel 471 — HUNTER Iranian Threat Actor Coverage PDF](https://go.intel471.com/hubfs/Emerging%20Threats/2025%20Emerging%20Threats/Upd%20HUNTER%20-%20Iranian%20Threat%20Actor%20Coverage.pdf)

**Iran Threat Context and Comparison Actors**

49. [CISA — Iran Threat Overview and Advisories](https://www.cisa.gov/topics/cyber-threats-and-advisories/advanced-persistent-threats/iran)
50. [CISA — Iran state-sponsored cyber threat publications](https://www.cisa.gov/topics/cyber-threats-and-advisories/nation-state-cyber-actors/iran/publications)
51. [CISA — AA23-335A: IRGC-Affiliated Cyber Actors Exploit PLCs in Multiple Sectors](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-335a)
52. [CISA — AA23-335A PDF](https://www.cisa.gov/sites/default/files/2023-12/aa23-335a-irgc-affiliated-cyber-actors-exploit-plcs-in-multiple-sectors-1.pdf)
53. [MITRE ATT&CK — APT34](https://attack.mitre.org/groups/G0049/)
54. [MITRE ATT&CK — APT35 / Charming Kitten](https://attack.mitre.org/groups/G0059/)
55. [MITRE ATT&CK — Agrius](https://attack.mitre.org/groups/G1030/)
56. [Microsoft — Mint Sandstorm](https://www.microsoft.com/en-us/security/security-insider/mint-sandstorm)
57. [Microsoft — Peach Sandstorm deploys new custom Tickler malware](https://www.microsoft.com/en-us/security/blog/2024/08/28/peach-sandstorm-deploys-new-custom-tickler-malware-in-long-running-intelligence-gathering-operations/)
58. [Microsoft Learn — How Microsoft names threat actors](https://learn.microsoft.com/en-us/microsoft-365/security/defender/microsoft-threat-actor-naming?view=o365-worldwide)
59. [SentinelOne — Iranian Cyber Activity Outlook](https://www.sentinelone.com/blog/sentinelone-intelligence-brief-iranian-cyber-activity-outlook/)
60. [Trellix — The Iranian Cyber Capability PDF](https://mirror.gpmidi.net/vx-underground/Malware%20Analysis/2024/2024-09-19%20-%20The%20Iranian%20Cyber%20Capability/Paper/2024-09-19%20-%20The%20Iranian%20Cyber%20Capability.pdf)

**OpenCTI / STIX / Knowledge Graph References**

61. [OpenCTI documentation — Data model](https://docs.opencti.io/latest/usage/data-model/)
62. [OpenCTI documentation — GraphQL API](https://docs.opencti.io/latest/reference/api/)
63. [OpenCTI documentation — Deduplication](https://docs.opencti.io/latest/usage/deduplication/)
64. [OASIS — STIX 2.1 HTML specification](https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html)
65. [OASIS — STIX 2.1 PDF specification](https://docs.oasis-open.org/cti/stix/v2.1/cs02/stix-v2.1-cs02.pdf)
66. [STIX Project — Relationships](https://stixproject.github.io/documentation/concepts/relationships/)
67. [STIXnet — Extracting STIX Objects in CTI Reports](https://arxiv.org/abs/2303.09999)
68. [From Text to Actionable Intelligence: Automating STIX Entity and Relationship Extraction](https://arxiv.org/abs/2507.16576)
69. [Context-aware Entity-Relation Extraction for Threat Intelligence Knowledge Graphs](https://arxiv.org/abs/2605.15904)

**Validate Before Promoting**

70. [Brandefense — MuddyWater PDF](https://brandefense.io/wp-content/uploads/2025/10/brandefense.io-muddywater-iran-linked-espionage-group-expanding-global-reach-muddywater-.pdf)
71. [KPMG — CTI Report MuddyWater PDF](https://assets.kpmg.com/content/dam/kpmgsites/in/pdf/2022/07/KPMG_CTI_Report_muddy.pdf.coredownload.inline.pdf)

**Critical discipline:** AI output was used only for source discovery. Every claim, mapping, and detection record required analyst review before entering the dataset.
