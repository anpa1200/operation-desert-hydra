# Source Reliability And Evidence Assessment

Date: 2026-05-22

Scope: acquisition-quality and source-level assessment for Operation Desert Hydra.

This is not yet a claim-by-claim source register. It is a triage table that decides which sources deserve promotion into `data/sources.yaml` and which sources should remain supporting context, duplicates, or excluded material.

## Rubric

Based on the CTI Analyst Field Manual:

- Source reliability is separate from information credibility.
- Source reliability uses A-F style ratings.
- Information credibility uses 1-6 style ratings.
- Evidence labels used here: `Observed`, `Reported`, `Assessed`, `Inferred`, `Unknown`, `Gap`.

Working interpretation:

| Rating | Meaning |
|---|---|
| `A` | Primary or highly reliable official source; strong publication discipline. |
| `B` | Usually reliable vendor, standards body, or research publisher. |
| `C` | Fairly reliable secondary, commercial, news, or marketing source. |
| `D` | Low reliability for this project or weak sourcing. |
| `F` | Cannot judge or acquisition failed. |

| Credibility | Meaning |
|---|---|
| `1` | Confirmed by primary artifact, standard, official source, or strong direct evidence. |
| `2` | Probably true; strong source and plausible detail, but not fully primary evidence. |
| `3` | Possibly true; useful but needs corroboration. |
| `4` | Doubtful or too indirect for promotion without corroboration. |
| `5` | Improbable for this project scope. |
| `6` | Cannot judge from the saved source. |

## Promotion Guidance

- `Promote`: strong enough for `data/sources.yaml`.
- `Promote as framework/context`: useful for modeling, not actor evidence.
- `Use as corroboration`: do not use as the primary source for a claim.
- `Use as comparison only`: useful for distinguishing actors or platform concepts.
- `Defer`: retained but needs manual spot-check before promotion.
- `Exclude`: failed acquisition, duplicate, blocked, or too weak.

## Sorted Assessment Table

| Rank | Source | Publisher / Type | Evidence label for project use | Reliability | Credibility | Acquisition | Decision | Reason |
|---:|---|---|---|---|---|---|---|---|
| 1 | [07 AA22-055A PDF mirror](raw-sources/07-u-s-cyber-command-defense-media-aa22-055a-pdf-mirror/source.pdf) | CISA/FBI/CNMF/NCSC-UK/NSA via Defense media / government advisory | `Reported`, `Assessed` | A | 2 | usable PDF | Promote | Best local copy of the joint advisory; authoritative attribution/TTP baseline. |
| 2 | [17 INCD MuddyWater / DarkBit PDF](raw-sources/17-israel-national-cyber-directorate-muddywater-darkbit-pdf/source.pdf) | Israel National Cyber Directorate / government report | `Observed`, `Reported`, `Assessed` | A | 2 | usable PDF | Promote | Israel-specific government reporting with technical incident detail. |
| 3 | [18 INCD MuddyWater 2024 PDF](raw-sources/18-israel-national-cyber-directorate-technological-advancement-and-evolution-of-muddywater-in/source.pdf) | Israel National Cyber Directorate / government report | `Observed`, `Reported`, `Assessed` | A | 2 | usable PDF | Promote | High-value Israel-focused source for updated procedures and tooling. |
| 4 | [05 CISA AA22-055A advisory page](raw-sources/05-cisa-fbi-cnmf-ncsc-uk-nsa-aa22-055a-advisory-page/fallback-reader.txt) | CISA/FBI/CNMF/NCSC-UK/NSA / government advisory | `Reported`, `Assessed` | A | 2 | usable fallback | Promote | Official advisory page; local copy is fallback text but complete enough. |
| 5 | [08 NCSC-UK MuddyWater advisory](raw-sources/08-ncsc-uk-joint-advisory-on-muddywater-actor/source.txt) | NCSC-UK / government advisory | `Reported`, `Assessed` | A | 2 | usable HTML/text | Promote | Official UK publication reinforcing joint-government advisory. |
| 6 | [19 INCD phishing PDF](raw-sources/19-israel-national-cyber-directorate-overview-of-recent-phishing-pdf/source.pdf) | Israel National Cyber Directorate / government alert | `Observed`, `Reported` | A | 2 | usable PDF | Promote | Useful for Israeli phishing context and defensive procedures. |
| 7 | [51 CISA AA23-335A page](raw-sources/51-cisa-aa23-335a-irgc-affiliated-cyber-actors-exploit-plcs-in-multiple-sectors/fallback-reader.txt) | CISA/FBI/NSA/NCSC-UK / government advisory | `Reported`, `Assessed` | A | 2 | usable fallback | Promote as comparison | Strong source for CyberAv3ngers/IRGC comparison; not MuddyWater evidence. |
| 8 | [09 U.S. Cyber Command / Iran Watch malware PDF](raw-sources/09-u-s-cyber-command-iran-watch-mirror-iranian-intel-cyber-suite-of-malware-pdf/source.pdf) | U.S. Cyber Command via Iran Watch / official malware disclosure mirror | `Reported` | A | 2 | usable PDF | Promote | Useful official malware-disclosure reference; prefer original CYBERCOM context where available. |
| 9 | [16 INCD MuddyWater page](raw-sources/16-israel-national-cyber-directorate-iranian-government-sponsored-threat-actor-muddywater-con/fallback-reader.txt) | Israel National Cyber Directorate / government page | `Reported`, `Assessed` | A | 2 | usable fallback | Promote as duplicate/context | Official page fallback; source 17 PDF is better for detailed citation. |
| 10 | [49 CISA Iran threat overview](raw-sources/49-cisa-iran-threat-overview-and-advisories/fallback-reader.txt) | CISA / government portal | `Reported` | A | 2 | usable fallback | Promote as context | Authoritative Iran-threat index and advisory context. |
| 11 | [50 CISA Iran publications](raw-sources/50-cisa-iran-state-sponsored-cyber-threat-publications/fallback-reader.txt) | CISA / government portal | `Reported` | A | 2 | usable fallback | Promote as context | Useful source-discovery/index page for Iran-related advisories. |
| 12 | [64 OASIS STIX 2.1 HTML](raw-sources/64-oasis-stix-2-1-html-specification/source.html) | OASIS / standards body | `Observed` | A | 1 | usable HTML/text | Promote as framework/context | Primary standard for STIX modeling. |
| 13 | [65 OASIS STIX 2.1 PDF](raw-sources/65-oasis-stix-2-1-pdf-specification/source.pdf) | OASIS / standards body | `Observed` | A | 1 | usable PDF | Promote as framework/context | Primary PDF standard for STIX modeling. |
| 14 | [61 OpenCTI data model](raw-sources/61-opencti-documentation-data-model/source.txt) | OpenCTI / official documentation | `Observed` | A | 1 | usable HTML/text | Promote as framework/context | Primary platform-model source. |
| 15 | [62 OpenCTI GraphQL API](raw-sources/62-opencti-documentation-graphql-api/source.txt) | OpenCTI / official documentation | `Observed` | A | 1 | usable HTML/text | Promote as framework/context | Primary API automation source. |
| 16 | [63 OpenCTI deduplication](raw-sources/63-opencti-documentation-deduplication/source.txt) | OpenCTI / official documentation | `Observed` | A | 1 | usable HTML/text | Promote as framework/context | Useful for graph hygiene and duplicate handling. |
| 17 | [01 MITRE ATT&CK MuddyWater](raw-sources/01-mitre-att-ck-muddywater-g0069/source.txt) | MITRE ATT&CK / curated framework | `Reported`, `Assessed` | A | 2 | usable HTML/text | Promote | Strong canonical actor/technique reference; still depends on cited sources. |
| 18 | [02 MITRE POWERSTATS](raw-sources/02-mitre-att-ck-powerstats-s0223/source.txt) | MITRE ATT&CK / curated framework | `Reported` | A | 2 | usable HTML/text | Promote | Useful software object for graph mapping. |
| 19 | [03 MITRE PowGoop](raw-sources/03-mitre-att-ck-powgoop-s1046/source.txt) | MITRE ATT&CK / curated framework | `Reported` | A | 2 | usable HTML/text | Promote | Useful software object for graph mapping. |
| 20 | [53 MITRE APT34](raw-sources/53-mitre-att-ck-apt34/source.txt) | MITRE ATT&CK / curated framework | `Reported`, `Assessed` | A | 2 | usable HTML/text | Use as comparison only | Strong comparison-actor reference; not MuddyWater evidence. |
| 21 | [54 MITRE APT35](raw-sources/54-mitre-att-ck-apt35-charming-kitten/source.txt) | MITRE ATT&CK / curated framework | `Reported`, `Assessed` | A | 2 | usable HTML/text | Use as comparison only | Strong comparison-actor reference. |
| 22 | [55 MITRE Agrius](raw-sources/55-mitre-att-ck-agrius/source.txt) | MITRE ATT&CK / curated framework | `Reported`, `Assessed` | A | 2 | usable HTML/text | Use as comparison only | Strong comparison-actor reference. |
| 23 | [58 Microsoft threat actor naming](raw-sources/58-microsoft-learn-how-microsoft-names-threat-actors/source.txt) | Microsoft Learn / official documentation | `Observed` | A | 1 | usable HTML/text | Promote as context | Primary source for Microsoft naming methodology. |
| 24 | [22 Microsoft MERCURY / DEV-1084](raw-sources/22-microsoft-mercury-and-dev-1084-destructive-attack-on-hybrid-environment/source.txt) | Microsoft Threat Intelligence / vendor primary | `Observed`, `Reported`, `Assessed` | B | 2 | usable HTML/text | Promote | Strong technical vendor source with platform telemetry context. |
| 25 | [23 Microsoft POLONIUM Israel](raw-sources/23-microsoft-exposing-polonium-activity-and-infrastructure-targeting-israeli-organizations/source.txt) | Microsoft Threat Intelligence / vendor primary | `Observed`, `Reported`, `Assessed` | B | 2 | usable HTML/text | Promote as context | Strong Israel/Iran context; separate actor handling required. |
| 26 | [56 Microsoft Mint Sandstorm](raw-sources/56-microsoft-mint-sandstorm/source.txt) | Microsoft Security Insider / vendor profile | `Reported`, `Assessed` | B | 2 | usable HTML/text | Use as comparison only | Useful Microsoft taxonomy/comparison source. |
| 27 | [57 Microsoft Peach Sandstorm](raw-sources/57-microsoft-peach-sandstorm-deploys-new-custom-tickler-malware/source.txt) | Microsoft Threat Intelligence / vendor primary | `Observed`, `Reported`, `Assessed` | B | 2 | usable HTML/text | Use as comparison only | Useful comparison source for Iranian actor separation. |
| 28 | [29 ESET MuddyWater: Snakes by the riverbank](raw-sources/29-eset-welivesecurity-muddywater-snakes-by-the-riverbank/source.txt) | ESET Research / vendor primary | `Observed`, `Reported`, `Assessed` | B | 2 | usable HTML/text | Promote | High-value malware/procedure analysis for recent MuddyWater activity. |
| 29 | [28 Check Point BugSleep](raw-sources/28-check-point-muddywater-threat-group-deploys-new-bugsleep-backdoor/source.txt) | Check Point Research / vendor primary | `Observed`, `Reported`, `Assessed` | B | 2 | usable HTML/text | Promote | Strong technical source for BugSleep and campaign procedures. |
| 30 | [24 Proofpoint TA450 PDFs](raw-sources/24-proofpoint-ta450-uses-embedded-links-in-pdf-attachments-in-latest-campaign/source.txt) | Proofpoint / vendor primary | `Observed`, `Reported`, `Assessed` | B | 2 | usable HTML/text | Promote | Strong TA450 phishing/RMM source. |
| 31 | [33 Proofpoint ClickFix](raw-sources/33-proofpoint-around-the-world-in-90-days-state-sponsored-actors-try-clickfix/source.txt) | Proofpoint / vendor primary | `Observed`, `Reported`, `Assessed` | B | 2 | usable HTML/text | Promote | Strong social-engineering/RMM source; good for procedure extraction. |
| 32 | [34 Proofpoint Crossed Wires](raw-sources/34-proofpoint-crossed-wires-a-case-study-of-iranian-espionage-and-attribution/source.txt) | Proofpoint / vendor primary | `Reported`, `Assessed`, `Inferred` | B | 2 | usable HTML/text | Promote with caution | Useful for attribution caution and overlap handling. |
| 33 | [12 Unit 42 Muddying the Water](raw-sources/12-palo-alto-unit-42-muddying-the-water-targeted-attacks-in-the-middle-east/source.txt) | Palo Alto Unit 42 / vendor primary | `Observed`, `Reported`, `Assessed` | B | 2 | usable HTML/text | Promote | Strong historical MuddyWater technical source. |
| 34 | [42 Unit 42 Boggy Serpens](raw-sources/42-unit-42-boggy-serpens-threat-assessment/source.txt) | Palo Alto Unit 42 / vendor profile | `Reported`, `Assessed` | B | 2 | usable HTML/text | Promote as context | Useful alias/context source; verify exact overlap before merging. |
| 35 | [11 SentinelOne Wading Through Muddy Waters](raw-sources/11-sentinelone-wading-through-muddy-waters/source.txt) | SentinelOne Labs / vendor primary | `Observed`, `Reported`, `Assessed` | B | 2 | usable HTML/text | Promote | Strong technical reporting and malware/procedure detail. |
| 36 | [59 SentinelOne Iran outlook](raw-sources/59-sentinelone-iranian-cyber-activity-outlook/source.txt) | SentinelOne Labs / vendor analysis | `Reported`, `Assessed` | B | 2 | usable HTML/text | Promote as context | Useful current Iranian activity context; not all MuddyWater-specific. |
| 37 | [45 Kaspersky ICS Q2 2024 PDF](raw-sources/45-kaspersky-ics-cert-apt-and-financial-attacks-on-industrial-organizations-in-q2-2024-pdf/source.pdf) | Kaspersky ICS CERT / vendor report | `Reported`, `Assessed` | B | 2 | usable PDF | Promote as context | Good industrial-sector context; extract only relevant Iran/MuddyWater claims. |
| 38 | [46 Kaspersky ICS Q2 2025 PDF](raw-sources/46-kaspersky-ics-cert-apt-and-financial-attacks-on-industrial-organizations-in-q2-2025-pdf/source.pdf) | Kaspersky ICS CERT / vendor report | `Reported`, `Assessed` | B | 2 | usable PDF | Promote as context | Good industrial-sector context; spot-check relevant sections. |
| 39 | [47 Trend Micro Annual APT Report 2025](raw-sources/47-trend-micro-annual-apt-report-2025-pdf/source.pdf) | Trend Micro / vendor report | `Reported`, `Assessed` | B | 2 | usable PDF/text | Promote as context | Useful broad APT context; not a primary MuddyWater campaign source. |
| 40 | [60 Trellix Iranian Cyber Capability](raw-sources/60-trellix-the-iranian-cyber-capability-pdf/source.pdf) | Trellix / vendor report mirror | `Reported`, `Assessed` | B | 3 | usable PDF | Use as context | Useful broad background; mirror source requires caution. |
| 41 | [37 Rapid7 Chaos ransomware](raw-sources/37-rapid7-muddying-the-tracks-the-state-sponsored-shadow-behind-chaos-ransomware/source.txt) | Rapid7 / vendor primary | `Observed`, `Reported`, `Assessed` | B | 2 | usable HTML/text | Promote | Strong recent source if actor/campaign claims corroborate. |
| 42 | [39 Rapid7 Iran conflict CTI](raw-sources/39-rapid7-iran-conflict-cyber-threat-intelligence/source.txt) | Rapid7 / vendor analysis | `Reported`, `Assessed` | B | 3 | usable HTML/text | Promote as context | Useful situational context; separate from actor evidence. |
| 43 | [26 Deep Instinct DarkBeatC2](raw-sources/26-deep-instinct-darkbeatc2-the-latest-muddywater-attack-framework/source.txt) | Deep Instinct / vendor primary | `Observed`, `Reported`, `Assessed` | B | 2 | usable HTML/text | Promote | Technical source for C2/tooling; corroborate naming. |
| 44 | [35 Group-IB Operation Olalampo](raw-sources/35-group-ib-operation-olalampo-inside-muddywater-s-latest-campaign/source.txt) | Group-IB / vendor primary | `Observed`, `Reported`, `Assessed` | B | 2 | usable HTML/text | Promote | Recent campaign source; good for procedures and tooling if corroborated. |
| 45 | [15 Group-IB MuddyWater profile](raw-sources/15-group-ib-muddywater-apt-group-profile/source.txt) | Group-IB / vendor profile | `Reported`, `Assessed` | B | 3 | usable HTML/text | Use as context | Profile-level source; useful but less precise than campaign writeups. |
| 46 | [44 Hive Pro Operation Olalampo PDF](raw-sources/44-hive-pro-muddywater-operation-olalampo-pdf/source.pdf) | Hive Pro / vendor report | `Reported`, `Assessed` | C | 3 | usable PDF | Use as corroboration | Useful but should not outrank primary vendor/government sources. |
| 47 | [43 Hive Pro MuddyWater overview](raw-sources/43-hive-pro-muddywater-iran-s-adaptive-cyber-espionage-machine/source.txt) | Hive Pro / vendor overview | `Reported`, `Assessed` | C | 3 | usable HTML/text | Use as corroboration | Good overview; verify against stronger primary sources. |
| 48 | [48 Intel 471 Iran coverage PDF](raw-sources/48-intel-471-hunter-iranian-threat-actor-coverage-pdf/source.pdf) | Intel 471 / commercial report | `Reported`, `Assessed` | C | 3 | usable PDF/text | Defer | Text exists, but source should be manually spot-checked before promotion. |
| 49 | [40 ExtraHop Iranian cyber front](raw-sources/40-extrahop-the-digital-front-of-iranian-cyber-offensive-and-defensive-response/source.txt) | ExtraHop / vendor analysis | `Reported`, `Assessed` | C | 3 | usable HTML/text | Use as context | Useful strategic context; claims need corroboration. |
| 50 | [41 Abnormal Iran-aligned operations](raw-sources/41-abnormal-security-tracking-iran-aligned-cyber-operations-following-u-s-israel-strikes/source.txt) | Abnormal Security / vendor analysis | `Reported`, `Assessed` | C | 3 | usable HTML/text | Use as context | Useful email-threat context; not primary for malware claims. |
| 51 | [13 CERTFA Radar cluster](raw-sources/13-certfa-radar-muddywater-threat-actor-cluster/source.txt) | CERTFA Radar / NGO research profile | `Reported`, `Assessed` | B | 3 | usable HTML/text | Use as corroboration | Relevant regional source; validate exact claims before promotion. |
| 52 | [14 CERTFA Earth Vetala intrusion](raw-sources/14-certfa-radar-muddywater-earth-vetala-intrusion/source.txt) | CERTFA Radar / NGO research | `Reported`, `Assessed` | B | 3 | usable HTML/text | Use as corroboration | Useful regional intrusion context; needs claim-level review. |
| 53 | [10 Decipher CYBERCOM samples](raw-sources/10-decipher-us-cyber-command-discloses-muddywater-malware-samples/source.txt) | Decipher / security news | `Reported` | C | 3 | usable HTML/text | Use as corroboration | Secondary reporting of official disclosure; cite official source first. |
| 54 | [27 SC Media DarkBeatC2 brief](raw-sources/27-sc-media-novel-c2-tool-leveraged-in-latest-muddywater-attacks/fallback-reader.txt) | SC Media / security news | `Reported` | C | 3 | usable fallback | Use as corroboration | Secondary brief; useful pointer, not primary evidence. |
| 55 | [31 Security Affairs MuddyViper](raw-sources/31-security-affairs-muddywater-strikes-israel-with-advanced-muddyviper-malware/source.txt) | Security Affairs / security news | `Reported` | C | 3 | usable HTML/text | Use as corroboration | Secondary summary of ESET; cite ESET first. |
| 56 | [32 The Hacker News Atera](raw-sources/32-the-hacker-news-iran-linked-muddywater-deploys-atera-for-surveillance-in-phishing-attacks/source.txt) | The Hacker News / security news | `Reported` | C | 3 | usable HTML/text | Use as corroboration | Secondary source for Atera/RMM narrative; cite Proofpoint/HarfangLab if available. |
| 57 | [36 The Hacker News GhostFetch](raw-sources/36-the-hacker-news-muddywater-targets-mena-organizations-with-ghostfetch-char-and-http-vip/source.txt) | The Hacker News / security news | `Reported` | C | 3 | usable HTML/text | Use as corroboration | Secondary source for Group-IB/Hive Pro claims. |
| 58 | [38 The Hacker News Teams](raw-sources/38-the-hacker-news-muddywater-uses-microsoft-teams-to-steal-credentials-in-false-flag-ransomw/source.txt) | The Hacker News / security news | `Reported` | C | 3 | usable HTML/text | Use as corroboration | Secondary source; cite Rapid7 if possible. |
| 59 | [30 ESET press release](raw-sources/30-eset-press-release-iran-s-muddywater-targets-critical-infrastructure-in-israel-and-egypt-m/source.txt) | ESET / press release | `Reported` | C | 3 | usable HTML/text | Use as corroboration | Press-release summary; cite ESET research article first. |
| 60 | [66 STIX Project relationships](raw-sources/66-stix-project-relationships/source.txt) | STIX Project / documentation | `Observed` | B | 2 | usable HTML/text | Promote as framework/context | Useful concept reference; older but relevant. |
| 61 | [67 STIXnet paper](raw-sources/67-stixnet-extracting-stix-objects-in-cti-reports/source.txt) | Academic / arXiv | `Reported`, `Assessed` | B | 3 | usable HTML/text | Use as methodology context | Useful extraction-method paper, not actor evidence. |
| 62 | [68 Text to Actionable Intelligence paper](raw-sources/68-from-text-to-actionable-intelligence-automating-stix-entity-and-relationship-extraction/source.txt) | Academic / arXiv | `Reported`, `Assessed` | B | 3 | usable HTML/text | Use as methodology context | Useful AI/STIX extraction context; validate maturity. |
| 63 | [69 Context-aware ER extraction paper](raw-sources/69-context-aware-entity-relation-extraction-for-threat-intelligence-knowledge-graphs/source.txt) | Academic / arXiv | `Reported`, `Assessed` | B | 3 | usable HTML/text | Use as methodology context | Useful KG extraction context; not actor evidence. |
| 64 | [70 Brandefense MuddyWater PDF](raw-sources/70-brandefense-muddywater-pdf/source.pdf) | Brandefense / commercial summary | `Reported`, `Assessed` | C | 4 | usable 1-page PDF | Defer | Very short commercial source; use only if corroborated. |
| 65 | [71 KPMG CTI Report MuddyWater](raw-sources/71-kpmg-cti-report-muddywater-pdf/source.pdf) | KPMG / commercial CTI brief | `Reported`, `Assessed` | C | 3 | usable PDF | Use as corroboration | Brief commercial report; useful but not primary. |
| 66 | 04 CISA MuddyWater alert | CISA / government alert | `Reported` | A | 2 | deleted | Exclude duplicate | Removed because saved copy failed quality; covered by 05 and 07. |
| 67 | 06 CISA AA22-055A PDF | CISA / government PDF | `Reported`, `Assessed` | A | 2 | deleted | Exclude duplicate | Removed because local PDF was access-denied HTML; source 07 is the real PDF. |
| 68 | 52 CISA AA23-335A PDF | CISA / government PDF | `Reported`, `Assessed` | A | 2 | deleted | Exclude duplicate | Removed because local PDF was access-denied HTML; source 51 retained. |
| 69 | 20 ClearSky Operation Quicksand blog | ClearSky / vendor blog | `Reported`, `Assessed` | B | 3 | deleted | Exclude until reacquired | Removed because local capture was anti-bot/minimal text. |
| 70 | 21 ClearSky Operation Quicksand PDF | ClearSky / vendor PDF | `Observed`, `Reported`, `Assessed` | B | 2 | deleted | Exclude until reacquired | Removed because local PDF was anti-bot HTML; reacquire manually because source itself is important. |
| 71 | 25 HarfangLab Atera campaign | HarfangLab / vendor blog | `Reported`, `Assessed` | B | 3 | deleted | Exclude until reacquired | Removed because local capture was anti-bot only. |

## Highest-Priority Promotion Set

Promote these first into `data/sources.yaml`:

```text
07, 17, 18, 05, 08, 19, 01, 02, 03, 22, 24, 29, 28, 33, 34, 11, 12, 37, 26, 35
```

## Sources To Keep Out Of Actor Claims

Use these for method/platform context only:

```text
61, 62, 63, 64, 65, 66, 67, 68, 69
```

Use these only for comparison-actor separation:

```text
23, 51, 53, 54, 55, 56, 57, 58
```

## Sources Needing Reacquisition

These are important but should not be promoted from the current local files:

```text
20, 21, 25
```

Source `21` is the most important reacquisition target because Operation Quicksand is central to historical MuddyWater activity against Israeli organizations.
