# Gemini Research — First Source Collection Result

```yaml
- id: src_cisa_aa22_055a
  title: "AA22-055A: Iranian Government-Sponsored Actors Conduct Cyber Operations Against Global Government and Commercial Networks"
  publisher: "Cybersecurity and Infrastructure Security Agency (CISA)"
  url: "https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-055a"
  direct_download_url: "https://media.defense.gov/2022/Feb/24/2002944274/-1/-1/0/CSA_AA22-055A_Iranian_Government-Sponsored_Actors_Conduct_Cyber_Operations.PDF"
  download_type: "pdf"
  publication_date: "2022-02-24"
  access_date: "2026-05-22"
  actor_claims: "Formally attributes MuddyWater as an active cyber espionage cluster operating as a subordinate element within the Iranian Ministry of Intelligence and Security (MOIS) since at least 2018."
  source_type: "government_advisory"
  reliability: "A"
  relevance_flags:
    actor_profile: true
    procedures: true
    malware: true
    infrastructure: true
    detections: true
    validation_lab: false
    opencti_modeling: true
  key_entities:
    - "MuddyWater"
    - "Ministry of Intelligence and Security (MOIS)"
    - "PowGoop"
    - "Small Sieve"
    - "Canopy"
    - "Mori"
    - "POWERSTATS"
  key_attck_techniques:
    - "T1566.001"
    - "T1574.002"
    - "T1059.001"
    - "T1027"
  source_summary: "A joint multi-agency advisory outlining the foundational toolsets and delivery mechanics of the MuddyWater threat group. It documents dll side-loading via Goopdate.dll and the distribution of macro-enabled spreadsheets."
  use_for_project: "Establishes the baseline governmental attribution schema and historical malware definitions."
  limitations: "Telemetry is historical and does not address the late-stage transitions to Rust or vishing over collaboration channels."

- id: src_incd_muddywater_israel
  title: "Iranian Government-Sponsored Threat Actor MuddyWater Conducts Cyber Attack Against Israel"
  publisher: "Israel National Cyber Directorate (INCD)"
  url: "https://www.gov.il/en/pages/_muddywater"
  direct_download_url: "none_found"
  download_type: "none_found"
  publication_date: "2023-03-09"
  access_date: "2026-05-22"
  actor_claims: "Attributes the February 2023 disruptive operations against the Technion to MuddyWater, exposing the usage of the DarkBit ransomware persona to conceal state sponsorship."
  source_type: "government_advisory"
  reliability: "A"
  relevance_flags:
    actor_profile: true
    procedures: true
    malware: true
    infrastructure: false
    detections: true
    validation_lab: true
    opencti_modeling: true
  key_entities:
    - "MuddyWater"
    - "DarkBit"
    - "8thcurse.exe"
  key_attck_techniques:
    - "T1486"
    - "T1490"
    - "T1059.003"
    - "T1140"
  source_summary: "Detailed forensic analysis of the Go-based DarkBit encryptor (8thcurse.exe) compiled with MinGW, outlining its parallel file-locking execution threads, shadow copy removal routines, and custom exclusions."
  use_for_project: "Provides structural insights into false-flag destructive campaigns targeting Israeli academia."
  limitations: "Specific to one primary campaign; does not detail C2 infrastructure domains."

- id: src_msft_mercury_dev1084
  title: "MERCURY and DEV-1084: Destructive attack on hybrid environment"
  publisher: "Microsoft Threat Intelligence"
  url: "https://www.microsoft.com/en-us/security/blog/2023/04/07/mercury-and-dev-1084-destructive-attack-on-hybrid-environment/"
  direct_download_url: "none_found"
  download_type: "none_found"
  publication_date: "2023-04-07"
  access_date: "2026-05-22"
  actor_claims: "Assesses with high confidence that MuddyWater (MERCURY) cooperated with DEV-1084 (Storm-1084) to execute hybrid destructive operations after gaining initial network access."
  source_type: "vendor_report"
  reliability: "A"
  relevance_flags:
    actor_profile: true
    procedures: true
    malware: false
    infrastructure: true
    detections: true
    validation_lab: true
    opencti_modeling: true
  key_entities:
    - "MERCURY"
    - "DEV-1084"
    - "vatacloud.com"
  key_attck_techniques:
    - "T1003.006"
    - "T1485"
    - "T1090"
    - "T1219"
  source_summary: "Forensic breakdown of on-premises to cloud lateral traversal, detailing the use of AADInternals on Azure AD Connect hosts to harvest sync credentials and delete critical tenant resources."
  use_for_project: "Provides the foundational model for analyzing MOIS hybrid directory service attacks."
  limitations: "Primarily focused on Microsoft platform log events and Microsoft Defender alerts."

- id: src_clearsky_quicksand
  title: "Operation Quicksand: MuddyWater's Offensive Attack Against Israeli Organizations"
  publisher: "ClearSky Cyber Security"
  url: "https://www.clearskysec.com/operation-quicksand/"
  direct_download_url: "https://www.clearskysec.com/wp-content/uploads/2020/10/Operation-Quicksand.pdf"
  download_type: "pdf"
  publication_date: "2020-10-15"
  access_date: "2026-05-22"
  actor_claims: "Documents a coordinated September 2020 destructive campaign targeting prominent Israeli entities using the PowGoop loader and Thanos ransomware."
  source_type: "vendor_report"
  reliability: "A"
  relevance_flags:
    actor_profile: true
    procedures: true
    malware: true
    infrastructure: true
    detections: true
    validation_lab: true
    opencti_modeling: true
  key_entities:
    - "MuddyWater"
    - "PowGoop"
    - "Thanos"
    - "SSF"
  key_attck_techniques:
    - "T1574.002"
    - "T1190"
    - "T1090"
    - "T1486"
  source_summary: "Exposes the dual attack paths utilized by MuddyWater: decoy documents establishing OpenSSL sessions and CVE-2020-0688 exploitation to drop webshells, combined with local socket proxying via SSF."
  use_for_project: "Essential for tracing the history of the group's PowGoop and custom loader iterations."
  limitations: "Campaign artifacts date back to 2020 and do not reflect recent Rust-based implants."

- id: src_eset_snakes_2025
  title: "MuddyWater's Snakes on a Riverbank"
  publisher: "ESET Research"
  url: "https://www.welivesecurity.com/en/eset-research/muddywater-snakes-riverbank/"
  direct_download_url: "none_found"
  download_type: "none_found"
  publication_date: "2025-12-02"
  access_date: "2026-05-22"
  actor_claims: "Discovers a novel late-2025 MuddyWater campaign targeting critical infrastructure in Israel and Egypt using previously unobserved custom payloads: Fooder loader and MuddyViper backdoor."
  source_type: "vendor_report"
  reliability: "A"
  relevance_flags:
    actor_profile: true
    procedures: true
    malware: true
    infrastructure: true
    detections: true
    validation_lab: true
    opencti_modeling: true
  key_entities:
    - "MuddyWater"
    - "MuddyViper"
    - "Fooder"
    - "processplanet.org"
  key_attck_techniques:
    - "T1134.001"
    - "T1497.003"
    - "T1140"
    - "T1573.001"
  source_summary: "Detailed analysis of the C/C++ backdoor MuddyViper, loaded into memory by Fooder (which implements an interactive Snake game to bypass sandboxes) and communicating using CNG APIs."
  use_for_project: "Establishes modern 2025 custom malware structures and unique cryptographic indicators."
  limitations: "Focus is restricted to telemetry collected from Israeli and Egyptian targets."

- id: src_proofpoint_ta450_pdfs
  title: "Security Brief: TA450 Uses Embedded Links in PDF Attachments in Latest Campaign"
  publisher: "Proofpoint"
  url: "https://www.proofpoint.com/us/blog/threat-insight/security-brief-ta450-uses-embedded-links-pdf-attachments-latest-campaign"
  direct_download_url: "none_found"
  download_type: "none_found"
  publication_date: "2024-03-21"
  access_date: "2026-05-22"
  actor_claims: "Reports on a March 2024 spearphishing campaign by TA450 targeting Israeli organizations with PDF attachments containing embedded malicious links."
  source_type: "vendor_report"
  reliability: "A"
  relevance_flags:
    actor_profile: true
    procedures: true
    malware: false
    infrastructure: true
    detections: true
    validation_lab: false
    opencti_modeling: true
  key_entities:
    - "TA450"
    - "AteraAgent"
  key_attck_techniques:
    - "T1566.001"
    - "T1219"
    - "T1204.001"
  source_summary: "Exposes a shift in email delivery tactics. TA450 used compromised '.il' accounts to send salary lures with PDF attachments containing embedded links that drop ZIP archives containing MSI installers for AteraAgent."
  use_for_project: "Maps email-delivery indicators and RMM delivery flows."
  limitations: "Provides sparse post-exploitation or host-level telemetry."

- id: src_proofpoint_ta450_clickfix
  title: "Around the World in 90 Days: State-Sponsored Actors Try ClickFix"
  publisher: "Proofpoint"
  url: "https://www.proofpoint.com/us/blog/threat-insight/around-world-90-days-state-sponsored-actors-try-clickfix"
  direct_download_url: "none_found"
  download_type: "none_found"
  publication_date: "2025-02-20"
  access_date: "2026-05-22"
  actor_claims: "Documents TA450 adopting the ClickFix social engineering scheme to install Level RMM across targets in the Middle East."
  source_type: "vendor_report"
  reliability: "A"
  relevance_flags:
    actor_profile: true
    procedures: true
    malware: false
    infrastructure: true
    detections: true
    validation_lab: false
    opencti_modeling: true
  key_entities:
    - "TA450"
    - "support@microsoftonlines.com"
    - "Level RMM"
  key_attck_techniques:
    - "T1204.001"
    - "T1059.001"
    - "T1219"
  source_summary: "Details a November 2024 campaign where threat actors sent spoofed Microsoft security update alerts to trick targets into pasting a PowerShell command directly into their consoles to deploy Level RMM."
  use_for_project: "Highlights the integration of fileless interactive execution and new third-party RMM tools."
  limitations: "Does not contain detailed reverse-engineering files of the command payload."

- id: src_rapid7_teams_ransom
  title: "MuddyWater Uses Microsoft Teams to Steal Credentials in False Flag Ransomware Attack"
  publisher: "Rapid7 (via The Hacker News)"
  url: "https://thehackernews.com/2026/05/muddywater-uses-microsoft-teams-to.html"
  direct_download_url: "none_found"
  download_type: "none_found"
  publication_date: "2026-05-06"
  access_date: "2026-05-22"
  actor_claims: "Attributes an early 2026 false-flag extortion campaign using Microsoft Teams and custom malware (Stagecomp, Darkcomp) to MuddyWater."
  source_type: "vendor_report"
  reliability: "A"
  relevance_flags:
    actor_profile: true
    procedures: true
    malware: true
    infrastructure: true
    detections: true
    validation_lab: true
    opencti_modeling: true
  key_entities:
    - "MuddyWater"
    - "Stagecomp"
    - "Darkcomp"
    - "Donald Gay"
  key_attck_techniques:
    - "T1566.002"
    - "T1219"
    - "T1036.005"
    - "T1105"
  source_summary: "Analyzes an attack chain utilizing interactive Teams screen-sharing to harvest credentials and deploy a custom WebView2-based RAT signed with a historic 'Donald Gay' certificate."
  use_for_project: "Exposes state-sponsored vishing mechanics and active 2026 malware structures."
  limitations: "Relies on a summarized technical release; full payload structures are not provided."

- id: src_extrahop_olalampo
  title: "The Digital Front of Iranian Cyber Offensive and Defensive Response"
  publisher: "ExtraHop"
  url: "https://www.extrahop.com/blog/the-digital-front-of-iranian-cyber-offensive-and-defensive-response"
  direct_download_url: "none_found"
  download_type: "none_found"
  publication_date: "2026-03-17"
  access_date: "2026-05-22"
  actor_claims: "Documents MuddyWater's Operation Olalampo (initiated January 26, 2026), which deployed multiple new post-Epic Fury custom malware families."
  source_type: "vendor_report"
  reliability: "B"
  relevance_flags:
    actor_profile: true
    procedures: true
    malware: true
    infrastructure: true
    detections: true
    validation_lab: false
    opencti_modeling: true
  key_entities:
    - "MuddyWater"
    - "CHAR"
    - "GhostBackDoor"
    - "GhostFetch"
    - "HTTP_VIP"
    - "Dindoor"
    - "Fakeset"
  key_attck_techniques:
    - "T1059.001"
    - "T1567.002"
    - "T1105"
  source_summary: "Reports on MuddyWater’s shift to Rust-based tooling (CHAR) and JavaScript-runtime loaders (Dindoor, leveraging Deno, signed 'Amy Cherne'), signaling generative AI involvement in malware creation."
  use_for_project: "Documents 2026 threat actor developments and structural campaigns."
  limitations: "Details network and script telemetry but lacks deep dynamic binary debugging details."

- id: src_cisa_aa23_335a
  title: "AA23-335A: IRGC-Affiliated Cyber Actors Exploit PLCs in Multiple Sectors"
  publisher: "CISA, FBI, NSA, NCSC-UK"
  url: "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-335a"
  direct_download_url: "https://www.cisa.gov/sites/default/files/2023-12/aa23-335a-irgc-affiliated-cyber-actors-exploit-plcs-in-multiple-sectors-1.pdf"
  download_type: "pdf"
  publication_date: "2023-12-01"
  access_date: "2026-05-22"
  actor_claims: "Formally attributes the systematic exploitation of Israeli-made Unitronics Vision Series PLCs starting in late 2023 to the IRGC-affiliated cyber persona 'CyberAv3ngers'."
  source_type: "government_advisory"
  reliability: "A"
  relevance_flags:
    actor_profile: true
    procedures: true
    malware: false
    infrastructure: true
    detections: true
    validation_lab: true
    opencti_modeling: true
  key_entities:
    - "CyberAv3ngers"
    - "Unitronics PLCs"
  key_attck_techniques:
    - "T1190"
    - "T1210"
    - "T1491.002"
    - "T1531"
  source_summary: "Analyzes OT campaigns compromising water, wastewater, energy, and food systems. Threat actors targeted internet-facing PLCs via TCP port 20256 using default credentials, defacing screens and replacing logic files."
  use_for_project: "Critical comparison reference to distinguish MOIS cyber-espionage from IRGC-affiliated physical disruption."
  limitations: "Provides no details regarding standard Windows/Active Directory enterprise campaigns."
```
