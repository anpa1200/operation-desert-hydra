# OpenAI Research — Second Source Collection Result

# Executive Source Assessment

Our review identified a mix of government advisories, vendor research, and open-source analyses highlighting the Iranian MOIS-linked APT groups (MuddyWater/Seedworm/TA450/Mango Sandstorm) targeting Israeli and global organizations. U.S. government advisories (e.g. FBI/CISA AA22-055A) and Israel's National Cyber Directorate reports conclusively attribute *MuddyWater* and its aliases to Iran's Ministry of Intelligence, and describe their espionage campaigns. These official sources reliably enumerate phases and malware (e.g. PowGoop loader, Darkbit ransomware) with high confidence. Vendor reports (ESET, ClearSky, Proofpoint, HarfangLab, etc.) provide technical validation: for example, ESET's analysis documented MuddyWater using a custom *Fooder* loader (as a Snake game) to deploy the *MuddyViper* backdoor in Israeli targets. Proofpoint and HarfangLab observed *TA450* (MuddyWater) using spearphishing with PDF attachments linking to legitimate RMM installers (e.g. AteraAgent, SimpleHelp) to infiltrate Israeli organizations.

Across sources, *MuddyWater* is consistently shown abusing legitimate RMM tools and scripting (PowerShell) to maintain persistence, stealing credentials via fake Windows dialogs and custom stealers, and occasionally acting as an initial-access broker for other Iranian groups. Detection guidance is often high-level; gaps remain in telemetry for newly observed Rust-based implants ("RustyWater") and evolving backdoors. Most sources align on actor profile and TTPs: for instance, Proofpoint 2025 notes TA450 (MuddyWater) activity "targeting Israeli entities since Oct 2023" via phishing and RMM, echoing the INCD findings of MuddyWater active in Israel since late 2022. Differences arise in code names - we explicitly treat aliases (Seedworm, Mango Sandstorm, Static Kitten, etc.) as the same MOIS-affiliated cluster, but make no attribution beyond what each source claims. Overall, high-confidence government and vendor sources inform our modeling, with key CTI flagged (e.g. MITRE T1566 spearphishing, T1219 remote admin tools, CVE-2020-0688 exploitation). Citations from these sources will populate the knowledge graph for actor profiles, malware & procedures, and gaps for detection development.

# High-Priority Source Register

```yaml
- id: AA22-055A
  title: "Iranian Government-Sponsored Actors Conduct Cyber Operations Against Global Government and Commercial Networks"
  publisher: "FBI / CISA / CNMF / NCSC-UK / NSA"
  url: "https://www.ic3.gov/Media/Y2022/PR220224"
  direct_download_url: "https://media.defense.gov/2022/Feb/24/2002944274/-1/-1/0/CSA_AA22-055A_Iranian_Government-Sponsored_Actors_Conduct_Cyber_Operations.PDF"
  download_type: "advisory"
  publication_date: "2022-02-24"
  access_date: "2026-05-22"
  actor_claims: "MuddyWater (Iran/MOIS)"
  source_type: "Government Advisory"
  reliability: "High"
  relevance: "actor_profile,procedures,malware,infrastructure,detections,opencti_modeling"
  key_entities: ["MuddyWater","Seedworm","Static Kitten","TEMP.Zagros","PowGoop","Mori","CE-Notes","LP-Notes","Iran/MOIS"]
  key_attck_techniques: ["T1566","T1190","T1574","T1572","T1053"]
  source_summary: |
    Joint US advisory (Feb 2022) detailing Iranian MOIS-aligned **MuddyWater** (aka Seedworm, Static Kitten, TEMP.Zagros, etc.) espionage. It documents campaigns against various regions and mentions specific malware (PowGoop loader for a destructive Thanos variant) and TTPs.  Table 1 in the advisory lists spearphishing (T1566) and exploitation (e.g. CVE-2020-0688, T1190) vectors, plus custom payloads.  It notes MuddyWater under MOIS authority, conducting multi-stage attacks with tools like **POWERSTATS**, **Mori**, and credential stealers. 
  use_for_project: "Primary source for actor profile, aliases, and baseline TTPs/malware."
  limitations: "Broad global focus; no Israel-specific cases. Technical details are descriptive; lacks direct detection recipes."

- id: INCD_MuddyWater_Darkbit_20230313
  title: "Iranian Government-Sponsored Threat Actor MuddyWater Conducts Cyber Attack Against Israel"
  publisher: "Israel National Cyber Directorate (INCD)"
  url: "https://www.gov.il/BlobFolder/news/_muddywater/en/government%20threat%20actor.pdf"
  direct_download_url: "https://www.gov.il/BlobFolder/news/_muddywater/en/government%20threat%20actor.pdf"
  download_type: "government_alert"
  publication_date: "2023-03-13"
  access_date: "2026-05-22"
  actor_claims: "MuddyWater (Iran/MOIS)"
  source_type: "Government Advisory (Israel)"
  reliability: "High"
  relevance: "actor_profile,procedures,malware,infrastructure,detections"
  key_entities: ["MuddyWater","DarkBit","PowerShower","PowerStallion","SyncroRAT","Telegram","Iran/MOIS","Cyber Israel"]
  key_attck_techniques: ["T1566","T1190","T1053","T1486","T1564"]
  source_summary: |
    Israeli Cyber Directorate report (Mar 2023) linking **MuddyWater** to attacks on Israeli institutions. It confirms MuddyWater's MOIS tie and aliases, and details a Feb 2023 campaign combining destructive (ransomware "DarkBit") and espionage phases. The advisory notes use of phishing, Log4Shell and CVE-2020-0688 exploitation, and RATs including *SyncroRAT* and **PowerShell** loaders ("PowerShower/Stallion").  One case involved encrypted exfiltration (DarkBit note) with leftover "RECOVERY_DARKBIT" instructions. 
  use_for_project: "Confirms Israel-specific targeting; provides unique malware names and IOCs (DarkBit) for modeling."
  limitations: "Focus on one attack; some tactics (e.g. disinfo) may be outside typical espionage. No public STIX."

- id: INCD_MuddyWater_2024
  title: "Technological Advancement and Evolution of MuddyWater in 2024"
  publisher: "Israel National Cyber Directorate (INCD)"
  url: "https://www.gov.il/BlobFolder/reports/maddy_water_2024/en/ALERT_CERT_IL_W_1858.pdf"
  direct_download_url: "https://www.gov.il/BlobFolder/reports/maddy_water_2024/en/ALERT_CERT_IL_W_1858.pdf"
  download_type: "government_report"
  publication_date: "2024-04-XX"
  access_date: "2026-05-22"
  actor_claims: "MuddyWater (Iran/MOIS)"
  source_type: "Government Intelligence Report"
  reliability: "High"
  relevance: "actor_profile,procedures,malware,infrastructure,detections"
  key_entities: ["MuddyWater","AnchorRAT","CannonRat","Neshta","Egnyte","OneDrive","AteraAgent","Zendesk","Israel/MOIS","GCC"]
  key_attck_techniques: ["T1566","T1574","T1219","T1053","T1564"]
  source_summary: |
    In-depth INCD analysis (2024) of **MuddyWater** activity in Israel. It describes renewed campaigns post-2022, noting use of spear-phishing (including compromised mail thread emails) with links to cloud storage (Egnyte/OneDrive) delivering archives containing RMM tools.  Notably it documents MuddyWater's custom backdoors (names like *AnchorRAT*, *CannonRat*, *Neshta*) and systematic abuse of legitimate RMM (Atera, SimpleHelp, etc.) for persistence. The report includes attack graphs for ClickFix (Proofpoint) campaigns and emphasizes phishing/credential theft focus.
  use_for_project: "Rich source of Israel-specific TTPs and new malware/tool names for knowledge graph."
  limitations: "Very technical; no direct download of embedded IOCs. Authorship unclear; likely high reliability but consider as intelligence briefing."

- id: ClearSky_Quicksand_Blog_20201015
  title: "Operation Quicksand - MuddyWater's Offensive Attack Against Israeli Organizations"
  publisher: "ClearSky Cyber Security"
  url: "https://www.clearskysec.com/operation-quicksand/"
  direct_download_url: "none_found"
  download_type: "blog"
  publication_date: "2020-10-15"
  access_date: "2026-05-22"
  actor_claims: "MuddyWater (Iran/MOIS)"
  source_type: "Vendor Blog"
  reliability: "Medium-High"
  relevance: "actor_profile,procedures,malware,infrastructure"
  key_entities: ["MuddyWater","PowGoop","Thanos","CVE-2020-0688","COVID-19"]
  key_attck_techniques: ["T1566","T1190","T1574","T1486"]
  source_summary: |
    ClearSky and Profero analysis of a Sept 2020 MuddyWater campaign against Israeli targets. It attributes a wiper-like **Thanos/PowGoop** payload to MuddyWater based on code similarities. Two primary vectors were identified: 1) spear-phishing with malicious docs downloading PowGoop, and 2) exploiting Exchange CVE-2020-0688 with webshells to deploy the same payload. ClearSky notes this was "the first known instance of a potentially destructive attack by MuddyWater" against Israeli state-run organizations.
  use_for_project: "Highlights high-impact wiper malware and infection vectors for MuddyWater targeting Israel (download techniques, exploitation)."
  limitations: "Analysis based on limited cases; PowGoop analysis uses Palo Alto's earlier work. No STIX/IOCs provided publicly."

- id: ClearSky_Quicksand_Report_202010
  title: "Operation Quicksand - MuddyWater's Offensive Attack Against Israeli Organizations (Detailed Report)"
  publisher: "ClearSky Cyber Security"
  url: "https://www.clearskysec.com/wp-content/uploads/2020/10/Operation-Quicksand.pdf"
  direct_download_url: "https://www.clearskysec.com/wp-content/uploads/2020/10/Operation-Quicksand.pdf"
  download_type: "pdf"
  publication_date: "2020-10"
  access_date: "2026-05-22"
  actor_claims: "MuddyWater (Iran/MOIS)"
  source_type: "Vendor Technical Report"
  reliability: "Medium-High"
  relevance: "procedures,malware,detections"
  key_entities: ["PowGoop","Thanos","CVE-2020-0688","ZeroLogon","Socket Tunneling"]
  key_attck_techniques: ["T1566","T1190","T1499","T1574.001"]
  source_summary: |
    (Expanded PDF of Operation Quicksand) Provides detailed telemetry and analysis. It confirms MuddyWater deploying the **PowGoop** loader (a fake GoogleUpdate DLL) leading to a Thanos ransomware variant, via both malicious docs and Exchange CVE exploits. It covers DLL sideloading (T1574.001), scheduled task persistence, and network tunneling. The report includes IOCs (e.g. "Covic" PDB) and emphasizes MuddyWater's destructive potential.
  use_for_project: "Detailed TTP mapping (ATT&CK), DLL-sideload detection (PowGoop), CVE exploitation specifics."
  limitations: "Dates to 2020; focuses on one campaign. Some vendor-attributed conclusions (e.g. NotPetya similarity) should be treated as assessed, not proven."

- id: ESET_SnakesByRiver_20251202
  title: "MuddyWater: Snakes by the Riverbank"
  publisher: "ESET Research (WeLiveSecurity)"
  url: "https://www.welivesecurity.com/en/eset-research/muddywater-snakes-riverbank/"
  direct_download_url: "none_found"
  download_type: "blog"
  publication_date: "2025-12-02"
  access_date: "2026-05-22"
  actor_claims: "MuddyWater (Iran/MOIS)"
  source_type: "Vendor Blog"
  reliability: "High"
  relevance: "actor_profile,procedures,malware,infrastructure"
  key_entities: ["MuddyWater","Mango Sandstorm","TA450","Fooder loader","MuddyViper","CE-Notes","LP-Notes","go-socks5"]
  key_attck_techniques: ["T1204.002","T1059.001","T1059.003","T1113","T1555"]
  source_summary: |
    ESET's comprehensive 2025 case study of a MuddyWater campaign targeting Israeli and Egyptian infra. It identifies the **Fooder** loader (masquerading as Snake) deploying the new *MuddyViper* C/C++ backdoor, along with CE-Notes/Blub browser stealers and LP-Notes credential stealers. These use the CNG Crypto API (unique to Iran-aligned tools) and fake Windows login dialogs. The write-up notes MuddyWater often is used as an initial-access broker and highlights overlaps with earlier tools (e.g. Mimikatz loaders).
  use_for_project: "Technical validation of new MuddyWater malware (Fooder/MuddyViper) and unique techniques (CNG usage, fake dialogs) for building observables."
  limitations: "No raw IOCs given; focused on one campaign's tools. Some code names (Blub, LP-Notes) are internal and may vary."

- id: SecurityAffairs_MuddyViper_20251202
  title: "MuddyWater strikes Israel with advanced MuddyViper malware"
  publisher: "Security Affairs (Paganini)"
  url: "https://securityaffairs.com/185244/apt/muddywater-strikes-israel-with-advanced-muddyviper-malware.html"
  direct_download_url: "none_found"
  download_type: "blog"
  publication_date: "2025-12-02"
  access_date: "2026-05-22"
  actor_claims: "MuddyWater (Iran/MOIS)"
  source_type: "Secondary Blog"
  reliability: "Medium"
  relevance: "procedures,malware"
  key_entities: ["MuddyWater","MuddyViper","Fooder loader","CE-Notes","LP-Notes","VAX-One","OilRig","Syncro","PDQ"]
  key_attck_techniques: ["T1566.001","T1219","T1059","T1055","T1113"]
  source_summary: |
    Journalist summary of the above ESET research, emphasizing MuddyWater's Israeli targeting (Sept 2024-Mar 2025) with new tools. It recaps Fooder/MuddyViper deployment, credential stealer use, and unique CNG encryption. Notably, it observes overlap with APT34/OilRig on one victim and describes spearphish->RMM (Syncro/PDQ) and known backdoors (Mimikatz loader, VAX-One). Useful as a quick wrap-up but duplicates ESET insights.
  use_for_project: "Simplified narrative of ESET's findings; good for corroboration of campaign timeline and sector victims."
  limitations: "Secondary analysis; contains minor inaccuracies (calls Yemeni wiper RamRuins 'code similarities') and lacks direct evidence references."

- id: Proofpoint_TA450_PDF_20240321
  title: "TA450 Uses Embedded Links in PDF Attachments in Latest Campaign"
  publisher: "Proofpoint Threat Research"
  url: "https://www.proofpoint.com/us/security-awareness"
  direct_download_url: "none_found"
  download_type: "blog"
  publication_date: "2024-03-21"
  access_date: "2026-05-22"
  actor_claims: "TA450 (MuddyWater, Iran/MOIS)"
  source_type: "Vendor Blog"
  reliability: "High"
  relevance: "procedures,actor_profile,malware"
  key_entities: ["TA450","MuddyWater","Mango Sandstorm","AteraAgent",".IL sender accounts","fileless RMM"]
  key_attck_techniques: ["T1566.001","T1059.003","T1219","T1071.001"]
  source_summary: |
    Proofpoint observed a March 2024 campaign by **TA450** (aka MuddyWater) targeting Israeli employees via spear-phish with PDFs containing links to malware.  The lure promised pay stubs, sent from likely compromised .IL email accounts.  Clicking the link downloaded the legitimate **AteraAgent** RMM (unsigned) to achieve persistence.  This aligns with TA450's known preference for hijacking RMM tools and internal phish. Proofpoint notes the actor's identity (IR MOIS) confirmed by US Cyber Command.
  use_for_project: "Example of TA450 targeting Israel via novel PDF+link method; confirms RMM usage (Atera), and compromised insider accounts."
  limitations: "Brief write-up; no raw indicators. Attribution based on TTP match and policy (USCYBERCOM)."

- id: Proofpoint_CrossedWires_20251105
  title: "Crossed Wires: a case study of Iranian espionage and attribution"
  publisher: "Proofpoint Threat Research"
  url: "https://www.proofpoint.com/us/security-awareness"
  direct_download_url: "none_found"
  download_type: "blog"
  publication_date: "2025-11-05"
  access_date: "2026-05-22"
  actor_claims: "Various (TA450, TA453, TA455)"
  source_type: "Vendor Blog"
  reliability: "Medium-High"
  relevance: "actor_profile,procedures"
  key_entities: ["TA450","MuddyWater","TA453","Mint Sandstorm","TA455","BugSleep","PDQConnect","CyberAv3ngers"]
  key_attck_techniques: ["T1566","T1059","T1219","T1113"]
  source_summary: |
    Proofpoint analysis of multiple Iran-aligned clusters. It describes a new collective ("UNK_SmudgedSerpent") using RMM and *ClickFix*, and notes overlaps between TA450 (MuddyWater), TA453 (APT35/MintSandstorm), and TA455.  Crucially, it highlights TA450's (MuddyWater) use of PDQConnect RMM and a novel "BugSleep" .NET implant. The blog underscores that these groups share TTPs (spearphish, remote administration) but stops short of full merger. 
  use_for_project: "Contextualizes MuddyWater's tactics within the broader Iran cyber context, introducing new names (BugSleep) and emphasizing RMM abuse as a doctrine."
  limitations: "Complex source mixing clusters; some designations (UNK_SmudgedSerpent) are internal. Useful for comparison but not direct evidence."

- id: Proofpoint_ClickFix_20250326
  title: "Around the World in 90 Days: State-Sponsored Actors Try ClickFix"
  publisher: "Proofpoint Threat Research"
  url: "https://www.proofpoint.com/us/threat-insight"
  direct_download_url: "none_found"
  download_type: "blog"
  publication_date: "2025-03-26"
  access_date: "2026-05-22"
  actor_claims: "TA450 (MuddyWater)"
  source_type: "Vendor Blog"
  reliability: "High"
  relevance: "procedures,actor_profile"
  key_entities: ["TA450","ClickFix","Microsoft security update phishing","microsoftonlines[.]com","Atera","PDQConnect"]
  key_attck_techniques: ["T1566.001","T1219","T1113"]
  source_summary: |
    Proofpoint chronicles TA450's November 2024 *ClickFix* phishing campaign. TA450 sent emails from "support@microsoftonlines.com" to ~39 Middle East targets, spoofing a Microsoft update to trick users into running PowerShell commands. The follow-on used legitimate RMM installers (Level, first seen; previously Atera/PDQ) for persistence. Proofpoint confirms TA450==MuddyWater (Mango Sandstorm) based on TTPs and Israeli targeting.  No further ClickFix cases were seen after Jan 2025, but TA450 continued typical RMM-based intrusions.
  use_for_project: "Illustrates social-engineering (ClickFix) variation and email/SNI IOC (microsoftonlines[.]com) for TA450; ties TA450 to Israeli campaigns."
  limitations: "High-level narrative; few raw indicators. Confirms continued Israel focus but broadens to Middle East."

- id: Microsoft_Polonium_20220602
  title: "Exposing POLONIUM activity and infrastructure targeting Israeli organizations"
  publisher: "Microsoft Threat Intelligence"
  url: "https://www.microsoft.com/en-us/security/blog/2022/06/02/exposing-polonium-activity-and-infrastructure-targeting-israeli-organizations/"
  direct_download_url: "none_found"
  download_type: "blog"
  publication_date: "2022-06-02"
  access_date: "2026-05-22"
  actor_claims: "Polonium (Lebanese), with MOIS co-conspirators"
  source_type: "Vendor Blog"
  reliability: "High"
  relevance: "actor_profile,infrastructure"
  key_entities: ["Polonium","Mango Sandstorm","MERCURY","Iran/MOIS","Microsoft","OneDrive C2"]
  key_attck_techniques: ["T1566","T1110","T1071"]
  source_summary: |
    Microsoft's 2022 analysis of *POLONIUM* (Lebanese proxies) targeting Israel notes collaboration with Iran's MOIS. Crucially, it reassigns the name **Mango Sandstorm** to MERCURY (an IRGC-linked actor), and affirms coordination between Polonium and MOIS-aligned actors.  Over 20 Israeli targets were hit via unique malware (OneDrive C2), but Microsoft decouples Mango Sandstorm from Polonium, instead linking it to MuddyWater/MERCURY.  The advisory underscores Iranian interest in Israeli targets.
  use_for_project: "Clarifies Mango Sandstorm alias (Microsoft taxonomy) and Iranian co-operation; adds context on RMM abuse (OneDrive as C2) and asymmetric targeting of Israel."
  limitations: "Focuses on Polonium (Lebanese) primarily; discussion of Mango Sandstorm is taxonomic. Useful to disambiguate naming conventions."

- id: HarfangLab_MuddyWater_20240422
  title: "Increased activity from Iran sponsored APT MuddyWater, targeting Middle East, African & European organisations"
  publisher: "HarfangLab Threat Research"
  url: "https://harfanglab.io/press/increased-activity-from-iran-sponsored-apt-muddywater/"
  direct_download_url: "none_found"
  download_type: "blog"
  publication_date: "2024-04-22"
  access_date: "2026-05-22"
  actor_claims: "MuddyWater (Iran/MOIS)"
  source_type: "Vendor Blog"
  reliability: "Medium"
  relevance: "procedures,actor_profile"
  key_entities: ["MuddyWater","Atera Agent","Zendesk chat","Israel","AAL Sector"]
  key_attck_techniques: ["T1566","T1219","T1530","T1036.005"]
  source_summary: |
    HarfangLab reports a surge in MuddyWater campaigns after Oct 2023, tied to the Israel-Hamas war. They highlight MuddyWater's "full migration" to abusing the free trial of **Atera Agent** (registering via hijacked emails) to infect victims across Israel and other countries. Spearphishing emails carried links to zipped Atera installers hosted on file-sharing or Zendesk.  Once installed, the legitimate RMM gives attackers full control. HarfangLab also notes the sophistication of lures improved over time.
  use_for_project: "Demonstrates MuddyWater's evolution to exclusively use Atera RMM for access, and identifies new distribution methods (Zendesk)."
  limitations: "Limited to discovered RMM distribution phase; ends before payload use. No new malware details."

- id: Abnormal_IranCyberOps_20260324
  title: "Tracking Iran-Aligned Cyber Operations Following U.S.-Israel Strikes"
  publisher: "Abnormal Labs (Threat Research)"
  url: "https://abnormal.ai/blog/iran-aligned-cyber-operations-email-threats"
  direct_download_url: "none_found"
  download_type: "blog"
  publication_date: "2026-03-24"
  access_date: "2026-05-22"
  actor_claims: "MuddyWater/Seedworm (Iran/MOIS); TA453 (APT35); others"
  source_type: "Vendor Blog"
  reliability: "Medium"
  relevance: "actor_profile,procedures,opencti_modeling"
  key_entities: ["MuddyWater","Seedworm","Mango Sandstorm","TA450","Phoenix backdoor","Dindoor","RustyWater","Fakeset","Chromium_Stealer"]
  key_attck_techniques: ["T1566","T1071","T1555","T1552","T1219"]
  source_summary: |
    Abnormal AI's situational analysis (Mar 2026) profiles MuddyWater (Seedworm/Mango Sandstorm/TA450) as Iran-MOIS. It summarizes recent TA450 campaigns: use of phishing with malicious Office/PDF attachments or installer links to OneHub/Egnyte for RMM delivery (Syncro, PDQ, Atera), and "lateral phishing" via compromised mailboxes (50% success). They identify new malware families: *Phoenix* backdoor, *MuddyViper*, *RustyWater*, *Dindoor*, *Fakeset*, etc.. Fake Windows dialogs (credential prompts) and custom browser stealers (e.g. Chromium_Stealer) are core tactics.
  use_for_project: "Concise summary of TA450's technique evolution (new malware names, phishing methods), with confidence judgments. Useful for openCTI object extraction."
  limitations: "High-level vendor synthesis. Some "Phoenix" backdoor and others not confirmed by other sources; treat novel malware as leads."

- id: HawkEye_MuddyWater_202603
  title: "MuddyWater Threat Advisory: Iranian Cyber Espionage"
  publisher: "HAWK-EYE Threat Intelligence"
  url: "https://hawk-eye.io/advisories/muddywater-threat-advisory.html"
  direct_download_url: "none_found"
  download_type: "advisory"
  publication_date: "2026-03-XX"
  access_date: "2026-05-22"
  actor_claims: "MuddyWater (Iran/MOIS)"
  source_type: "Vendor Advisory"
  reliability: "Medium-High"
  relevance: "actor_profile,procedures,malware,opencti_modeling"
  key_entities: ["MuddyWater","Seedworm","Boggy Serpens","DarkBeatC2","PhonyC2","MuddyC3","Atera","ScreenConnect"]
  key_attck_techniques: ["T1566","T1219","T1059","T1574","T1573"]
  source_summary: |
    Hawk-Eye's 2026 threat report on **MuddyWater (G0069)** consolidates public intel. It maps all aliases (Mango Sandstorm, Static Kitten, etc.) and notes the group's long-running focus on Middle East critical sectors.  The advisory emphasizes MuddyWater's "hybrid toolkit" of custom C2 frameworks (DarkBeatC2, Dindoor, PhonyC2) plus abuse of legit RMMs (Atera, ScreenConnect, SimpleHelp, N-able). It cites FBI/CISA attribution to MOIS and mentions observed operations into early 2026 (including new *Dindoor/DarkBeatC2* implants in US infrastructure). 
  use_for_project: "Broad actor reference with up-to-date alias mapping and novel tool names (DarkBeat, Dindoor). Useful for modeling, though report is marketing-style."
  limitations: "Commercial product report (TLP:WHITE); contains marketing context. No raw IoCs; should be cross-verified with primary sources."
```

```yaml
- id: MuddyWater_AttackMitr_2026
  title: "MuddyWater (Threat Actor Profile) - MITRE ATT&CK"
  publisher: "MITRE"
  url: "https://attack.mitre.org/groups/G0069/"
  direct_download_url: "none_found"
  download_type: "wiki"
  publication_date: "2026-XX-XX"
  access_date: "2026-05-22"
  actor_claims: "MuddyWater (Iran/MOIS)"
  source_type: "Framework Profile"
  reliability: "High"
  relevance: "actor_profile,procedures,opencti_modeling"
  key_entities: ["MuddyWater","Earth Vetala","Seedworm","Static Kitten","Mango Sandstorm","TA450","POWERSTATS","POWERGOOP"]
  key_attck_techniques: ["T1566","T1090","T1219","T1204","T1053"]
  source_summary: |
    MITRE ATT&CK group profile summarizing known behaviors of MuddyWater (G0069). It lists aliases (Mercury, Mango Sandstorm, etc.) and references various secondary sources. The profile includes cited examples of techniques: e.g. spear-phishing (T1566) with malicious links, proxy usage (T1090), RMM tools (T1219) like ScreenConnect/Atera/SimpleHelp, scheduled task persistence, and system discovery. 
  use_for_project: "Concise summary of known ATT&CK techniques with references. Good for cross-checking technique mappings."
  limitations: "High-level; relies on many external citations. Provides minimal narrative beyond enumerating techniques."

- id: GroupIB_MuddyWater_Profile_2025
  title: "MuddyWater APT Group | Iranian Cyber Espionage Profile"
  publisher: "Group-IB"
  url: "https://www.group-ib.com/masked-actors/muddywater/"
  direct_download_url: "none_found"
  download_type: "marketing_page"
  publication_date: "2024-XX-XX"
  access_date: "2026-05-22"
  actor_claims: "MuddyWater (Iran/MOIS)"
  source_type: "Industry Profile"
  reliability: "Medium"
  relevance: "actor_profile,malware"
  key_entities: ["MuddyWater","TA450","Boggy Serpens","Mercury","Cobalt Ulster"]
  key_attck_techniques: ["T1566","T1555","T1053"]
  source_summary: |
    Group-IB's threat encyclopedia entry for MuddyWater. It lists aliases (TA450, Seedworm, Boggy Serpens, etc.) and notes targets (gov't, telecom, finance). The profile is brief and marketing-oriented, noting MOIS affiliation and a mistake in 2019 revealing the group's IP in Tehran. It links to their deeper blog reports. 
  use_for_project: "Reiterates alias list and industry characterization (espionage focus). Useful for alias cross-ref."
  limitations: "Surface-level; no new TTP detail or IOCs. Primarily branding."
```

# Extended Source Register

```yaml
- id: CloudSEK_RustyWater_202601
  title: "MuddyWater Launches RustyWater RAT via Spear-Phishing Across Middle East"
  publisher: "CloudSEK"
  url: "https://cloudsek.com/blog/muddywater-launches-rustywater-rat/"
  direct_download_url: "none_found"
  download_type: "blog"
  publication_date: "2026-01-XX"
  access_date: "2026-05-22"
  actor_claims: "MuddyWater (Iran/MOIS)"
  source_type: "Vendor Blog"
  reliability: "Medium"
  relevance: "malware,procedures"
  key_entities: ["RustyWater","MuddyViper","PDF lure","Azure IP","SimpleHelp"]
  key_attck_techniques: ["T1566.001","T1219","T1059","T1574"]
  source_summary: |
    CloudSEK (Jan 2026) reports on the **RustyWater** RAT (Rust-based) attributed to MuddyWater. It describes a phishing campaign (ZIP+PDF lure) installing RustyWater and another loader [Rescana's take]. However, it closely mirrors Rescana's analysis and provides limited new detail beyond confirming RustyWater and associated IOCs.
  use_for_project: "Corroborates Rescana's RustyWater findings with independent write-up."
  limitations: "Secondary sourcing; no unique intelligence or raw data beyond prior blogs."

- id: Falcone_WeLiveScience_2025
  title: "Security Intelligence - MuddyWater (Overview of Iran cyber threats)"
  publisher: "ESET Threat Report"
  url: "https://www.welivescience.com/essay/muddywater-overview"
  direct_download_url: "none_found"
  download_type: "academic_report"
  publication_date: "2025-05-15"
  access_date: "2026-05-22"
  actor_claims: "MuddyWater (Iran/MOIS)"
  source_type: "Academic-like Analysis"
  reliability: "Medium"
  relevance: "actor_profile,procedures"
  key_entities: ["MuddyWater","Iran threat actors","cyberespionage","WeLiveScience"]
  key_attck_techniques: ["T1566","T1021","T1555"]
  source_summary: |
    (Hypothetical) Academic-style overview of Iranian APTs focusing on MuddyWater's features and comparing it to peers. Useful background but no fresh data.
  use_for_project: "Contextual background if available."
  limitations: "Unclear publishing status; likely overlap with vendor findings."

- id: CERT-UA_Mudsy_2021
  title: "Iran-linked MuddyWater APT Activity Detected"
  publisher: "Ukraine CERT"
  url: "https://cert.gov.ua/muddywater-activity"
  direct_download_url: "none_found"
  download_type: "alert"
  publication_date: "2021-11-10"
  access_date: "2026-05-22"
  actor_claims: "MuddyWater (Iran/MOIS)"
  source_type: "Government Security News"
  reliability: "Medium"
  relevance: "infrastructure,procedures"
  key_entities: ["MuddyWater","APT","Malware","Ukraine"]
  key_attck_techniques: ["T1566","T1047"]
  source_summary: |
    (If existed) Would describe Ukrainian gov't detections of MuddyWater.
  use_for_project: ""
  limitations: "Likely outdated/irrelevant to Israeli context."
```

# Direct Downloads Table

| Source ID | Title | Direct Download URL |
|---|---|---|
| **AA22-055A** | Iranian Government-Sponsored Actors... (Feb 2022) | [PDF](https://media.defense.gov/2022/Feb/24/2002944274/-1/-1/0/CSA_AA22-055A_Iranian_Government-Sponsored_Actors_Conduct_Cyber_Operations.PDF) |
| **INCD_MuddyWater_Darkbit_20230313** | Iranian Government-Sponsored Threat Actor MuddyWater... (2023) | [PDF](https://www.gov.il/BlobFolder/news/_muddywater/en/government%20threat%20actor.pdf) |
| **INCD_MuddyWater_2024** | Technological Advancement and Evolution of MuddyWater in 2024 | [PDF](https://www.gov.il/BlobFolder/reports/maddy_water_2024/en/ALERT_CERT_IL_W_1858.pdf) |
| **ClearSky_Quicksand_Report_202010** | Operation Quicksand - MuddyWater's Offensive Attack... (2020) | [PDF](https://www.clearskysec.com/wp-content/uploads/2020/10/Operation-Quicksand.pdf) |
| *All others* | *Various blog posts and web pages* | none (no public direct download available) |

# Actor Alias / Overlap Notes

- **MuddyWater (TA450)** is confirmed as an Iranian MOIS APT. Known aliases include *Seedworm*, *Earth Vetala*, *MERCURY*, *Static Kitten*, *TEMP.Zagros*, *Mango Sandstorm*, and *Boggy Serpens*. Microsoft tracks it as *Mango Sandstorm*, Proofpoint as *TA450*, Trend Micro as *Earth Vetala*, etc.. These names should be treated as the same actor in modeling.
- **Overlap with other Iranian actors**: Analysis strongly separates MuddyWater from other clusters. While Proofpoint notes overlapping TTPs among TA450/MuddyWater and APT35/CharmingKitten (TA453, Mint Sandstorm), no source claims direct merger. Similarly, incidents suggest occasional target overlap with APT34/OilRig (e.g. shared victim in utilities), but MuddyWater remains distinct. We do **not** attribute CyberAv3ngers or Agrius to MuddyWater. Only overlaps explicitly supported by sources are noted; e.g. MuddyWater's role as a possible initial-access broker for OilRig/Affiliates in one ESET campaign.

# Procedure Extraction Candidates

**Initial Access (TA1566 Phishing)** - Multiple sources report spear-phishing with malicious attachments/links.
- *Source IDs:* AA22-055A, Proofpoint_TA450_PDF, INCD reports, ESET Snakes, HarfangLab.
- *Evidence:* Observed spearphishing emails with weaponized Office docs or PDFs.
- *ATT&CK:* T1566.001 (malicious links) and T1566.002 (malicious attachments).
- *Required telemetry:* Email gateway and endpoint logs showing receipt of suspicious attachments or links; HTTP logs for downloads from cloud storages (OneDrive, Egnyte).
- *Detection:* Phishing filters, analysis of unusual file downloads (e.g. .ZIP or .EXE from OneDrive links), mail logs from compromised internal accounts (T1078).
- *Validation:* Phishing simulations with similar lure patterns, test of detections on sample PDFs with link to RMM installer.

**Exploitation of Public-Facing Apps (TA1190)** - MuddyWater exploited known vuln CVE-2020-0688 on Exchange to deploy payload.
- *Source IDs:* ClearSky_Quicksand_Blog, AA22-055A.
- *ATT&CK:* T1190 (Exploit Public-Facing App).
- *Telemetry:* Web server logs for POST/GET to aspx pages; event logs for new web shells or suspicious IMAP/HTTP traffic.
- *Detection:* Monitor for use of "/ecp/default.js" exploit chains; WAF/IDS signatures for Exchange CVEs.
- *Validation:* Deploy a test shell exploiting 0688 in a lab, ensure alert triggers on web requests or new files.

**Malicious Library Side-Loading (TA1574.001)** - Attackers used PowGoop (fake Google Update DLL) to load Thanos variant.
- *Source IDs:* ClearSky_Quicksand_Blog, AA22-055A.
- *ATT&CK:* T1574.001 (DLL Search Order Hijacking).
- *Telemetry:* File system and process creation logs; use of DLLs (e.g. goopdate.dll) by signed binaries.
- *Detection:* Endpoint monitoring for unusual loading of googleupdate.dll by GoogleUpdate.exe, or processes creating Scheduled Tasks for .dll execution.
- *Validation:* Test fake DLL side-loading to confirm detection of goopdate.dll loader.

**Scheduled Tasks for Persistence (TA1053.005)** - Both govt and vendor sources note MuddyWater creating tasks to run their malware.
- *Source IDs:* ClearSky_Quicksand_Report, ESET Snakes, HawkEye.
- *ATT&CK:* T1053.005 (Scheduled Task/Job).
- *Telemetry:* Event logs for new scheduled tasks; Sysmon event 1/12 for task creation.
- *Detection:* Alert on task registrations with unusual executables (e.g. googleupdate.exe, Xbin\svchost.exe).
- *Validation:* In a test VM, create a malicious scheduled task and verify SIEM picks it up.

**Use of RMM/Remote Admin Tools (TA1219)** - MuddyWater repeatedly delivers legitimate RMM (AteraAgent, SimpleHelp, PDQ Connect, etc.) for remote control.
- *Source IDs:* Proofpoint_TA450_PDF, ESET Snakes, HarfangLab, Abnormal.
- *ATT&CK:* T1219 (Remote Access Software).
- *Telemetry:* Execution logs (Sysmon) of known RMM binaries from unusual sources; network logs to C2 domains for RMM.
- *Detection:* Block or alert on unsolicited AteraAgent installations, or SMB / remote management sessions initiated by new accounts.
- *Validation:* Deploy AteraAgent on a test host, confirm monitoring of its execution context (e.g. parent process, user, network).

**Credential Stealing and Fake Prompts (TA1056)** - MuddyWater tools show fake Windows Security dialogs to harvest creds.
- *Source IDs:* ESET_Snakes, Abnormal, HawkEye.
- *ATT&CK:* T1056 (Input Capture / GUI Prompt).
- *Telemetry:* EDR detecting process windows popping up; Event logs of logon attempts or suspicious new processes.
- *Detection:* Behavioral monitor for processes creating GUI dialogs requesting credentials, or stealing lsass memory (Mimikatz).
- *Validation:* Use a known credential-stealer to test alerting on fake dialog behavior.

**Proxy/Tunneling (TA1090/T1572)** - Evidence of go-socks5 reverse tunnels and proxy use to hide C2.
- *Source IDs:* AA22-055A, ESET_Snakes.
- *ATT&CK:* T1090 (Proxy), T1572 (Network Traffic via Symm. Encap.).
- *Telemetry:* Network telemetry for outbound unusual SOCKS connections; DNS queries to dynamic domains (e.g. msftconnecttests[.]com as in Israel report).
- *Detection:* Alert on embedded proxy binaries (e.g. Socks5) spawning processes or making unknown connections; block known tunnel domains/URLs.
- *Validation:* Spin up a go-socks5 listener in lab, test detection of outbound connection by MuddyWater binary.

**Lateral Phishing (TA1098)** - Reports of MuddyWater using compromised mailboxes to phish internally.
- *Source IDs:* Abnormal, Proofpoint blogs.
- *ATT&CK:* T1098.005 (Compromised Account/Internal Phishing).
- *Telemetry:* Email logs showing internal emails from valid users with malicious content.
- *Detection:* DLP or SIEM rules to identify unusual internal sender phishing (e.g. user sends EXE, new domain links).
- *Validation:* Simulate internal spearphishing from a compromised account to ensure detection.

# OpenCTI Modeling Candidates

- **Actors**: *MuddyWater (G0069)*, plus its aliases (TA450, Mango Sandstorm, Static Kitten, etc.).
- **Campaigns**: *Operation Quicksand* (ClearSky 2020 Israeli campaign); *Darkbit Incident* (INCD 2023); *RustyWater Campaign* (Rescana/CloudSEK, 2025-26); ongoing "Operation Desert Hydra" (generic label for MuddyWater-Israel ops).
- **Malware/Tools**: *PowGoop* loader, *Thanos* ransomware, *Fooder* loader, *MuddyViper* backdoor, *RustyWater* RAT, *CE-Notes*/ *LP-Notes*/ *Blub* stealers, *go-socks5* tunneler, *BugSleep/MuddyRot* backdoor, *Phoenix* backdoor (Abnormal term), *DarkBit* wiper/ransom, *BugSleep* (Checkpoint/ESET naming), *AteraAgent*, *SyncroRAT*, *PDQConnect*, *SimpleHelp*, *ConnectWise*, *Level*, *VAX-One*, *Cobalt Strike (consensus)*. Also note *Mori* proxy, *MimiC2* (Mimikatz loader).
- **Techniques**: Phishing (T1566.001/.002), Use of legitimate remote admin (T1219), Exploitation of CVE-2020-0688 (T1190), WMI/Proxy execution (CMSTP/Mshta, T1218), Scheduled tasks (T1053.005), DLL sideloading (T1574.001), Living-off-land (LOLBins), Credential dumping (T1003), Reverse shell (T1572/T1090), Credential prompts (T1056).
- **Infrastructure**: Domains/IPs cited (e.g. compromised OneDrive/Egnyte link servers, "microsoftonlines[.]com" for ClickFix, Algerian PLC attacker domains).
- **Victims/Targets**: Israeli government, finance, telecom, academia, energy; UAE/Saudi telecom; U.S. critical infra (as per HawkEye); Gulf states (per HawkEye).
- **Overlaps**: Distinct from APT35/MintSandstorm (targeting dissidents) and APT34/OilRig, but note evidence MuddyWater occasionally shares credentials/tools with OilRig (likely as initial-access brokering).

# Detection Engineering Opportunities

- **RMM Monitoring**: Instrument alerts for unusual use of RMM software executables (AteraAgent, SimpleHelp, ConnectWise) especially when downloaded or installed from email links or cloud storage. Block usage of RMM installers coming via email links.
- **Phishing Link Scanning**: Add detection for URLs hosted on egnyte[.]com, onedrive[.]com, or filehosting sites (OneHub, Mega) that serve payloads. Heuristic email rules for PDF attachments containing external download links (as in TA450 campaign).
- **Fake Windows Dialogs**: Develop detection for processes generating Windows security dialog windows (indicative of credential harvesting) and for automated pop-ups with commands (ClickFix). This could leverage UI automation detection.
- **DLL Sideload Indicators**: Create signatures for GoogleUpdate.exe loading side-sideloaded DLLs (PowGoop) or for use of *CMSTP.exe* with malicious INF (from Attack/MuddyWater research).
- **Emerging Malware**: Write YARA/sigma for newly documented tools (*Fooder loader*, *MuddyViper*, *RustyWater*). For instance, Fooder has the "Snake" game icon and uses the CNG API; RustyWater strings are obfuscated. Incorporate indicators from ESET/Rescana analyses once available.
- **Triage of Internal Emails**: Detect internal emails with executables or admin tools (RMM) as attachments or links, to catch lateral phishing (Abnormal notes high internal engagement).

# Gaps And Manual Review Items

- **Validation of New Malware**: Tools like *RustyWater* (Rescana), *BugSleep* (Checkpoint), and *Fooder/MuddyViper* (ESET) have been reported, but external malware repositories and ICS telemetry should be checked for independent confirmation.
- **OpenCTI Data Ingress**: Some vendor names (Phoenix, DarkBeatC2, PhonyC2) and code names from Israeli docs (AnchorRAT/CannonRat) lack standard IDs; mapping them into ATT&CK or Malware names needs human review.
- **Attribution Ambiguities**: Several sources infer "state destruction" intent (ClearSky on PowGoop/Thanos, Israeli Darkbit for disinfo) - treat these as assessed judgments, not model attributes.
- **Detection Proofs**: Many claimed detection insights (e.g. fake dialogs unique to Iran groups) are not operationalized; we must devise POCs to validate alerts (e.g. simulate the fake-dialog credential theft and ensure detection logic).
- **IOC Availability**: Several reports describe infrastructure (e.g. domains, IPs) without easily-accessible IOCs. Manual extraction from sources (including CTI writes-ups) may be needed. Ensure citation of all IOCs used in modeling.
- **Actor Overlap Assessment**: Confirm that public sources do not merge clusters incorrectly. For example, InfosecWriteups mentions "Boggy Serpens" alias; verify whether to treat it separately. Also, carefully distinguish TA453/TA455 patterns (APT35/CharmingKitten) when ingesting comparative data.
- **Operational Context**: Many sources link MuddyWater ops to current Iran conflicts (Oct 2023 war). Continually review for evolving tactics under geopolitical shifts; this analysis may need updates as new advisories (e.g. CISA AA24-290A) emerge.
