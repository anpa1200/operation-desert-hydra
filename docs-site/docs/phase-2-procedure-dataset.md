---
id: phase-2-procedure-dataset
title: "Phase 2: Procedure Dataset"
sidebar_label: Procedure Dataset
---

![The 10 Procedures — MuddyWater procedure-level dataset](/img/10-procedures-infographic.png)

A procedure record is not an ATT&CK technique. ATT&CK describes what a class of actors *can* do. A procedure record describes what *this actor* did, in *this campaign*, as documented by *this source*, with a specific evidence label attached.

The distinction matters for detection. "Adversaries use scheduled tasks (T1053.005)" does not help you tune a detection rule. "BugSleep creates a scheduled task with a 43-minute repeat interval (INCD 2024, Observed)" does — because you now have a concrete interval to hunt for, a specific tool name, and a source you can cite in your detection rationale.

Each of the 10 records in [`data/procedures.yaml`](https://github.com/anpa1200/operation-desert-hydra/blob/main/data/procedures.yaml) captures four things:

- The specific behavior — not the technique category
- The source references that support it, with evidence labels
- Candidate ATT&CK technique mappings and the reasoning behind each candidate
- Required telemetry, a detection idea, validation plan, and known limitations

## Confidence Labels

Each record carries one of four evidence labels inherited from the source assessment:

**Observed** — the behavior appears directly in source telemetry, a recovered sample, a screenshot, or a government incident report with direct visibility into the event. This is the strongest label and the only one that justifies a high-priority detection without further corroboration.

**Reported** — a source states the behavior occurred, but the evidence is assertion-level rather than artifact-level. Still usable; requires corroboration before relying on it alone.

**Assessed** — the source draws an analytical conclusion based on multiple indicators. Appropriate for ATT&CK candidate mappings; not sufficient alone for a new detection claim.

**Inferred** — analyst conclusion derived from combining multiple reported facts across sources. Weakest label; flag for review before using in production.

All 10 procedures in this dataset carry **Observed** or **High** confidence. That is not a coincidence — it reflects the promotion threshold. Procedures that came only from secondary or inferred sources were not promoted into `data/procedures.yaml`; they stayed in the claim extraction notes for future work.

## The 10 Procedures

### proc_mw_0001 — Spearphishing Email Delivery
*Confidence: Observed · Sources: AA22-055A, INCD 2023, INCD 2024 · ATT&CK: T1566.001, T1566.002, T1534*

Three delivery variants documented across all three primary government sources: ZIP attachments containing macro-enabled Excel files or PDFs; email links to Egnyte or OneDrive delivering compressed RMM installers; and emails sent from compromised legitimate accounts to increase lure credibility. In 2024, a Microsoft-update-lure campaign sent to 10,000+ accounts embedded a PowerShell API key, granting the actor direct agent access immediately after the RMM tool installed. Three independent government sources corroborate this procedure — it is the highest-confidence initial access vector in the dataset.

### proc_mw_0002 — Public-Facing Exploitation
*Confidence: Observed · Sources: AA22-055A, INCD 2023, INCD 2024 · ATT&CK: T1190*

Secondary initial access vector to phishing. Documented CVEs: CVE-2020-1472 (Netlogon/Zerologon), CVE-2020-0688 (Exchange), CVE-2021-44228 (Log4j), and unspecified VPN vulnerabilities confirmed by INCD 2024. Exploitation is typically followed by RMM tool deployment or custom backdoor staging. The VPN claim from INCD 2024 does not name a specific CVE — treat as Reported until a CVE is attributed.

### proc_mw_0003 — PowerShell Execution and Script Obfuscation
*Confidence: Observed · Sources: AA22-055A, INCD 2024 · ATT&CK: T1059.001, T1027*

Cross-cutting technique present in every tool tier. PowGoop uses an obfuscated `.dat` + `config.txt` PowerShell chain for C2 beaconing. POWERSTATS is a persistent PowerShell backdoor. The 2024 lure embedded an API key executed via PowerShell to grant direct agent access. Obfuscation is applied consistently via Base64, XOR, and custom encoding. Detection anchor: Script Block Logging (EID 4104) is the primary telemetry dependency — without it, this procedure is nearly invisible to endpoint-only detection.

### proc_mw_0004 — DLL Side-Loading
*Confidence: Observed · Sources: AA22-055A, INCD 2024 · ATT&CK: T1574.002*

PowGoop's canonical execution method: a malicious DLL renamed `Goopdate.dll` placed alongside `GoogleUpdate.exe`, causing the legitimate signed binary to load and execute the malicious DLL. INCD 2024 confirms continued use across the 2024 toolset. Detection requires Sysmon EID 7 (image load) with signing status — not available from Windows Event Log alone. This is the most telemetry-constrained procedure in the dataset; validation was PARTIAL because the lab's stub DLL did not produce sufficient EID 7 signal.

### proc_mw_0005 — Registry Run Key and Startup Folder Persistence
*Confidence: Observed · Sources: AA22-055A, INCD 2024 · ATT&CK: T1547.001*

Small Sieve adds `index.exe` under the Run key named `OutlookMicrosift` — mimicking a Microsoft application name. Canopy installs its first WSF script in the startup folder. AA22-055A documents an additional key: `SystemTextEncoding`. INCD 2024 confirms continued use. The specific key names (`OutlookMicrosift`, `SystemTextEncoding`) are high-confidence IoCs when present; a detection based only on "new Run key written by a non-installer" will generate noise in most enterprise environments.

### proc_mw_0006 — Scheduled Task (43-Minute Beacon)
*Confidence: Observed · Source: INCD 2024 (single source) · ATT&CK: T1053.005*

BugSleep creates a Windows scheduled task triggered every 43 minutes for C2 beaconing. The interval is documented as customizable, but 43 minutes is the specific value observed in the INCD 2024 analysis. This is a single-source procedure — INCD 2024 only — which is why it carries a coverage score of 4 (correlated analytic) rather than 5 in the detection atlas. Before treating this interval as a high-confidence fingerprint in production, corroborate with a vendor source.

### proc_mw_0007 — RMM Tool Abuse
*Confidence: Observed · Sources: AA22-055A, INCD 2023, INCD 2024, multiple vendor sources · ATT&CK: T1219*

The most consistently documented technique across all source tiers — five independent government and vendor sources corroborate it. Tool inventory across campaigns: ScreenConnect (2022), SyncroRAT (Israel 2023), rport.exe (DarkBit operation), AteraAgent (multiple vendor sources), SimpleHelp, Level, PDQConnect (2024). The 2024 lure embedded an API key so the actor had direct agent access the moment the victim installed the tool. Detection must rely on delivery context and parent process — not binary name alone, since these are legitimate commercial tools.

### proc_mw_0008 — C2 via Web Protocols and DNS Tunneling
*Confidence: Observed · Sources: AA22-055A, INCD 2024 · ATT&CK: T1071.001, T1572, T1102*

Multiple C2 channels documented. Small Sieve beacons via Telegram Bot API over HTTPS. Canopy sends collected data via HTTP POST. Blackout uses GET `/questions` and POST `/about-us`. AnchorRAT communicates over HTTPS port 443 in JSON format. Mori uses DNS tunneling. In 2024, Rentry.co was used as a legitimate platform for C2 redirection. The Telegram API is the highest-confidence detection anchor: outbound HTTPS to `api.telegram.org` from a non-browser process is unusual in enterprise environments and directly attributed across multiple sources.

### proc_mw_0009 — WMI System Discovery Survey
*Confidence: Observed · Source: AA22-055A (script documented verbatim) · ATT&CK: T1047, T1082, T1016, T1033, T1518.001*

MuddyWater runs a PowerShell script that queries WMI to collect: IP addresses (`Win32_NetworkAdapterConfiguration`), OS name and architecture (`Win32_OperatingSystem`), hostname, domain, username, and AV product names (`root\SecurityCenter2\AntiVirusProduct`). The collected data is assembled into a delimited string, encoded, and sent to C2. The exact script is reproduced in the CISA advisory. The `SecurityCenter2` query is the detection anchor: legitimate enterprise software rarely queries this WMI namespace outside AV management contexts, making it a low-noise signal.

### proc_mw_0010 — Credential Dumping from LSASS and Credential Stores
*Confidence: Observed · Source: AA22-055A · ATT&CK: T1003.001, T1003.004, T1003.005*

Post-access credential access using three tools: Mimikatz and procdump64.exe against LSASS memory (T1003.001); LaZagne for LSA secrets (T1003.004) and cached domain credentials (T1003.005). Used post-exploitation to enable lateral movement with harvested credentials. Detection via Sysmon EID 10 (process accessing lsass.exe) is tool-agnostic — it fires regardless of whether the actor uses Mimikatz, procdump, or a custom variant with a different binary name. This is the most reliable detection path for this procedure.
