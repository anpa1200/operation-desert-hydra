---
id: phase-4-detection-atlas
title: "Phase 4: Detection Atlas"
sidebar_label: Detection Atlas
---

The detection atlas is the core analytical output. Each of the 11 detection records in [`data/detections.yaml`](https://github.com/anpa1200/operation-desert-hydra/blob/main/data/detections.yaml) contains:

- The specific MuddyWater behavior it targets (not the ATT&CK technique category)
- Required log sources and capability gates
- Multi-rule pseudologic (SIEM-agnostic — works as a template for Sigma, KQL, SPL, or any rule format)
- False positive classes and tuning guidance
- A `creation_logic` field explaining *why* the rule is designed this way — the design decision, not just what the rule does

Coverage scores follow a strict scale: **5** = lab-validated with a Kibana screenshot. **4** = correlated analytic (good logic, single source or partial lab). **3** = behavioral detection with partial validation. A score of 5 requires a proof, not just passing pseudologic.

## Step 20 — Analyst Review

Before any detection went to validation, every record went through a review pass that checked: operator precedence in multi-clause conditions, access mask completeness for LSASS detection, path allowlist accuracy for the GoogleUpdate/Goopdate IoC, and ATT&CK technique coverage gaps. The review fixed a real operator precedence bug in det_mw_0010 Rule B where the `command_line` clause was outside the `event_type` guard, tightened the LSASS access mask set, improved T1033 coverage in det_mw_0009 Rule C via `Win32_ComputerSystem`, and added the x86/x64 Google installation path allowlist to det_mw_0004 Rule A.

![Step 20 — Detection review (det_mw_0001)](/img/proofs/step-20-det-mw-0001.png)

![Step 20 — Detection review (det_mw_0010)](/img/proofs/step-20-det-mw-0010.png)

---

## det_mw_0001 — Email Delivery Correlated with Process Spawn
*Techniques: T1566.001, T1566.002 · Score: 5 (lab-validated)*

**What it targets:** MuddyWater delivers malicious content three ways — ZIP or Office macro attachments, links to Egnyte/OneDrive delivering RMM installers, and emails from compromised accounts. Corroborated by CISA AA22-055A, INCD 2023, and INCD 2024. The highest-priority initial access vector in the dataset.

**Why it's built this way:** Email delivery alone is not a detection signal — MuddyWater's phishing emails are indistinguishable from legitimate mail at the gateway layer. The detection value comes from correlating delivery with a process spawn on the recipient endpoint within a tight 5-minute window. The parent process constraint (Outlook, browser) is the key limiter: it restricts scope to email-triggered or link-triggered execution, which is exactly the documented delivery chain. Both attachment-based and link-based delivery methods are covered because all variants are source-confirmed. The `correlated` logic type reflects that neither event alone is sufficient — only the combination is meaningful.

**Required telemetry:** Email gateway or SEG with attachment metadata and URL extraction. EDR or Sysmon Event ID 1 with parent image and command line. Without the gateway telemetry, this detection degrades to parent-process heuristics only and loses the delivery-correlation value.

```
event_type IN [email_delivery] AND
  (attachment.extension IN ["zip","xlsx","xlsm","pdf","docm"] OR
   link.domain IN ["egnyte.com","onedrive.live.com","1drv.ms"])
CORRELATE WITHIN 300 seconds WITH
event_type IN [process_create] WHERE
  parent_image IN ["OUTLOOK.EXE","chrome.exe","firefox.exe","msedge.exe"] AND
  image IN ["powershell.exe","cmd.exe","wscript.exe","mshta.exe",
            "AteraAgent.exe","ScreenConnect.exe","SimpleHelp.exe","rport.exe"]
```

**Key false positives:** Legitimate macro-enabled Office files from internal users. IT-approved RMM tools deployed via email links during onboarding. Tune by excluding known sender domains and approved RMM deployment windows.

---

## det_mw_0002 — Web Service Spawning Interpreter Shell
*Techniques: T1190 · Score: 5 (lab-validated)*

**What it targets:** MuddyWater uses public-facing exploitation as a secondary initial access vector — CVE-2020-0688 (Exchange), CVE-2020-1472 (Netlogon/Zerologon), CVE-2021-44228 (Log4j), and unspecified VPN vulnerabilities from INCD 2024.

**Why it's built this way:** The detection targets the post-exploitation moment — a web service spawning a shell — rather than the exploit payload itself. This is deliberately CVE-agnostic: it fires on CVE-2020-0688, CVE-2020-1472, Log4j, and any unnamed VPN vulnerability without needing individual exploit signatures. The parent process list maps directly to the documented CVEs: `w3wp.exe` covers Exchange and IIS, `java.exe` covers Log4j, `lsass.exe` covers Netlogon exploitation leading to SYSTEM-level shell creation. The `SYSTEM` integrity level filter is the key noise reducer — legitimate administrative scripts rarely run at SYSTEM under IIS application pools without a clear documented reason.

**Required telemetry:** EDR or Sysmon Event ID 1 with full parent-child chain and integrity level. IDS/IPS for CVE-specific signatures as a complementary layer.

```
event_type = process_create AND
parent_image IN ["w3wp.exe","java.exe","lsass.exe","services.exe",
                 "vmtoolsd.exe","vpnagent.exe"] AND
image IN ["cmd.exe","powershell.exe","wscript.exe","cscript.exe","bash.exe"] AND
(parent_user IN ["NETWORK SERVICE","IIS_IUSRS","SYSTEM"] OR
 integrity_level = "System")
```

**Key false positives:** Legitimate administrative scripts under IIS application pools. Java-based monitoring agents that spawn processes. Tune by process hash allowlisting for known-good management tools.

---

## det_mw_0003 — PowerShell Encoded Command and Script Obfuscation
*Techniques: T1059.001, T1027 · Score: 5 (lab-validated)*

**What it targets:** PowerShell obfuscation is a cross-cutting technique present in every MuddyWater tool tier — PowGoop (Base64 C2 setup), POWERSTATS (IEX + web request for stage delivery), and the 2024 lure campaigns (embedded API key executed via PowerShell). Three distinct usage patterns across tools required three rules.

**Why it's built this way:** Each rule targets a different MuddyWater PowerShell pattern with a different telemetry requirement.

Rule A targets PowGoop and POWERSTATS loader delivery. The regex `\s-e[a-zA-Z]*\s+[A-Za-z0-9+/=]{50,}` is deliberately written to match all unambiguous prefix forms of `-EncodedCommand` (`-e`, `-ec`, `-en`, `-enc`) while the 50-character minimum for the Base64 blob avoids matching the `-Encoding` parameter. This is the operator precision that matters: `-Encoding UTF8` would otherwise match a naive regex.

Rule B targets POWERSTATS script execution behavior: IEX combined with a web request. This is the decoded content layer — it requires Script Block Logging (Event ID 4104), which is the capability gate that determines whether this detection class exists at all in a given environment.

Rule C is the delivery-context fallback: PowerShell spawned by an Office application, email client, or browser has no legitimate explanation in a standard enterprise environment and fires regardless of whether Script Block Logging is enabled.

**Required telemetry:** Script Block Logging (Event ID 4104) — required for Rule B and for the highest-fidelity version of this detection. Sysmon Event ID 1 for Rules A and C. Without Script Block Logging, the detection degrades to command-line heuristics only.

```
# Rule A — Encoded command flag (all prefix forms: -e, -ec, -en, -enc ...)
event_type = process_create AND
image ENDSWITH "powershell.exe" AND
command_line IMATCHES "\s-e[a-zA-Z]*\s+[A-Za-z0-9+/=]{50,}"

# Rule B — Script Block content (Event ID 4104)
event_type = script_block_log AND
script_block_text MATCHES "(IEX|Invoke-Expression|InvokeScript)" AND
script_block_text MATCHES "(WebClient|Invoke-WebRequest|DownloadString|Net\.Http)"

# Rule C — Suspicious parent process
event_type = process_create AND
image ENDSWITH "powershell.exe" AND
parent_image IN ["OUTLOOK.EXE","winword.exe","excel.exe",
                 "chrome.exe","firefox.exe","msedge.exe","WScript.exe"]
```

**Key false positives:** Administrative scripts using `-EncodedCommand` for special characters. SCCM/Ansible deployments running Base64-encoded payloads. Baseline known-good encoded commands by hash before alerting on Rule A.

---

## det_mw_0004 — Unsigned DLL Loaded by Signed Executable
*Techniques: T1574.002 · Score: 3 (behavioral, partial validation)*

**What it targets:** PowGoop's execution method — a malicious DLL renamed `Goopdate.dll` placed alongside `GoogleUpdate.exe`, causing the legitimate signed binary to load it. Confirmed in 2024 toolset by INCD 2024.

**Why it's built this way:** Two rules serve different confidence tiers. Rule A is sourced directly from the documented PowGoop technique: the specific process name (`GoogleUpdate.exe`), DLL name (`Goopdate.dll`), and the fact that any path outside the Google installation directories is anomalous. The allowlist covers both x86 and x64 installation paths because omitting either creates a bypass. This combination — specific binary, specific DLL name, path outside expected directory — is near-unique and fires with high precision. Rule B is the generic behavioral net for future DLL side-loading variants where the actor may use different binary names — it trades precision for coverage against toolset evolution.

Score is 3 (not 5) because the lab's stub DLL did not produce sufficient Sysmon EID 7 signal during validation. The detection logic is sound; the telemetry dependency (Sysmon image load events with signing status) is the constraint.

**Required telemetry:** Sysmon Event ID 7 (ImageLoad) with signed/unsigned status — this is the hard dependency. Without it, DLL loads are invisible to SIEM-based detection.

```
# Rule A — Specific IoC: GoogleUpdate loading Goopdate from non-Google path
event_type = image_load AND
image ENDSWITH "GoogleUpdate.exe" AND
loaded_image ENDSWITH "Goopdate.dll" AND
NOT (loaded_image_path STARTSWITH "C:\Program Files (x86)\Google\" OR
     loaded_image_path STARTSWITH "C:\Program Files\Google\")

# Rule B — Generic: signed process loading unsigned DLL from user-writable path
event_type = image_load AND
process_signed = true AND
loaded_image_signed = false AND
loaded_image_path MATCHES "(\\Users\\|\\AppData\\|\\Temp\\|\\ProgramData\\)"
```

**Key false positives:** Third-party software shipping unsigned DLLs alongside signed executables (common). Developer workstations with locally compiled DLLs. Rule B requires environment-specific tuning before production deployment.

---

## det_mw_0005 — Registry Run Key and Startup Folder Persistence
*Techniques: T1547.001 · Score: 5 (lab-validated)*

**What it targets:** Multiple MuddyWater malware families use Run key persistence with actor-specific value names. Small Sieve: `OutlookMicrosift` (deliberate typo mimicking Microsoft). AA22-055A documents a second key: `SystemTextEncoding`. Canopy installs a WSF script in the startup folder — a sub-technique that doesn't appear as a Run key write.

**Why it's built this way:** Three rules cover three distinct persistence mechanisms across the malware catalog. Rule A is an exact-match IoC alert on the two named value names — it fires immediately on any match without needing path or parent context, because these specific strings have no legitimate usage in a standard enterprise environment. Rule B is the behavioral safety net for unknown or renamed values: path heuristic (AppData/Temp) combined with a non-installer parent covers the common pattern of malware writing its own persistence without using an installer. The `process_integrity_level` filter removes high-integrity (admin-level) processes from the behavioral rule because legitimate software installers typically run elevated. Rule C is added specifically to cover Canopy's startup folder WSF persistence, which doesn't show up as a Run key write at all — it's a file creation event.

**Required telemetry:** Sysmon Event ID 13 (registry value set) for Rules A and B. Sysmon Event ID 11 (file create) for Rule C.

```
# Rule A — Specific IoC: known MuddyWater Run key value names
event_type = registry_set AND
registry_key MATCHES "\\CurrentVersion\\Run" AND
registry_value_name IN ["OutlookMicrosift","SystemTextEncoding"]

# Rule B — Behavioral: Run key pointing to writable/unusual path
event_type = registry_set AND
registry_key MATCHES "(HKCU|HKLM)\\.*\\CurrentVersion\\Run" AND
registry_value_data MATCHES "(\\AppData\\|\\Temp\\|\\ProgramData\\|\\Users\\)" AND
process_image NOT IN ["msiexec.exe","setup.exe","install.exe","update.exe"] AND
process_integrity_level NOT IN ["High","System"]

# Rule C — Script files written to startup folder (covers Canopy WSF)
event_type = file_create AND
file_path MATCHES "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\" AND
file_extension IN ["wsf","vbs","js","ps1","bat","cmd"]
```

**Key false positives:** Rule A has essentially zero false positives on the specific value names. Rule B requires installer process exclusion — the list is environment-specific. Rule C may fire on legitimate startup scripts deployed by IT via Group Policy; exclude by file hash or signer.

---

## det_mw_0006 — Scheduled Task with 43-Minute Beacon Interval
*Techniques: T1053.005 · Score: 4 (correlated analytic)*

**What it targets:** BugSleep creates a Windows scheduled task triggered every 43 minutes for C2 beaconing — a specific behavioral fingerprint documented in the INCD 2024 report. The interval is documented as customizable, but 43 minutes is the observed operational value.

**Why it's built this way:** The 43-minute interval is the single most precise artifact in the entire procedure dataset. Rule A is designed as a high-fidelity immediate alert requiring no tuning: `PT43M` is the ISO 8601 duration format for 43 minutes and appears verbatim in the Windows Task XML. This fires with near-zero false positives because no legitimate software uses a 43-minute repeat interval for any standard purpose. Rule B generalizes the pattern for future BugSleep variants that may use a different interval: short repetition (under 60 minutes) combined with a task action pointing to a user-writable path is anomalous regardless of exact interval. Rule C is the telemetry fallback — many environments do not forward Task Scheduler event logs to SIEM, but `schtasks.exe` process creation (Sysmon EID 1) is more commonly collected and captures the command line.

Score is 4 (not 5) because this is a single-source procedure — INCD 2024 only. Before treating Rule A as a high-confidence production alert, corroborate with a second vendor source.

**Required telemetry:** Windows Security Event ID 4698 (scheduled task created) or Task Scheduler operational log for Rules A and B. Sysmon Event ID 1 for Rule C.

```
# Rule A — Specific: 43-minute interval (BugSleep artifact) — immediate alert
event_type = scheduled_task_created AND
task_trigger_repetition_interval = "PT43M"

# Rule B — Behavioral: short interval + suspicious action path
event_type = scheduled_task_created AND
task_trigger_repetition_interval_minutes < 60 AND
task_action_path MATCHES "(\\AppData\\|\\Temp\\|\\ProgramData\\|\\Users\\)" AND
creating_process NOT IN ["svchost.exe","taskeng.exe","msiexec.exe"]

# Rule C — Sysmon command line fallback
event_type = process_create AND
image ENDSWITH "schtasks.exe" AND
command_line MATCHES "/create" AND
command_line MATCHES "(AppData|Temp|ProgramData)"
```

**Key false positives:** Backup and monitoring software creating frequent tasks. Browser update mechanisms. Rule B requires interval baseline per environment before production deployment.

---

## det_mw_0007 — RMM Tool Executed from User-Writable Path
*Techniques: T1219 · Score: 5 (lab-validated)*

**What it targets:** RMM tool abuse is the most consistently documented MuddyWater technique across all source tiers — five independent government and vendor sources corroborate it. Tool inventory across campaigns: ScreenConnect (2022), SyncroRAT (Israel 2023), rport.exe (DarkBit operation), AteraAgent (multiple sources), SimpleHelp, Level, PDQConnect (2024).

**Why it's built this way:** RMM tool detection is inherently a context problem. The binary is legitimate. The network traffic to vendor infrastructure is legitimate. Only the delivery chain and execution path are anomalous. Three rules address this from different angles.

Rule A uses path as the primary signal: a legitimately IT-deployed RMM tool installs to Program Files or a managed path, not AppData/Temp/Downloads. A known RMM binary executing from a user-writable path means it was delivered, not installed by IT.

Rule B uses parent process as the signal: no legitimate RMM deployment is spawned by Outlook, a browser, or an archive utility. This is the delivery-context constraint — if an RMM binary's parent is `OUTLOOK.EXE`, the delivery chain is phishing regardless of what the binary is.

Rule C uses network destination: RMM infrastructure connections from endpoints with no authorized RMM deployment are anomalous. Rules A+C together — RMM binary from writable path plus outbound connection to vendor domain — form the highest-confidence combined signal.

**The baseline prerequisite is non-negotiable.** Rule C without a baseline of authorized RMM deployments per endpoint generates constant noise in any environment that legitimately uses RMM tools. This is the single highest-ROI detection in the dataset if the baseline is clean.

**Required telemetry:** EDR or Sysmon Event ID 1 with parent image and file path. Network flow or proxy logs with process name attribution for Rule C.

```
# Rule A — Known RMM binary from non-standard installation path
event_type = process_create AND
(image ENDSWITH "AteraAgent.exe" OR
 image ENDSWITH "ScreenConnect.exe" OR
 image ENDSWITH "SimpleHelp.exe" OR
 image ENDSWITH "rport.exe" OR
 image ENDSWITH "SyncroRAT.exe" OR
 image ENDSWITH "Level.exe" OR
 image ENDSWITH "PDQConnect.exe") AND
image_path MATCHES "(\\AppData\\|\\Temp\\|\\Downloads\\|\\Users\\[^\\]+\\Desktop\\)"

# Rule B — RMM binary spawned by email client or browser
event_type = process_create AND
(image ENDSWITH "AteraAgent.exe" OR image ENDSWITH "ScreenConnect.exe" OR
 image ENDSWITH "SimpleHelp.exe" OR image ENDSWITH "rport.exe") AND
parent_image IN ["OUTLOOK.EXE","outlook.exe","chrome.exe","firefox.exe",
                 "msedge.exe","7zFM.exe","WinRAR.exe","explorer.exe"]

# Rule C — Outbound connection to RMM vendor infrastructure from unexpected endpoint
event_type = network_connection AND
destination_domain MATCHES "(atera\.com|screenconnect\.com|simplehelp\.net|syncromsp\.com)" AND
source_process NOT IN [known_rmm_processes_baseline]
```

**Key false positives:** All RMM tools are legitimate software — the entire detection depends on delivery context and path. Authorized deployments must be baselined per endpoint before any rule produces useful signal. Help desk technicians installing RMM from their downloads folder will match Rule A; exclude by user account or machine type.

---

## det_mw_0008a — Non-Browser Process Connecting to Telegram Bot API
*Techniques: T1071.001, T1102 · Score: 3 (behavioral, partially validated)*

**What it targets:** Small Sieve beacons exclusively via the Telegram Bot API (`api.telegram.org`) over HTTPS. This is one of the most specific C2 channels documented for MuddyWater — a fixed, known hostname with no CDN rotation.

**Why it's built this way:** The detection is single-rule because the signal is specific enough not to need graduated fallbacks. `api.telegram.org` is a fixed hostname. The discriminating condition is not the domain but the process: in enterprise environments where Telegram is not a standard application, any process connecting to this endpoint is anomalous. The approach is deliberately narrow — it will miss if MuddyWater switches from Telegram to another messaging API, but fires with high precision on the documented Small Sieve C2 channel.

Score is 3 because VirtualBox NAT blocked outbound Telegram connections in the lab, preventing full Kibana validation of the network connection event.

**Required telemetry:** DNS query logs or network flow logs with process name attribution. In environments without process-attributed network telemetry, this degrades to a domain-based alert with no process context.

```
event_type = network_connection AND
destination_domain = "api.telegram.org" AND
destination_port = 443 AND
source_process NOT IN ["Telegram.exe","telegram.exe","chrome.exe",
                        "firefox.exe","msedge.exe","iexplore.exe"]
```

**Key false positives:** Telegram desktop application where it is approved. Bot developers testing scripts from dev workstations. In organizations where Telegram is standard, strict process allowlisting is required before this detection is useful.

---

## det_mw_0008b — DNS Tunneling Volume and Entropy
*Techniques: T1572 · Score: 5 (lab-validated)*

**What it targets:** Mori, MuddyWater's DNS-tunneling backdoor, uses DNS queries as the C2 channel. DNS tunneling encodes data in subdomain labels, producing distinctive patterns: high query volume to a single domain, unusually long subdomain strings, and high Shannon entropy in the label content.

**Why it's built this way:** DNS tunneling detection cannot rely on a single heuristic because each heuristic has a different failure mode. Volume (Rule A) catches high-throughput tunneling but misses slow/low-rate tools that deliberately throttle to blend in. Label length (Rule B) catches encoded payloads regardless of rate or entropy but misses short encoded segments. Entropy (Rule C) catches random-looking subdomains at any length and rate but produces noise on CDN hash labels without a comprehensive baseline. The three rules are additive — any single trigger warrants investigation, two or more from the same source are high-confidence.

The thresholds (>100 queries per 60 seconds, >40-character labels, >3.5 Shannon entropy) were validated in the lab by generating 180 DNS queries with 42-character random subdomains from the simulation playbook.

**Required telemetry:** DNS resolver logs with full QNAME — not available in all environments. If only DNS flow logs (not query content) are available, Rule B and Rule C are unavailable.

```
# Rule A — High query volume to single parent domain
event_type = dns_query
GROUP BY source_ip, query_domain_parent
HAVING COUNT(*) > 100 WITHIN 60 seconds

# Rule B — Long subdomain labels (>40 chars indicates encoded payload)
event_type = dns_query AND
LENGTH(subdomain_label) > 40

# Rule C — High entropy subdomains (random-looking encoded content)
event_type = dns_query AND
SHANNON_ENTROPY(subdomain_label) > 3.5 AND
subdomain_label NOT IN [known_cdn_domains_baseline]
```

**Key false positives:** CDN domains using hash-based subdomains (Akamai, Cloudflare, AWS) — require comprehensive allowlist for Rule C. DNSSEC validation traffic with long encoded keys. Calibrate thresholds against your specific environment's DNS baseline before deploying Rule A in production.

---

## det_mw_0009 — WMI SecurityCenter2 Discovery Survey
*Techniques: T1047, T1082, T1016, T1033, T1518.001 · Score: 5 (lab-validated)*

**What it targets:** CISA AA22-055A reproduces the exact PowerShell survey script MuddyWater uses post-access: a WMI query chain that collects IP addresses (`Win32_NetworkAdapterConfiguration`), OS name and architecture (`Win32_OperatingSystem`), hostname, domain, username (`Win32_ComputerSystem`), and AV product names (`root\SecurityCenter2\AntiVirusProduct`). The collected data is assembled into a delimited string, encoded, and sent to C2.

**Why it's built this way:** The detection anchors on `SecurityCenter2\AntiVirusProduct` because it is the highest-specificity WMI class in the documented survey. The other classes — OS name, IP addresses, hostname — are queried by dozens of legitimate monitoring tools. AntiVirusProduct enumeration has a much smaller legitimate caller population: primarily AV management consoles and endpoint security platforms. This makes it the most reliable low-noise signal from the full survey chain.

Three rules are layered by telemetry quality. Rule A requires Script Block Logging (highest fidelity, decoded script content visible). Rule B falls back to command-line logging — medium fidelity, only fires if `SecurityCenter2` appears in the literal command line, not in a decoded payload. Rule C is the most specific: a multi-class pattern that matches the complete documented survey chain, covering all five ATT&CK techniques in a single event. T1033 coverage was added to Rule C via `Win32_ComputerSystem` during the analyst review pass — it was missing from the initial draft.

Rule C matches the CISA-documented script closely enough to be treated as near-exact-match when observed.

**Required telemetry:** Script Block Logging (Event ID 4104) — required for Rules A and C. Sysmon Event ID 1 for Rule B.

```
# Rule A — Script Block captures SecurityCenter2 query
event_type = script_block_log AND
script_block_text MATCHES "SecurityCenter2" AND
script_block_text MATCHES "AntiVirusProduct"

# Rule B — Process command line contains SecurityCenter2 (fallback without SBL)
event_type = process_create AND
image ENDSWITH "powershell.exe" AND
command_line MATCHES "SecurityCenter2"

# Rule C — Full survey pattern: all 5 ATT&CK techniques in one event
# T1518.001 (AV enum) + T1016 (network config) + T1082 (OS info) + T1033 (username)
event_type = script_block_log AND
script_block_text MATCHES "SecurityCenter2" AND
script_block_text MATCHES "Win32_NetworkAdapterConfiguration" AND
script_block_text MATCHES "Win32_OperatingSystem" AND
script_block_text MATCHES "(Win32_ComputerSystem|Win32_UserAccount|UserName)"
```

**Key false positives:** AV management software and endpoint security platforms querying SecurityCenter2. IT inventory tools (Lansweeper, SCCM hardware inventory). Exclude by process hash or signer rather than by process name, since attackers can rename their scripts.

---

## det_mw_0010 — LSASS Memory Access and Credential Tool Execution
*Techniques: T1003.001, T1003.004, T1003.005 · Score: 5 (lab-validated)*

**What it targets:** MuddyWater performs credential access using three tools documented in CISA AA22-055A: Mimikatz and procdump64.exe against LSASS memory (T1003.001), and LaZagne for LSA secrets (T1003.004) and cached domain credentials (T1003.005).

**Why it's built this way:** Three independent rules cover the full credential dumping lifecycle, each with a different detection philosophy.

Rule A is the design priority: a process accessing LSASS memory is the universal pre-condition for any LSASS dump, regardless of tool. Detecting the access event (Sysmon EID 10) rather than the tool name means Rule A fires on Mimikatz, procdump, custom C++ loaders, and any future variant — as long as the access mask is in the covered set. The access masks were sourced from established Mimikatz research (0x1010, 0x1410, 0x1438, 0x143a, 0x1418) and extended with 0x1fffff (PROCESS_ALL_ACCESS, used by custom dumpers) and 0x1f0fff (another all-access variant observed in the field). The exclusion list covers known legitimate callers — AV engines, CSrss, WinInit — without which this rule generates constant noise from endpoint security products.

Rule B is the name-based backstop. Lower fidelity because it misses renamed tools, but catches actors using stock Mimikatz. The analyst review pass re-bracketed the `command_line` clause to keep it inside the `event_type` guard — a real operator precedence bug that would have caused the command-line check to match events outside the process_create filter.

Rule C catches the dump artifact on disk — a final fallback when process-level events are unavailable. `.dmp` files in user-writable paths are anomalous outside of Windows Error Reporting, which writes to a fixed known path.

**Required telemetry:** Sysmon Event ID 10 (ProcessAccess) with explicit `lsass.exe` targeting in the Sysmon configuration — this is not enabled by default. Without it, Rule A does not exist. Sysmon Event ID 1 for Rule B. Sysmon Event ID 11 for Rule C.

```
# Rule A — LSASS process access (tool-agnostic, highest confidence)
event_type = process_access AND
target_image ENDSWITH "lsass.exe" AND
granted_access MATCHES "(0x1010|0x1410|0x1438|0x143a|0x1418|0x1fffff|0x1f0fff)" AND
source_image NOT IN ["MsMpEng.exe","csrss.exe","wininit.exe","svchost.exe",
                     "SecurityHealthService.exe","CylanceSvc.exe","SentinelAgent.exe"]

# Rule B — Known credential tool execution (name-based backstop)
# command_line clause is bracketed inside event_type guard (bug fix in review)
event_type = process_create AND
(image IMATCHES "mimikatz\.exe" OR
 image ENDSWITH "procdump64.exe" OR
 image IMATCHES "lazagne\.exe" OR
 command_line IMATCHES "(sekurlsa|lsadump|privilege::debug)")

# Rule C — Dump file creation in user-writable path (artifact backstop)
event_type = file_create AND
file_extension = "dmp" AND
file_path MATCHES "(\\AppData\\|\\Temp\\|\\Users\\|\\ProgramData\\)"
```

**Key false positives:** AV and EDR agents that legitimately access LSASS — exclude by process hash, not name, since names are spoofable. Windows Error Reporting creating `.dmp` files in `%TEMP%\WER` — exclude that specific path in Rule C. Legitimate procdump usage by developers for application crash diagnostics — require a separate approved-tools baseline.

**Important environment note:** Credential Guard and PPL (Protected Process Light) prevent LSASS reads on modern, hardened systems. If your environment has these enabled, LSASS dump detection is still valuable as a canary for misconfigured or unpatched endpoints, but confirm protection status before using coverage scores here as a measure of actual protection.
