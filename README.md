# Operation Desert Hydra

**Public-source CTI → OpenCTI knowledge graph → Detection engineering → Lab validation**

A complete, reproducible pipeline that takes public-source threat intelligence about **MuddyWater (Iranian MOIS)** and converts it into analyst-reviewed, SOC-usable detection artifacts — all version-controlled, all deployable from a single clone.

---

## What This Repo Contains

```
operation-desert-hydra/
├── start.sh                    # Start everything (OpenCTI + Kibana + lab VM)
├── stop.sh                     # Stop everything (halt or destroy)
│
├── stack/                      # Docker Compose stack (OpenCTI + Elasticsearch + Kibana)
│   ├── docker-compose.yml
│   ├── docker-compose.kibana.yml
│   └── .env.template           # Copy to .env and fill secrets
│
├── lab/                        # Detection validation lab
│   ├── Vagrantfile             # Windows 10 VM (ws01)
│   ├── Makefile                # make up / validate / down / destroy
│   └── ansible/
│       ├── playbooks/
│       │   ├── deploy.yml      # Provision VM (Sysmon, PS logging, Winlogbeat)
│       │   └── validate.yml    # Run 11 benign detection simulations
│       └── roles/              # sysmon / winlogbeat / audit_logging
│
├── data/                       # Structured intelligence dataset (YAML)
│   ├── sources.yaml            # Source register with confidence tiers
│   ├── procedures.yaml         # 10 procedure records (proc_mw_0001–0010)
│   ├── detections.yaml         # 11 detection records with coverage scores
│   └── validation-results.yaml # Phase 5 lab validation output
│
├── detections/                 # Detection logic by format
│   ├── sigma/                  # Sigma rules
│   ├── kql/                    # Kibana KQL queries
│   ├── elastic/                # Elastic rule JSON
│   └── spl/                    # Splunk SPL
│
├── docs/
│   ├── article-step-0-project-scenario.md   # Full project walkthrough (Phases 1–8)
│   ├── medium-article.md                     # Publication-ready Medium article
│   └── proofs/
│       ├── phase-3/            # OpenCTI graph screenshots (Steps 10–19)
│       ├── phase-4/            # Detection atlas review screenshots (Step 20)
│       └── phase-5/            # Kibana validation proofs (Steps 21–31)
│
└── tools/                      # OpenCTI import scripts
```

---

## Quick Start

### Prerequisites

| Tool | Version | Purpose |
|------|---------|---------|
| Docker + Compose plugin | 24+ | OpenCTI + Kibana stack |
| VirtualBox | 7.x | Lab VM hypervisor |
| Vagrant | 2.4+ | VM lifecycle management |
| Ansible | 9+ | VM provisioning + simulation |
| Python 3 + pywinrm | any | Ansible WinRM transport |

```bash
# Ubuntu / Debian
sudo apt install docker.io docker-compose-plugin virtualbox vagrant ansible
pip3 install pywinrm
```

### Deploy

```bash
# 1. Clone
git clone https://github.com/anpa1200/operation-desert-hydra.git
cd operation-desert-hydra

# 2. Configure secrets
cp stack/.env.template stack/.env
$EDITOR stack/.env          # fill in passwords and tokens

# 3. Start everything
bash start.sh
```

`start.sh` does:
1. Creates the `opencti_network` Docker network
2. Starts OpenCTI + Elasticsearch + Kibana + Redis + MinIO + RabbitMQ
3. Waits for Elasticsearch to be healthy
4. Brings up the Windows 10 Vagrant VM (`ws01`)
5. Provisions it via Ansible (Sysmon 15.x, Script Block Logging, Winlogbeat 8.13)
6. Runs all 11 detection simulations and prints results

### Options

```bash
bash start.sh --skip-lab        # Start OpenCTI stack only (no VM)
bash start.sh --skip-validate   # Deploy VM but skip simulations
bash stop.sh                    # Halt VM, leave stack running
bash stop.sh --destroy-vm       # Destroy VM disk
bash stop.sh --destroy-stack    # Stop Docker stack too
```

---

## Lab Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        HOST MACHINE (Linux)                              │
│                                                                          │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │                  Docker: opencti_network                          │   │
│  │                                                                   │   │
│  │   ┌─────────┐   ┌───────────────┐   ┌──────┐   ┌───────────┐   │   │
│  │   │ OpenCTI │──▶│ Elasticsearch │   │Redis │   │ RabbitMQ  │   │   │
│  │   │  :8080  │   │    :9200      │   │:6379 │   │   :5672   │   │   │
│  │   └─────────┘   └──────┬────────┘   └──────┘   └───────────┘   │   │
│  │                        │                                          │   │
│  │   ┌─────────┐          │  ┌───────┐                              │   │
│  │   │  Kibana │──────────┤  │ MinIO │                              │   │
│  │   │  :5601  │          │  │ :9001 │                              │   │
│  │   └─────────┘          │  └───────┘                              │   │
│  └────────────────────────┼─────────────────────────────────────────┘   │
│                           │ port 9200 exposed to host                    │
│                           │                                              │
│          ┌────────────────┴──────────────────────────────┐              │
│          │  VirtualBox NAT gateway: 10.0.2.2              │              │
│          │                                                │              │
│          │  ┌──────────────────────────────────────────┐ │              │
│          │  │         ws01 — Windows 10                │ │              │
│          │  │         hostname: DESERTWS01             │ │              │
│          │  │                                          │ │              │
│          │  │  Sysmon 15.x          ──logs──▶          │ │              │
│          │  │  Winlogbeat 8.13      ──────▶ 10.0.2.2:9200              │
│          │  │  Script Block Logging (EID 4104 enabled) │ │              │
│          │  │  ProcessAccess (EID 10 for LSASS)        │ │              │
│          │  │  ImageLoad    (EID 7)                    │ │              │
│          │  │  DNS events   (EID 22)                   │ │              │
│          │  │                                          │ │              │
│          │  │  WinRM :55985 ◀── Ansible (host)         │ │              │
│          │  └──────────────────────────────────────────┘ │              │
│          └────────────────────────────────────────────────┘              │
└─────────────────────────────────────────────────────────────────────────┘
```

### Component Roles

| Component | Role | URL / Port |
|-----------|------|-----------|
| OpenCTI 6.2 | CTI knowledge graph — intrusion sets, campaigns, malware, ATT&CK relationships | :8080 |
| Elasticsearch 8.13 | Log storage — receives Winlogbeat events from lab VM; also OpenCTI backend | :9200 |
| Kibana 8.13 | Detection proof — KQL queries against Winlogbeat index for validation screenshots | :5601 |
| Redis 7.2 | OpenCTI session / queue backend | :6379 |
| MinIO | OpenCTI file storage | :9001 |
| RabbitMQ 3.13 | OpenCTI worker message bus | :5672 |
| ws01 (Windows 10) | Endpoint under test — Sysmon + Winlogbeat installed by Ansible | WinRM :55985 |

### Log Flow

```
Windows Event Log (Sysmon EID 1/7/10/11/13/22, PS EID 4104)
         │
    Winlogbeat 8.13
         │  HTTPS → 10.0.2.2:9200
         ▼
    Elasticsearch  ←→  Kibana (KQL detection queries)
         │
    OpenCTI (knowledge graph backend shares the same ES instance)
```

---

## Detection Coverage

| ID | Detection | Score | ATT&CK |
|----|-----------|:-----:|--------|
| det_mw_0001 | Email delivery → process spawn correlation | 5 | T1566.001, T1566.002 |
| det_mw_0002 | Web service spawning interpreter shell | 5 | T1190 |
| det_mw_0003 | PowerShell encoded command / IEX script block | 5 | T1059.001, T1027 |
| det_mw_0004 | Unsigned DLL loaded by signed executable | 3 | T1574.002 |
| det_mw_0005 | Registry Run key / Startup folder persistence | 5 | T1547.001 |
| det_mw_0006 | Scheduled task — 43-minute interval | 4 | T1053.005 |
| det_mw_0007 | RMM binary from user-writable path | 5 | T1219 |
| det_mw_0008a | Non-browser process → Telegram Bot API | 3 | T1071.001, T1102 |
| det_mw_0008b | DNS tunneling — volume / label entropy | 5 | T1572 |
| det_mw_0009 | PowerShell WMI query to SecurityCenter2 | 5 | T1047, T1082, T1016, T1033, T1518.001 |
| det_mw_0010 | LSASS memory access / credential tool execution | 5 | T1003.001, T1003.004, T1003.005 |

**Scores:** 5 = lab-validated | 4 = correlated analytic | 3 = behavioral (partial validation)

**Lab results:** 13 PASS / 1 PARTIAL / 1 FAIL across 16 rule checks

---

## Validation Proofs

All Kibana screenshots are in `docs/proofs/phase-5/`:

| File | What it proves |
|------|---------------|
| step-21-det-mw-0001.png | EID 1 — wscript.exe → powershell.exe -EncodedCommand |
| step-22-det-mw-0002.png | EID 1 — wscript.exe → cmd.exe recon chain |
| step-23a-det-mw-0003-rule-a.png | EID 1 — powershell.exe -e + Base64 blob |
| step-23b-det-mw-0003-rule-b.png | EID 4104 — IEX + DownloadString |
| step-25a-det-mw-0005-rule-a.png | EID 13 — OutlookMicrosift Run key |
| step-25c-det-mw-0005-rule-c.png | EID 11 — WSF in Startup folder |
| step-26-det-mw-0006.png | EID 1 — schtasks.exe /mo 43 |
| step-27-det-mw-0007.png | EID 1 — ScreenConnect.exe from \Temp\ |
| step-29-det-mw-0008b.png | EID 22 — 180 DNS queries, 42-char random labels |
| step-30a-det-mw-0009-rule-a.png | EID 4104 — SecurityCenter2 WMI query |
| step-31a-det-mw-0010-rule-a.png | EID 10 — lsass.exe GrantedAccess 0x1400 |
| step-31c-det-mw-0010-rule-c.png | EID 11 — lsass_test.dmp file creation |

---

## Project Phases

| Phase | Deliverable | Status |
|-------|------------|--------|
| 1 | Source register (8 government + vendor sources, confidence-tiered) | Done |
| 2 | Procedure dataset (10 records, analyst-reviewed) | Done |
| 3 | OpenCTI knowledge graph (intrusion set, campaigns, malware, ATT&CK) | Done |
| 4 | Detection atlas (11 detections with pseudologic, FPs, creation logic) | Done |
| 5 | Safe validation lab (Ansible playbook, 12 Kibana proofs) | Done |
| 6 | Coverage matrix (22 ATT&CK techniques, 6 capability gates, gap analysis) | Done |
| 7 | Final report (methodology → source base → coverage → limitations → next work) | Done |
| 8 | Executive summary (defender-facing priorities and telemetry gaps) | Done |

Full walkthrough: [`docs/medium-article.md`](docs/medium-article.md)

---

## Data Pipeline — Real Records

Every claim in this project is traceable from raw source through to detection. The pipeline is:

```
sources.yaml  →  claims.yaml  →  procedures.yaml  →  detections.yaml
```

**Source record** (`data/sources.yaml`) — one entry per promoted source, with reliability and credibility ratings:

```yaml
- id: src_usgov_aa22_055a_pdf_mirror
  title: "AA22-055A: Iranian Government-Sponsored Actors Conduct Cyber Operations..."
  publisher: "CISA / FBI / CNMF / NCSC-UK / NSA"
  url: "https://media.defense.gov/2022/Feb/24/2002944274/-1/-1/0/CSA_AA22-055A..."
  local_files:
    raw:  "docs/source-gathering/raw-sources/07-.../source.pdf"
    text: "docs/source-gathering/raw-sources/07-.../source.txt"
  source_type: "government_advisory"
  source_reliability: "A"
  information_credibility: 2
  evidence_support: ["Reported", "Assessed"]
  actor_claims: ["MuddyWater", "Seedworm", "Static Kitten", "TEMP.Zagros", "Iran MOIS"]
  candidate_attck_techniques: ["T1566", "T1190", "T1574", "T1059.001", "T1219"]
  promotion_decision: "promote"
```

**Claim record** (`data/claims.yaml`) — source-bound atomic claim with evidence label:

```yaml
- id: clm_mw_0006
  source_id: src_usgov_aa22_055a_pdf_mirror
  claim: >
    MuddyWater spearphishing campaigns have used ZIP files containing either
    malicious macro-enabled Excel files or PDFs that drop malicious files.
  evidence_label: "Reported"
  confidence: "High"
  source_reliability: "A"
  information_credibility: 2
  technique_refs: ["T1566.001"]
  supports:
    procedure: true
    detection: true
```

**Procedure record** (`data/procedures.yaml`) — behavior extracted from claims, with telemetry and detection idea:

```yaml
- id: proc_mw_0006
  title: "Persistence via Scheduled Task"
  evidence_label: "Observed"
  confidence: "High"
  source_refs: ["src_incd_muddywater_2024_evolution"]
  attck_candidates:
    - technique: "T1053.005"
      notes: "BugSleep creates a scheduled task triggered every 43 minutes for C2 beaconing"
  procedure_summary: >
    BugSleep establishes persistence and C2 beaconing regularity by creating
    a Windows scheduled task triggered every 43 minutes.
  required_telemetry:
    - "Windows Security Event ID 4698 (scheduled task created)"
    - "Sysmon Event ID 1: schtasks.exe with /create arguments"
  detection_idea: >
    Alert on tasks with repetition intervals not matching standard software
    patterns (e.g., 43 minutes) with actions pointing to user-writable paths.
```

**Detection record** (`data/detections.yaml`) — deployable pseudologic with coverage score and analyst creation logic:

```yaml
- id: det_mw_0006
  title: "Scheduled Task Created with Anomalous Short Repetition Interval"
  techniques: ["T1053.005"]
  coverage_score: 4
  validation_status: lab_validated
  pseudologic: |
    # Rule A — Specific: PT43M interval (BugSleep artifact) — immediate alert
    event_type = scheduled_task_created AND
    task_trigger_repetition_interval = "PT43M"

    # Rule B — Behavioral: short interval + suspicious action path
    event_type = scheduled_task_created AND
    task_trigger_repetition_interval_minutes < 60 AND
    task_action_path MATCHES "(\\AppData\\|\\Temp\\|\\ProgramData\\)"

    # Rule C — Sysmon fallback (many envs don't forward Task Scheduler logs)
    event_type = process_create AND
    image ENDSWITH "schtasks.exe" AND
    command_line MATCHES "/create" AND
    command_line MATCHES "(AppData|Temp|ProgramData)"
  creation_logic: >
    The 43-minute interval is the single most precise artifact in the dataset,
    documented as BugSleep's specific C2 beacon interval in INCD 2024.
    Rule A fires with near-zero false positives. Rule C is the telemetry
    fallback when Task Scheduler event logs are not forwarded to SIEM.
```

**Raw source acquisition** (`docs/source-gathering/raw-sources/`) — each of the 71 candidate sources was fetched and stored with its metadata:

```json
{
  "number": 7,
  "url": "https://media.defense.gov/2022/Feb/.../CSA_AA22-055A_...PDF",
  "http_status": "200",
  "kind": "pdf",
  "size_bytes": 1220598,
  "saved": true,
  "raw_file": "docs/source-gathering/raw-sources/07-.../source.pdf",
  "text_file": "docs/source-gathering/raw-sources/07-.../source.txt"
}
```

---

## Working Principles

- Public-source CTI only — no classified or restricted material.
- ATT&CK mapping is a candidate mapping, not attribution evidence.
- AI-assisted research is untrusted until analyst-reviewed.
- No live malware, no real C2, no credential exfiltration in the lab.
- All `.dmp` files are deleted immediately after event confirmation.
- Coverage scores are conservative — 5 requires a Kibana proof, not just passing logic.
