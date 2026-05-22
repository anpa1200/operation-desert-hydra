#!/usr/bin/env python3
"""
Desert Hydra — Phase 3 OpenCTI graph import.

Reads data/sources.yaml and data/procedures.yaml and creates:
  - Identity:       Iran MOIS (organization)
  - Intrusion Set:  MuddyWater (with all known aliases)
  - Malware:        actor-developed tools (9 objects)
  - Tool:           legitimate tools abused (4 objects)
  - Reports:        one per promoted source (up to 20)
  - Relationships:  attributed-to, uses (malware/tool/ATT&CK)

Idempotent — existing objects are not duplicated.
ATT&CK pattern links are skipped for techniques not yet synced by the
MITRE connector; re-run the script after the MITRE sync completes.

Usage:
    export OPENCTI_URL=http://localhost:8080
    export OPENCTI_TOKEN=<admin-token>
    python3 tools/opencti_import.py
"""

import os
import sys
import yaml
from pathlib import Path
from pycti import OpenCTIApiClient
from pycti.entities.opencti_identity import IdentityTypes

# ── Bootstrap ─────────────────────────────────────────────────────────────────

OPENCTI_URL   = os.environ.get("OPENCTI_URL",   "http://localhost:8080")
OPENCTI_TOKEN = os.environ.get("OPENCTI_TOKEN", "")
REPO_ROOT     = Path(__file__).resolve().parent.parent

if not OPENCTI_TOKEN:
    sys.exit("ERROR: set OPENCTI_TOKEN environment variable")

api = OpenCTIApiClient(url=OPENCTI_URL, token=OPENCTI_TOKEN, log_level="error")
print(f"[desert-hydra] Connected  {OPENCTI_URL}")

# ── Load YAML data ─────────────────────────────────────────────────────────────

with open(REPO_ROOT / "data" / "sources.yaml") as f:
    SOURCES = yaml.safe_load(f)["sources"]

with open(REPO_ROOT / "data" / "procedures.yaml") as f:
    PROCEDURES = yaml.safe_load(f)["procedures"]

print(f"[desert-hydra] Loaded {len(SOURCES)} sources, {len(PROCEDURES)} procedures")

# ── TLP:WHITE ─────────────────────────────────────────────────────────────────

def get_tlp_white():
    results = api.marking_definition.list(
        filters={
            "mode": "and",
            "filters": [{"key": "definition", "values": ["TLP:WHITE"]}],
            "filterGroups": [],
        }
    )
    if results:
        return results[0]["id"]
    obj = api.marking_definition.create(
        definition_type="TLP",
        definition="TLP:WHITE",
        x_opencti_color="#ffffff",
        x_opencti_order=0,
    )
    return obj["id"]

TLP_WHITE = get_tlp_white()
print(f"[desert-hydra] TLP:WHITE  {TLP_WHITE}")

# ── Helpers ───────────────────────────────────────────────────────────────────

def _find(accessor, name):
    """Look up a STIX object by name. Returns the object dict or None."""
    return accessor.read(
        filters={
            "mode": "and",
            "filters": [{"key": "name", "values": [name]}],
            "filterGroups": [],
        }
    )


def link(from_id, to_id, rel_type, confidence=80):
    """Create a STIX core relationship; silently skip if it already exists."""
    try:
        api.stix_core_relationship.create(
            fromId=from_id,
            toId=to_id,
            relationship_type=rel_type,
            confidence=confidence,
            objectMarking=[TLP_WHITE],
        )
    except Exception:
        pass


ATTCK_NAMES = {
    "T1574.002": "DLL Side-Loading",
    "T1574.001": "DLL Search Order Hijacking",
    "T1546.015": "Component Object Model Hijacking",
    "T1218.010": "Regsvr32",
}

def find_or_create_attack_pattern(mitre_id):
    """Look up an ATT&CK pattern by x_mitre_id. Create it if not synced yet."""
    result = api.attack_pattern.read(
        filters={
            "mode": "and",
            "filters": [{"key": "x_mitre_id", "values": [mitre_id]}],
            "filterGroups": [],
        }
    )
    if result:
        return result["id"], False
    # Not in MITRE sync yet — create a stub so the relationship can be recorded
    name = ATTCK_NAMES.get(mitre_id, mitre_id)
    obj = api.attack_pattern.create(
        name=name,
        x_mitre_id=mitre_id,
        description=f"MITRE ATT&CK technique {mitre_id}. Created as stub — will be updated by MITRE connector sync.",
        objectMarking=[TLP_WHITE],
        confidence=75,
    )
    return obj["id"], True

# ── Step 1: Iran MOIS Identity ────────────────────────────────────────────────

print("\n[Step 1] Iran MOIS — Identity (Organization)")

existing = _find(api.identity, "Iran MOIS")
if existing:
    MOIS_ID = existing["id"]
    print(f"  [exists]  {MOIS_ID}")
else:
    obj = api.identity.create(
        type=IdentityTypes.ORGANIZATION.value,
        name="Iran MOIS",
        description=(
            "Iranian Ministry of Intelligence and Security (MOIS). "
            "State sponsor attributed to MuddyWater cyber operations by CISA, FBI, "
            "CNMF, NCSC-UK, and NSA in joint advisory AA22-055A (February 2022)."
        ),
        objectMarking=[TLP_WHITE],
        confidence=85,
    )
    MOIS_ID = obj["id"]
    print(f"  [created] {MOIS_ID}")

# ── Step 2: MuddyWater Intrusion Set ──────────────────────────────────────────

print("\n[Step 2] MuddyWater — Intrusion Set")

existing = _find(api.intrusion_set, "MuddyWater")
if existing:
    MW_ID = existing["id"]
    print(f"  [exists]  {MW_ID}")
else:
    obj = api.intrusion_set.create(
        name="MuddyWater",
        aliases=[
            "Seedworm", "Mango Sandstorm", "TA450",
            "Static Kitten", "TEMP.Zagros", "Mercury", "DEV-1084",
        ],
        description=(
            "Iranian Ministry of Intelligence and Security (MOIS) subordinate threat group, "
            "active since at least 2017. Targets government, defense, telecom, oil and gas, "
            "and managed service providers globally. Significant focus on Israeli organizations "
            "since 2022, including combined cyber-espionage and destructive operations (Technion, "
            "February 2023). Known for spearphishing, RMM tool abuse, and a shift toward "
            "in-house tooling (BugSleep, AnchorRAT) beginning ~May 2024."
        ),
        resource_level="government",
        primary_motivation="espionage",
        confidence=85,
        objectMarking=[TLP_WHITE],
        createdBy=MOIS_ID,
    )
    MW_ID = obj["id"]
    print(f"  [created] {MW_ID}")

link(MW_ID, MOIS_ID, "attributed-to", 85)
print(f"  MuddyWater → attributed-to → Iran MOIS")

# ── Step 3: Malware catalog ────────────────────────────────────────────────────

print("\n[Step 3] Malware catalog")

MALWARE_CATALOG = [
    {
        "name": "POWERSTATS",
        "aliases": ["Powermud"],
        "description": (
            "MuddyWater first-stage PowerShell backdoor (MITRE S0223). "
            "Uses Invoke-Expression to download and execute additional stages via HTTP/S C2."
        ),
    },
    {
        "name": "PowGoop",
        "aliases": ["Goopdate"],
        "description": (
            "MuddyWater DLL loader (MITRE S1046) that hijacks GoogleUpdate.exe via DLL "
            "side-loading (Goopdate.dll replacement). Executes an obfuscated PowerShell "
            "chain as a second-stage loader."
        ),
    },
    {
        "name": "Small Sieve",
        "aliases": [],
        "description": (
            "MuddyWater Python-based backdoor compiled as an NSIS installer "
            "(gram_app.exe / index.exe). Uses the Telegram Bot API for C2 over HTTPS. "
            "Persists via HKCU Run key (OutlookMicrosift)."
        ),
    },
    {
        "name": "Canopy",
        "aliases": ["Starwhale"],
        "description": (
            "MuddyWater dropper delivered via malicious Excel macro. Drops two Windows Script "
            "Files (WSF) and persists via the startup folder. Collects system survey data "
            "(IP, hostname, username, OS) and HTTP POSTs to C2."
        ),
    },
    {
        "name": "Mori",
        "aliases": [],
        "description": (
            "MuddyWater backdoor using DNS tunneling for C2 communication. "
            "Deployed as FML.dll via regsvr32.exe (T1218.010)."
        ),
    },
    {
        "name": "BugSleep",
        "aliases": [],
        "description": (
            "MuddyWater in-house backdoor introduced ~May 2024. Persists via a 43-minute "
            "scheduled task. Injects shellcode into legitimate processes (T1055). Supports "
            "file exfiltration and remote command execution. Represents MuddyWater's shift "
            "away from commercial RMM tools toward actor-developed capabilities."
        ),
    },
    {
        "name": "AnchorRAT",
        "aliases": [],
        "description": (
            "MuddyWater custom RAT observed in 2024 Israeli targeting. Persists via COM "
            "object hijacking: "
            "HKCU\\Software\\Classes\\CLSID\\{0358B920-...}\\InProcServer32 (T1546.015)."
        ),
    },
    {
        "name": "SyncroRAT",
        "aliases": [],
        "description": (
            "Remote access tool deployed by MuddyWater in the Technion campaign (February 2023). "
            "Used alongside Log4j exploitation (CVE-2021-44228) for initial access."
        ),
    },
    {
        "name": "DarkBit",
        "aliases": [],
        "description": (
            "Ransomware/wiper persona deployed by MuddyWater in the February 2023 attack "
            "against Technion University. Combined cyber-espionage (CNE) with destructive "
            "objectives (CNA). Deleted shadow copies via vssadmin.exe (T1490). "
            "Contained a hardcoded Technion server list indicating pre-attack network mapping."
        ),
    },
]

MALWARE_IDS = {}
for m in MALWARE_CATALOG:
    existing = _find(api.malware, m["name"])
    if existing:
        MALWARE_IDS[m["name"]] = existing["id"]
        print(f"  [exists]  Malware: {m['name']}")
    else:
        obj = api.malware.create(
            name=m["name"],
            aliases=m["aliases"],
            description=m["description"],
            is_family=False,
            objectMarking=[TLP_WHITE],
            createdBy=MOIS_ID,
        )
        MALWARE_IDS[m["name"]] = obj["id"]
        print(f"  [created] Malware: {m['name']}")

# ── Step 4: Tool catalog ──────────────────────────────────────────────────────

print("\n[Step 4] Tool catalog (legitimate tools abused)")

TOOL_CATALOG = [
    {
        "name": "AteraAgent",
        "aliases": ["Atera RMM"],
        "description": (
            "Commercial remote monitoring and management (RMM) platform abused by MuddyWater "
            "for persistent remote access. Delivered as a compressed installer via spearphishing "
            "links to Egnyte or OneDrive."
        ),
    },
    {
        "name": "SimpleHelp",
        "aliases": [],
        "description": (
            "Commercial RMM tool abused by MuddyWater in 2024 Israeli targeting campaigns "
            "as a post-compromise persistent remote access mechanism."
        ),
    },
    {
        "name": "Mimikatz",
        "aliases": [],
        "description": (
            "Open-source Windows credential dumping tool. MuddyWater uses Mimikatz alongside "
            "procdump64.exe to extract credentials from LSASS process memory (T1003.001)."
        ),
    },
    {
        "name": "LaZagne",
        "aliases": [],
        "description": (
            "Open-source credential recovery tool. MuddyWater uses LaZagne to dump "
            "LSA secrets (T1003.004) and cached domain credentials (T1003.005)."
        ),
    },
]

TOOL_IDS = {}
for t in TOOL_CATALOG:
    existing = _find(api.tool, t["name"])
    if existing:
        TOOL_IDS[t["name"]] = existing["id"]
        print(f"  [exists]  Tool: {t['name']}")
    else:
        obj = api.tool.create(
            name=t["name"],
            aliases=t["aliases"],
            description=t["description"],
            objectMarking=[TLP_WHITE],
            createdBy=MOIS_ID,
        )
        TOOL_IDS[t["name"]] = obj["id"]
        print(f"  [created] Tool: {t['name']}")

# ── Step 5: uses relationships ────────────────────────────────────────────────

print("\n[Step 5] MuddyWater → uses → Malware/Tool")

for name, mid in MALWARE_IDS.items():
    link(MW_ID, mid, "uses", 80)
    print(f"  → uses → {name}")

for name, tid in TOOL_IDS.items():
    link(MW_ID, tid, "uses", 80)
    print(f"  → uses → {name}")

# ── Step 6: Reports from sources.yaml ────────────────────────────────────────

print("\n[Step 6] Reports from sources.yaml")

# Known publication dates; default 2023-01-01 for unlisted sources
SOURCE_DATES = {
    "src_usgov_aa22_055a_pdf_mirror":        "2022-02-24T00:00:00.000Z",
    "src_incd_muddywater_darkbit_2023":      "2023-02-07T00:00:00.000Z",
    "src_incd_muddywater_2024_evolution":    "2024-06-01T00:00:00.000Z",
    "src_cisa_aa22_055a_page":               "2022-02-24T00:00:00.000Z",
    "src_ncsc_uk_muddywater_joint_advisory": "2022-02-24T00:00:00.000Z",
    "src_incd_recent_phishing_1947":         "2024-09-01T00:00:00.000Z",
    "src_mitre_attack_muddywater_g0069":     "2024-01-01T00:00:00.000Z",
    "src_mitre_powerstats_s0223":            "2024-01-01T00:00:00.000Z",
    "src_mitre_powgoop_s1046":               "2024-01-01T00:00:00.000Z",
}

RELIABILITY_MAP = {
    "A": "A - Completely reliable",
    "B": "B - Usually reliable",
    "C": "C - Fairly reliable",
}

REPORT_IDS = {}
for src in SOURCES:
    src_id     = src["id"]
    title      = src["title"]
    pub_date   = SOURCE_DATES.get(src_id, "2023-01-01T00:00:00.000Z")
    confidence = 85 if src.get("source_reliability") == "A" else 70

    description = "\n".join([
        f"Publisher: {src['publisher']}",
        f"Source type: {src.get('source_type', '')}",
        f"Reliability: {src.get('source_reliability', '?')} — Credibility: {src.get('information_credibility', '?')}",
        f"URL: {src['url']}",
        "",
        f"Actor claims: {', '.join(src.get('actor_claims', []))}",
        f"Key entities: {', '.join(src.get('key_entities', []))}",
        f"ATT&CK candidates: {', '.join(src.get('candidate_attck_techniques', []))}",
        "",
        "Limitations: " + " ".join(src.get("limitations", [])),
    ])

    existing = _find(api.report, title)
    if existing:
        REPORT_IDS[src_id] = existing["id"]
        print(f"  [exists]  {title[:72]}")
    else:
        obj = api.report.create(
            name=title,
            published=pub_date,
            description=description,
            report_types=["threat-report"],
            confidence=confidence,
            objectMarking=[TLP_WHITE],
            createdBy=MOIS_ID,
            objects=[MW_ID],
        )
        REPORT_IDS[src_id] = obj["id"]
        print(f"  [created] {title[:72]}")

# ── Step 7: ATT&CK pattern links from procedures ──────────────────────────────

print("\n[Step 7] MuddyWater → uses → ATT&CK patterns (from procedures)")

linked   = set()
stubs    = []

for proc in PROCEDURES:
    for candidate in proc.get("attck_candidates", []):
        tid = candidate["technique"]
        if tid in linked:
            continue
        pattern_id, created_as_stub = find_or_create_attack_pattern(tid)
        link(MW_ID, pattern_id, "uses", 75)
        linked.add(tid)
        if created_as_stub:
            stubs.append(tid)
            print(f"  → uses → {tid}  [stub created — not in MITRE sync]")
        else:
            print(f"  → uses → {tid}")

if stubs:
    print(f"\n  [note] {len(stubs)} stub pattern(s) created: {', '.join(stubs)}")
    print("  These will be enriched automatically when the MITRE connector syncs them.")

# ── Summary ───────────────────────────────────────────────────────────────────

print("\n" + "─" * 60)
print("[desert-hydra] Import complete")
print(f"  Malware objects  : {len(MALWARE_IDS)}")
print(f"  Tool objects     : {len(TOOL_IDS)}")
print(f"  Reports          : {len(REPORT_IDS)}")
print(f"  ATT&CK linked    : {len(linked)}")
print(f"  ATT&CK stubs     : {len(stubs)} (will be enriched by MITRE sync)")
print("─" * 60)
