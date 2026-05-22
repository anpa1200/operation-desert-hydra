#!/usr/bin/env python3
"""Create Operation Desert Hydra OpenCTI dashboard with widgets."""

import base64
import json
import os
import uuid

from pycti import OpenCTIApiClient

OPENCTI_URL = os.environ.get("OPENCTI_URL", "http://localhost:8080")
OPENCTI_TOKEN = os.environ.get("OPENCTI_TOKEN")
if not OPENCTI_TOKEN:
    raise SystemExit("ERROR: set OPENCTI_TOKEN environment variable")

api = OpenCTIApiClient(OPENCTI_URL, OPENCTI_TOKEN, ssl_verify=False)

IRAN_MOIS_ID = "8bfc9f8d-ac1d-4eeb-ab1a-8eec36bf53c8"

# NOTE: Filter 'key' must be an array per OpenCTI GraphQL schema: key: Array<String>
EMPTY_DYN = {"mode": "and", "filters": [], "filterGroups": []}


def flt(*conditions):
    """Build a FilterGroup with AND-combined conditions. Each condition is (key, values)."""
    return {
        "mode": "and",
        "filters": [
            {"key": [k], "values": v, "operator": "eq", "mode": "or"}
            for k, v in conditions
        ],
        "filterGroups": [],
    }


MALWARE_FILTER = flt(("entity_type", ["Malware"]), ("createdBy", [IRAN_MOIS_ID]))
REPORT_FILTER = flt(("entity_type", ["Report"]), ("createdBy", [IRAN_MOIS_ID]))
TOOL_FILTER = flt(("entity_type", ["Tool"]), ("createdBy", [IRAN_MOIS_ID]))
AUTHOR_FILTER = flt(("createdBy", [IRAN_MOIS_ID]))


def ds(label, attribute, perspective, filters, date_attribute="created_at", number=20):
    return {
        "label": label,
        "attribute": attribute,
        "date_attribute": date_attribute,
        "perspective": perspective,
        "isTo": False,
        "filters": filters,
        "dynamicFrom": EMPTY_DYN,
        "dynamicTo": EMPTY_DYN,
        "number": number,
    }


def w(widget_type, perspective, data_selection, parameters, x, y, width, height):
    wid = str(uuid.uuid4())
    return wid, {
        "id": wid,
        "type": widget_type,
        "perspective": perspective,
        "dataSelection": data_selection,
        "parameters": parameters,
        "layout": {
            "i": wid,
            "x": x,
            "y": y,
            "w": width,
            "h": height,
            "moved": False,
            "static": False,
        },
    }


widgets = {}

# Row 1: header text + three number counters
_, widget = w(
    "text", None,
    [],   # text widgets have no dataSelection
    {
        "title": "Operation Desert Hydra",
        "content": (
            "**MuddyWater** (TEMP.Zagros / APT34-adjacent) — Iranian MOIS-linked threat actor "
            "active since 2017. Targets government, telecom, and defence sectors across the Middle East.\n\n"
            "This graph covers 9 malware families, 4 tools, 19 threat reports, and 21 ATT&CK technique links "
            "imported as part of Operation Desert Hydra."
        ),
    },
    0, 0, 12, 3,
)
widgets[_] = widget

_, widget = w(
    "number", "entities",
    [ds("Malware", "entity_type", "entities", MALWARE_FILTER)],
    {"title": "Malware Families"},
    0, 3, 4, 3,
)
widgets[_] = widget

_, widget = w(
    "number", "entities",
    [ds("Tools", "entity_type", "entities", TOOL_FILTER)],
    {"title": "Tools"},
    4, 3, 4, 3,
)
widgets[_] = widget

_, widget = w(
    "number", "entities",
    [ds("Reports", "entity_type", "entities", REPORT_FILTER)],
    {"title": "Threat Reports"},
    8, 3, 4, 3,
)
widgets[_] = widget

# Row 3: donut + malware list
_, widget = w(
    "donut", "entities",
    [ds("By type", "entity_type", "entities", AUTHOR_FILTER)],
    {"title": "Arsenal — by Object Type"},
    0, 6, 5, 6,
)
widgets[_] = widget

_, widget = w(
    "list", "entities",
    [ds("Malware", "name", "entities", MALWARE_FILTER)],
    {"title": "MuddyWater Malware Families"},
    5, 6, 7, 6,
)
widgets[_] = widget

# Row 4: reports bar + tools list
_, widget = w(
    "bar", "entities",
    [ds("Reports", "published", "entities", REPORT_FILTER, date_attribute="published")],
    {"title": "Reports by Publication Year", "interval": "year"},
    0, 12, 8, 5,
)
widgets[_] = widget

_, widget = w(
    "list", "entities",
    [ds("Tools", "name", "entities", TOOL_FILTER)],
    {"title": "Living-off-the-Land Tools"},
    8, 12, 4, 5,
)
widgets[_] = widget

manifest_json = json.dumps({"widgets": widgets, "config": {}})
manifest_b64 = base64.b64encode(manifest_json.encode()).decode()

# Delete existing Desert Hydra workspaces
existing = api.query("{ workspaces(first:20) { edges { node { id name } } } }", {})
for edge in existing["data"]["workspaces"]["edges"]:
    if "Desert Hydra" in edge["node"]["name"]:
        api.query(
            "mutation Del($id: ID!) { workspaceDelete(id: $id) }",
            {"id": edge["node"]["id"]},
        )
        print(f"Deleted old workspace: {edge['node']['id']}")

# Create dashboard
result = api.query(
    """
    mutation WorkspaceAdd($input: WorkspaceAddInput!) {
        workspaceAdd(input: $input) { id name }
    }
    """,
    {"input": {"type": "dashboard", "name": "Operation Desert Hydra — MuddyWater"}},
)
ws_id = result["data"]["workspaceAdd"]["id"]
print(f"Created workspace: {ws_id}")

# Store base64-encoded manifest
api.query(
    """
    mutation PatchManifest($id: ID!, $input: [EditInput!]!) {
        workspaceFieldPatch(id: $id, input: $input) { id name }
    }
    """,
    {"id": ws_id, "input": [{"key": "manifest", "value": [manifest_b64]}]},
)
print("Manifest applied. Open Dashboards in OpenCTI to see it.")
