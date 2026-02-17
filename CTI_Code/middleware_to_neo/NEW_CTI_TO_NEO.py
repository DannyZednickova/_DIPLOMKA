from __future__ import annotations
import os
import json
from typing import Dict, Any, List, Tuple
from dotenv import load_dotenv
from pycti import OpenCTIApiClient

# ----------------------------
# CONFIG
# ----------------------------
load_dotenv()

OPENCTI_URL = os.getenv("OPENCTI_URL", "http://localhost:8080/graphql")
OPENCTI_TOKEN = os.getenv("OPENCTI_TOKEN", "3c6f2d8e-9c6e-4f4a-9f7a-5a8c9a8b1e22")

import logging

logging.getLogger("api").setLevel(logging.WARNING)
logging.getLogger("opencti").setLevel(logging.WARNING)


# Vymyslený příklad 5 CVE (změň si dle datasetu)
CVE_NAMES = [
    "CVE-2024-21887",
    "CVE-2023-23397",
    "CVE-2021-44228",
    "CVE-2022-30190",
    "CVE-2023-34362",
]

MODE = os.getenv("MODE", "full")  # full / simple (na vztahy targets typicky chceš full)

# Jaké vztahy tě zajímají
REL_TYPES = {"targets", "exploits", "uses"}

# Jaké typy zdrojových objektů chceme vidět
SOURCE_TYPES = {"attack-pattern", "malware", "intrusion-set"}  # STIX "type" jsou lower-case

client = OpenCTIApiClient(OPENCTI_URL, OPENCTI_TOKEN)


# ----------------------------
# Helpers
# ----------------------------
def find_cve_by_name(cve_name: str) -> Dict[str, Any] | None:
    """Najde vulnerability v OpenCTI podle jména (CVE-xxxx-xxxx) a vrátí OpenCTI entity dict."""
    return client.vulnerability.read(
        filters={
            "mode": "and",
            "filters": [{"key": "name", "values": [cve_name]}],
            "filterGroups": [],
        }
    )


def get_bundle_for_opencti_entity(entity_type: str, entity_id: str, mode: str) -> Dict[str, Any]:
    """Stáhne STIX bundle pro zadanou entitu (OpenCTI interní ID)."""
    return client.stix2.get_stix_bundle_or_object_from_entity_id(
        entity_type=entity_type,
        entity_id=entity_id,
        mode=mode,
    )


def index_bundle_objects(bundle: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """Index STIX objektů podle STIX id (např. vulnerability--..., attack-pattern--...)."""
    idx: Dict[str, Dict[str, Any]] = {}
    for obj in bundle.get("objects", []):
        obj_id = obj.get("id")
        if obj_id:
            idx[obj_id] = obj
    return idx


def extract_cve_edges_from_bundle(
    bundle: Dict[str, Any],
    cve_name: str,
    rel_types: set[str] = REL_TYPES,
    source_types: set[str] = SOURCE_TYPES,
) -> List[Tuple[str, str, str, str, str]]:
    """
    Vrátí seznam hran ve formátu:
    (source_type, source_name, relationship_type, target_type, target_name)
    pro vztahy mířící na vulnerability objekt v bundlu.
    """
    objects_idx = index_bundle_objects(bundle)

    # najdi STIX objekt vulnerability podle name
    vuln_obj = None
    for obj in bundle.get("objects", []):
        if obj.get("type") == "vulnerability" and obj.get("name") == cve_name:
            vuln_obj = obj
            break
    if vuln_obj is None:
        return []

    vuln_stix_id = vuln_obj["id"]

    edges: List[Tuple[str, str, str, str, str]] = []

    for obj in bundle.get("objects", []):
        if obj.get("type") != "relationship":
            continue

        rtype = obj.get("relationship_type")
        if rtype not in rel_types:
            continue

        src_ref = obj.get("source_ref")
        tgt_ref = obj.get("target_ref")
        if not src_ref or not tgt_ref:
            continue

        # chceme vztahy kde target je ta vulnerability
        if tgt_ref != vuln_stix_id:
            continue

        src_obj = objects_idx.get(src_ref)
        tgt_obj = objects_idx.get(tgt_ref)

        if not src_obj or not tgt_obj:
            continue

        # filtr zdrojových typů (attack-pattern / malware / intrusion-set)
        if src_obj.get("type") not in source_types:
            continue

        edges.append((
            src_obj.get("type", "?"),
            src_obj.get("name", src_ref),
            rtype,
            tgt_obj.get("type", "?"),
            tgt_obj.get("name", tgt_ref),
        ))

    return edges


# ----------------------------
# Main
# ----------------------------
all_results = {}

for cve_name in CVE_NAMES:
    cve = find_cve_by_name(cve_name)
    if not cve:
        print(f"[SKIP] CVE nenalezeno v OpenCTI: {cve_name}")
        continue

    # DŮLEŽITÉ:
    # cve["id"] je OpenCTI interní UUID, to je správné pro export bundle.
    bundle = get_bundle_for_opencti_entity("Vulnerability", cve["id"], MODE)

    edges = extract_cve_edges_from_bundle(bundle=bundle, cve_name=cve_name)

    all_results[cve_name] = {
        "opencti_id": cve["id"],
        "edges": [
            {
                "source_type": e[0],
                "source_name": e[1],
                "relationship_type": e[2],
                "target_type": e[3],
                "target_name": e[4],
            }
            for e in edges
        ],
    }

    print(f"\n=== {cve_name} ===")
    print(f"OpenCTI ID: {cve['id']}")
    if not edges:
        print("Žádné edges (targets/exploits/uses) na attack-pattern/malware/intrusion-set v bundlu.")
    else:
        for (st, sn, rt, tt, tn) in edges:
            print(f"{sn} [{st}] --({rt})-> {tn} [{tt}]")

# Pokud chceš i JSON výstup do souboru:
# with open("cve_edges.json", "w", encoding="utf-8") as f:
#     json.dump(all_results, f, ensure_ascii=False, indent=2)
