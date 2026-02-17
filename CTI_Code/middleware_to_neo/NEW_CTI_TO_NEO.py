from __future__ import annotations
import os
import json
import logging
from dotenv import load_dotenv
from pycti import OpenCTIApiClient

# ----------------------------
# (volitelně) vypnout otravný logging pycti
# ----------------------------
logging.getLogger("api").setLevel(logging.WARNING)
logging.getLogger("opencti").setLevel(logging.WARNING)
logging.getLogger("pycti").setLevel(logging.WARNING)

# ----------------------------
# CONFIG
# ----------------------------
load_dotenv()

OPENCTI_URL = os.getenv("OPENCTI_URL", "http://localhost:8080/graphql")
OPENCTI_TOKEN = os.getenv("OPENCTI_TOKEN", "CHANGE_ME")

# 1) Pole CVE (vymyslených 5 – změň podle datasetu)
CVE_NAMES = [
    "CVE-2024-21887",
    "CVE-2023-23397",
    "CVE-2021-44228",
    "CVE-2022-30190",
    "CVE-2023-34362",
]

MODE = os.getenv("MODE", "full")  # full / simple

# které relationship typy tě zajímají
REL_TYPES = {"targets", "exploits", "uses"}

# source typy, které chceme zobrazit (STIX typy v bundlu jsou lower-case)
SOURCE_TYPES = {"attack-pattern", "malware", "intrusion-set"}

client = OpenCTIApiClient(OPENCTI_URL, OPENCTI_TOKEN)


# ----------------------------
# HELPERS (jen to nejnutnější)
# ----------------------------
def index_bundle_objects(bundle: dict) -> dict:
    """Index STIX objektů v bundlu podle jejich STIX id."""
    idx = {}
    for obj in bundle.get("objects", []):
        oid = obj.get("id")
        if oid:
            idx[oid] = obj
    return idx


def find_vuln_obj_in_bundle(bundle: dict, cve_name: str) -> dict | None:
    """Najdi vulnerability objekt ve STIX bundlu podle name (CVE-...)."""
    for obj in bundle.get("objects", []):
        if obj.get("type") == "vulnerability" and obj.get("name") == cve_name:
            return obj
    return None


def print_source_metadata(src: dict) -> None:
    """Vypíše víc info o malware/attack-pattern/intrusion-set přímo z bundlu."""
    print("   source.stix_id:", src.get("id"))
    print("   source.type:", src.get("type"))
    print("   source.name:", src.get("name"))
    print("   source.x_opencti_id:", src.get("x_opencti_id"))
    print("   source.x_opencti_type:", src.get("x_opencti_type"))
    print("   source.created:", src.get("created"), "| modified:", src.get("modified"))

    # pár typických polí navíc (když existují)
    if src.get("type") == "malware":
        if "is_family" in src:
            print("   malware.is_family:", src.get("is_family"))
        aliases = src.get("aliases") or src.get("x_mitre_aliases") or src.get("x_opencti_aliases")
        if aliases:
            print("   malware.aliases:", aliases)

    if src.get("type") == "attack-pattern":
        if "kill_chain_phases" in src:
            print("   attack.kill_chain_phases:", src.get("kill_chain_phases"))
        if "external_references" in src:
            print("   attack.external_references:", src.get("external_references"))

    if src.get("type") == "intrusion-set":
        aliases = src.get("aliases") or src.get("x_mitre_aliases") or src.get("x_opencti_aliases")
        if aliases:
            print("   intrusion-set.aliases:", aliases)


# ----------------------------
# MAIN
# ----------------------------
for cve_name in CVE_NAMES:
    # 1) Najdi CVE v OpenCTI podle name
    cve = client.vulnerability.read(
        filters={
            "mode": "and",
            "filters": [{"key": "name", "values": [cve_name]}],
            "filterGroups": [],
        }
    )

    if not cve:
        print(f"\n[SKIP] CVE nenalezeno v OpenCTI: {cve_name}")
        continue

    print(f"\n==============================")
    print(f"CVE: {cve['name']}")
    print(f"OpenCTI ID: {cve['id']}")
    print(f"==============================")

    # 2) Export STIX bundle pro tuhle Vulnerability
    bundle = client.stix2.get_stix_bundle_or_object_from_entity_id(
        entity_type="Vulnerability",
        entity_id=cve["id"],   # OpenCTI interní UUID
        mode=MODE,
    )

    # 3) Index pro rychlé dohledání source/target objektů v bundlu
    objects_idx = index_bundle_objects(bundle)

    vuln_obj = find_vuln_obj_in_bundle(bundle, cve_name)
    if not vuln_obj:
        print("[WARN] Vulnerability objekt nebyl nalezen v bundlu podle name (divné, ale může se stát).")
        continue

    vuln_stix_id = vuln_obj["id"]  # např. vulnerability--...

    # 4) Projdi relationshipy a vyfiltruj ty, které míří na tuhle CVE
    found_any = False
    for obj in bundle.get("objects", []):
        if obj.get("type") != "relationship":
            continue

        rtype = obj.get("relationship_type")
        if rtype not in REL_TYPES:
            continue

        src_ref = obj.get("source_ref")
        tgt_ref = obj.get("target_ref")
        if not src_ref or not tgt_ref:
            continue

        # vztahy kde target_ref = naše vulnerability
        if tgt_ref != vuln_stix_id:
            continue

        src_obj = objects_idx.get(src_ref)
        tgt_obj = objects_idx.get(tgt_ref)
        if not src_obj or not tgt_obj:
            continue

        # zobrazujeme jen vybrané source typy (attack-pattern/malware/intrusion-set)
        if src_obj.get("type") not in SOURCE_TYPES:
            continue

        found_any = True
        print(
            f"{src_obj.get('name', src_ref)} [{src_obj.get('type')}] "
            f"--({rtype})-> "
            f"{tgt_obj.get('name', tgt_ref)} [{tgt_obj.get('type')}]"
        )

        # 5) Víc metadat o source (už je v bundlu)
        print_source_metadata(src_obj)

    if not found_any:
        print("Žádné vztahy (targets/exploits/uses) na attack-pattern/malware/intrusion-set pro tuto CVE.")


