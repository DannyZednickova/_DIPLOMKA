# middleware_to_neo/NEW_CTI_TO_NEO.py
import os
import json
import logging
from dotenv import load_dotenv
from pycti import OpenCTIApiClient

from typing import Dict, List, Tuple, Set

# ----------------------------
# CONFIG
# ----------------------------
load_dotenv()

logging.basicConfig(level=logging.WARNING)
logging.getLogger("api").setLevel(logging.WARNING)
logging.getLogger("pycti").setLevel(logging.WARNING)

OPENCTI_URL = os.getenv("OPENCTI_URL", "http://localhost:8080/graphql")
OPENCTI_TOKEN = os.getenv("OPENCTI_TOKEN", "CHANGE_ME")

CVE_NAME = os.getenv("CVE_NAME", "CVE-2024-21887").strip().upper()
MODE = os.getenv("MODE", "full")  # full / simple

client = OpenCTIApiClient(OPENCTI_URL, OPENCTI_TOKEN)

def build_index(stix_bundle: dict) -> Tuple[Dict[str, dict], List[dict]]:
    objs = stix_bundle.get("objects", []) or []
    by_id = {o.get("id"): o for o in objs if isinstance(o, dict) and o.get("id")}
    rels = [o for o in objs if isinstance(o, dict) and o.get("type") == "relationship"]
    return by_id, rels

def obj_name(o: dict) -> str:
    return o.get("name") or o.get("value") or o.get("x_mitre_id") or o.get("id") or "<?>"

def obj_type(o: dict) -> str:
    return o.get("type") or o.get("x_opencti_type") or "<?>"

def is_stix(prefix: str, stix_id: str) -> bool:
    return isinstance(stix_id, str) and stix_id.startswith(prefix + "--")

def pretty_rel(by_id: dict, r: dict) -> str:
    rel_id = r.get("id") or "relationship--<?>"
    rel_xid = r.get("x_opencti_id") or "<?>"
    rt = (r.get("relationship_type") or "?").upper()

    s = r.get("source_ref") or "<?>"
    t = r.get("target_ref") or "<?>"
    so = by_id.get(s, {"id": s})
    to = by_id.get(t, {"id": t})

    return (
        f"REL(id={rel_id}, x_opencti_id={rel_xid}, type={rt})\n"
        f"  SRC(ref={s}, type={obj_type(so)}, name={obj_name(so)}, x_opencti_id={so.get('x_opencti_id','<?>')})\n"
        f"  TGT(ref={t}, type={obj_type(to)}, name={obj_name(to)}, x_opencti_id={to.get('x_opencti_id','<?>')})"
    )

def get_cve_by_name(cve_name: str) -> dict:
    cve = client.vulnerability.read(
        filters={
            "mode": "and",
            "filters": [{"key": "name", "values": [cve_name]}],
            "filterGroups": [],
        }
    )
    if not cve:
        raise SystemExit(f"[ERROR] CVE nenalezeno: {cve_name}")
    return cve

def export_bundle_by_entity_id(entity_id: str, mode: str) -> dict:
    entity = client.stix_core_object.read(id=entity_id)
    if not entity:
        return {"type": "bundle", "objects": []}
    entity_type = entity.get("entity_type") or entity.get("type")
    if not entity_type:
        return {"type": "bundle", "objects": []}

    return client.stix2.get_stix_bundle_or_object_from_entity_id(
        entity_type=entity_type,
        entity_id=entity_id,
        mode=mode,
    )

def find_cve_stix_id(by_id: dict, cve_name: str) -> str:
    for oid, o in by_id.items():
        if o.get("type") == "vulnerability" and (o.get("name") or "").strip().upper() == cve_name.strip().upper():
            return oid
    raise SystemExit(f"[ERROR] CVE '{cve_name}' nebylo v CVE bundle nalezeno jako vulnerability objekt.")

def main():
    # 1) najdi CVE přes name -> OpenCTI entity id
    cve = get_cve_by_name(CVE_NAME)
    ENTITY_ID = cve["id"]
    print(f"[OK] CVE nalezeno: {cve.get('name')} | ENTITY_ID(OpenCTI)={ENTITY_ID}")

    # 2) export CVE bundle (full/simple)
    bundle = export_bundle_by_entity_id(ENTITY_ID, mode=MODE)
    print(f"[OK] entity_type=Vulnerability | mode={MODE}")

    # ---- CVE bundle index ----
    cve_by_id, cve_rels = build_index(bundle)
    CVE_STIX_ID = find_cve_stix_id(cve_by_id, CVE_NAME)

    print("\n" + "=" * 100)
    print(f"[CVE] {CVE_NAME} | OpenCTI ENTITY_ID={ENTITY_ID} | CVE_STIX_ID={CVE_STIX_ID} | mode={MODE}")
    print("=" * 100)

    # ----------------------------
    # LEVEL 1: z CVE bundle
    # (AttackPattern/IntrusionSet/Malware) -(targets|exploits)-> CVE
    # + seedy x_opencti_id pro intrusion-sety a malware (nepoužito dál)
    # ----------------------------
    L1: List[dict] = []
    intrusion_opencti_ids: Set[str] = set()
    malware_opencti_ids: Set[str] = set()

    for r in cve_rels:
        if (r.get("relationship_type") or "").lower() not in ("targets", "exploits"):
            continue
        if r.get("target_ref") != CVE_STIX_ID:
            continue

        src = r.get("source_ref")
        if not isinstance(src, str):
            continue

        if not (is_stix("attack-pattern", src) or is_stix("intrusion-set", src) or is_stix("malware", src)):
            continue

        L1.append(r)

        src_obj = cve_by_id.get(src, {})
        src_xid = src_obj.get("x_opencti_id")
        if is_stix("intrusion-set", src) and isinstance(src_xid, str):
            intrusion_opencti_ids.add(src_xid)
        if is_stix("malware", src) and isinstance(src_xid, str):
            malware_opencti_ids.add(src_xid)

    print("\n[LEVEL 1] (from CVE bundle)  (AttackPattern/IntrusionSet/Malware) -(targets|exploits)-> CVE")
    if not L1:
        print("  (nic)")
    else:
        for r in L1:
            print("  -", pretty_rel(cve_by_id, r))

    print("\n[LEVEL 1 seeds]")
    print(f"  IntrusionSet x_opencti_id count: {len(intrusion_opencti_ids)}")
    print(f"  Malware      x_opencti_id count: {len(malware_opencti_ids)}")

    print("\n" + "-" * 100)
    print("[SUMMARY]")
    print(f"  L1 rels: {len(L1)} | IntrusionSet seeds: {len(intrusion_opencti_ids)} | Malware seeds: {len(malware_opencti_ids)}")
    print("-" * 100 + "\n")

if __name__ == "__main__":
    main()