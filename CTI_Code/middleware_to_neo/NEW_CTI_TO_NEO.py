from __future__ import annotations

import os
import json
import logging
from typing import Dict, Any, List, Optional
from dotenv import load_dotenv

from pycti import OpenCTIApiClient
from neo4j import GraphDatabase

#newcti je databaze jen pro cti.... v neo4j, abychom tam nemichali jine datasety a nemuseli resit konflikty s existujicim graphem

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

OPENCTI_URL = os.getenv("OPENCTI_URL")
OPENCTI_TOKEN = os.getenv("OPENCTI_TOKEN")

NEO4J_URI = os.getenv("NEO4J_URI")
NEO4J_USER = os.getenv("NEO4J_USER")
NEO4J_PASS = os.getenv("NEO4J_PASS")

# !!! DŮLEŽITÉ: databáze
NEO4J_DB = os.getenv("NEO4J_DB")  # např. "newcti"
# pokud není nastaveno, použije se default DB
# (někdy je default "neo4j")
MODE = os.getenv("MODE", "full")

CVE_NAMES = [
    "CVE-2024-21887",
    "CVE-2023-23397",
    "CVE-2021-44228",
    "CVE-2022-30190",
    "CVE-2023-34362",
]

REL_TYPES = {"targets", "exploits", "uses"}
SOURCE_TYPES = {"attack-pattern", "malware", "intrusion-set"}

client = OpenCTIApiClient(OPENCTI_URL, OPENCTI_TOKEN)


# ----------------------------
# HELPERS: STIX bundle parsing
# ----------------------------
def index_bundle_objects(bundle: dict) -> dict:
    idx = {}
    for obj in bundle.get("objects", []):
        oid = obj.get("id")
        if oid:
            idx[oid] = obj
    return idx


def find_vuln_obj_in_bundle(bundle: dict, cve_name: str) -> Optional[dict]:
    for obj in bundle.get("objects", []):
        if obj.get("type") == "vulnerability" and obj.get("name") == cve_name:
            return obj
    return None


def stix_type_to_label(stix_type: str) -> str:
    mapping = {
        "malware": "Malware",
        "attack-pattern": "AttackPattern",
        "intrusion-set": "IntrusionSet",
        "vulnerability": "Vulnerability",
        "threat-actor": "ThreatActor",
        "campaign": "Campaign",
        "indicator": "Indicator",
        "tool": "Tool",
        "identity": "Identity",
        "report": "Report",
    }
    if stix_type in mapping:
        return mapping[stix_type]
    return "".join(part.capitalize() for part in stix_type.split("-"))


def rel_type_to_neo4j(rel_type: str) -> str:
    return rel_type.upper().replace("-", "_")


def to_neo4j_props(stix_obj: Dict[str, Any]) -> Dict[str, Any]:
    props: Dict[str, Any] = {}
    for k, v in stix_obj.items():
        if v is None:
            continue
        if isinstance(v, (str, int, float, bool)):
            props[k] = v
        elif isinstance(v, (list, dict)):
            props[k] = json.dumps(v, ensure_ascii=False)
        else:
            props[k] = str(v)

    props["stix_id"] = stix_obj.get("id")
    if "x_opencti_id" in stix_obj:
        props["opencti_id"] = stix_obj.get("x_opencti_id")
    if "type" in stix_obj and isinstance(stix_obj["type"], str):
        props["stix_type"] = stix_obj["type"]

    return props


def extract_edges_for_cve(bundle: dict, cve_name: str) -> List[Dict[str, Any]]:
    objects_idx = index_bundle_objects(bundle)
    vuln_obj = find_vuln_obj_in_bundle(bundle, cve_name)
    if not vuln_obj:
        return []

    vuln_stix_id = vuln_obj["id"]
    edges = []

    for obj in bundle.get("objects", []):
        if obj.get("type") != "relationship":
            continue

        rtype = obj.get("relationship_type")
        if rtype not in REL_TYPES:
            continue

        if obj.get("target_ref") != vuln_stix_id:
            continue

        src_ref = obj.get("source_ref")
        tgt_ref = obj.get("target_ref")
        if not src_ref or not tgt_ref:
            continue

        src_obj = objects_idx.get(src_ref)
        tgt_obj = objects_idx.get(tgt_ref)
        if not src_obj or not tgt_obj:
            continue

        if src_obj.get("type") not in SOURCE_TYPES:
            continue

        edges.append({"relationship": obj, "source": src_obj, "target": tgt_obj})

    return edges


# ----------------------------
# NEO4J: schema + upsert
# ----------------------------
def neo4j_init_constraints(driver) -> None:
    labels = [
        "Malware",
        "AttackPattern",
        "IntrusionSet",
        "Vulnerability",
        "ThreatActor",
        "Campaign",
        "Indicator",
        "Tool",
        "Identity",
        "Report",
    ]
    # !!! DŮLEŽITÉ: session do správné DB
    with driver.session(database=NEO4J_DB) as session:
        for lbl in labels:
            session.run(
                f"CREATE CONSTRAINT {lbl.lower()}_stix_id IF NOT EXISTS "
                f"FOR (n:{lbl}) REQUIRE n.stix_id IS UNIQUE"
            )


def upsert_node(tx, label: str, props: Dict[str, Any]) -> None:
    if not props.get("stix_id"):
        return
    tx.run(
        f"""
        MERGE (n:{label} {{stix_id: $stix_id}})
        SET n += $props
        """,
        stix_id=props["stix_id"],
        props=props,
    )


def upsert_relationship(tx, src_label: str, src_id: str, rel_type: str, tgt_label: str, tgt_id: str, rel_props: Dict[str, Any]) -> None:
    if not rel_props.get("stix_id"):
        rel_props["stix_id"] = f"{src_id}::{rel_type}::{tgt_id}"

    tx.run(
        f"""
        MATCH (a:{src_label} {{stix_id: $src_id}})
        MATCH (b:{tgt_label} {{stix_id: $tgt_id}})
        MERGE (a)-[r:{rel_type} {{stix_id: $rel_stix_id}}]->(b)
        SET r += $props
        """,
        src_id=src_id,
        tgt_id=tgt_id,
        rel_stix_id=rel_props["stix_id"],
        props=rel_props,
    )


def rel_props_from_relationship(rel: Dict[str, Any]) -> Dict[str, Any]:
    props = {}
    for k, v in rel.items():
        if v is None:
            continue
        if isinstance(v, (str, int, float, bool)):
            props[k] = v
        elif isinstance(v, (list, dict)):
            props[k] = json.dumps(v, ensure_ascii=False)
        else:
            props[k] = str(v)

    props["stix_id"] = rel.get("id")
    if "x_opencti_id" in rel:
        props["opencti_id"] = rel.get("x_opencti_id")
    props["relationship_type_norm"] = rel.get("relationship_type")
    return props


# ----------------------------
# MAIN PIPELINE
# ----------------------------
def main():
    if not all([NEO4J_URI, NEO4J_USER, NEO4J_PASS]):
        raise SystemExit("Neo4j env proměnné chybí: NEO4J_URI/NEO4J_USER/NEO4J_PASS")

    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASS))

    # sanity check: vypiš DB kam píšeš
    print(f"[NEO4J] uri={NEO4J_URI} user={NEO4J_USER} db={NEO4J_DB or '(default)'}")

    neo4j_init_constraints(driver)

    total_edges = 0
    total_nodes = 0

    # !!! DŮLEŽITÉ: session do správné DB
    with driver.session(database=NEO4J_DB) as session:
        for cve_name in CVE_NAMES:
            cve = client.vulnerability.read(
                filters={
                    "mode": "and",
                    "filters": [{"key": "name", "values": [cve_name]}],
                    "filterGroups": [],
                }
            )
            if not cve:
                print(f"[SKIP] CVE nenalezeno v OpenCTI: {cve_name}")
                continue

            print(f"\n=== {cve_name} ===")
            print(f"OpenCTI ID: {cve['id']}")

            bundle = client.stix2.get_stix_bundle_or_object_from_entity_id(
                entity_type="Vulnerability",
                entity_id=cve["id"],
                mode=MODE,
            )

            edges = extract_edges_for_cve(bundle, cve_name)
            if not edges:
                print("   (žádné relevantní relationshipy v bundlu)")
                continue

            vuln_obj = find_vuln_obj_in_bundle(bundle, cve_name)
            if vuln_obj:
                vuln_label = stix_type_to_label(vuln_obj["type"])
                vuln_props = to_neo4j_props(vuln_obj)
                try:
                    session.execute_write(upsert_node, vuln_label, vuln_props)
                except Exception as e:
                    print("[ERROR] upsert_node vulnerability:", e)
                total_nodes += 1

            for e in edges:
                src = e["source"]
                tgt = e["target"]
                rel = e["relationship"]

                src_label = stix_type_to_label(src.get("type", "unknown"))
                tgt_label = stix_type_to_label(tgt.get("type", "unknown"))

                src_props = to_neo4j_props(src)
                tgt_props = to_neo4j_props(tgt)

                try:
                    session.execute_write(upsert_node, src_label, src_props)
                    session.execute_write(upsert_node, tgt_label, tgt_props)
                except Exception as ex:
                    print("[ERROR] upsert_node src/tgt:", ex)

                total_nodes += 2

                neo_rel_type = rel_type_to_neo4j(rel.get("relationship_type", "RELATED_TO"))
                props = rel_props_from_relationship(rel)

                try:
                    session.execute_write(
                        upsert_relationship,
                        src_label, src_props["stix_id"],
                        neo_rel_type,
                        tgt_label, tgt_props["stix_id"],
                        props,
                    )
                except Exception as ex:
                    print("[ERROR] upsert_relationship:", ex)

                total_edges += 1

                print(f"   {src.get('name', src.get('id'))} [{src.get('type')}] --({rel.get('relationship_type')})-> {tgt.get('name', tgt.get('id'))} [{tgt.get('type')}]")

        # ✅ tvrdá kontrola po zápisu v té samé session/db
        cnt_nodes = session.run("MATCH (n) RETURN count(n) AS c").single()["c"]
        cnt_rels = session.run("MATCH ()-[r]->() RETURN count(r) AS c").single()["c"]
        print(f"\n[CHECK] Neo4j DB '{NEO4J_DB or '(default)'}' : nodes={cnt_nodes}, rels={cnt_rels}")

    driver.close()
    print(f"\n[OK] Hotovo. Nodes upsert calls ~{total_nodes}, edges created/updated: {total_edges}")


if __name__ == "__main__":
    main()
