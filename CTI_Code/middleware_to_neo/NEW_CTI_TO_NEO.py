
from __future__ import annotations

import os
import json
import logging
from typing import Dict, Any, List, Optional
from dotenv import load_dotenv

from pycti import OpenCTIApiClient
from neo4j import GraphDatabase

logging.getLogger("api").setLevel(logging.WARNING)
logging.getLogger("opencti").setLevel(logging.WARNING)
logging.getLogger("pycti").setLevel(logging.WARNING)

load_dotenv()

OPENCTI_URL = os.getenv("OPENCTI_URL")
OPENCTI_TOKEN = os.getenv("OPENCTI_TOKEN")
NEO4J_URI = os.getenv("NEO4J_URI")
NEO4J_USER = os.getenv("NEO4J_USER")
NEO4J_PASS = os.getenv("NEO4J_PASS")
NEO4J_DB = os.getenv("NEO4J_DB")
MODE = os.getenv("MODE", "full")

REL_TYPES = {"targets", "exploits", "uses"}
SOURCE_TYPES = {"attack-pattern", "malware", "intrusion-set"}

client = OpenCTIApiClient(OPENCTI_URL, OPENCTI_TOKEN)

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
    return mapping.get(stix_type, "".join(part.capitalize() for part in stix_type.split("-")))

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
    edges: List[Dict[str, Any]] = []
    for obj in bundle.get("objects", []):
        if obj.get("type") != "relationship":
            continue
        rtype = obj.get("relationship_type")
        if rtype not in REL_TYPES:
            continue
        if obj.get("target_ref") != vuln_stix_id:
            continue
        src_ref = obj.get("source_ref")
        if not src_ref:
            continue
        src_obj = objects_idx.get(src_ref)
        if not src_obj or src_obj.get("type") not in SOURCE_TYPES:
            continue
        edges.append({"relationship": obj, "source": src_obj, "target": vuln_obj})
    return edges

def rel_props_from_relationship(rel: Dict[str, Any]) -> Dict[str, Any]:
    props: Dict[str, Any] = {}
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

def neo4j_init_constraints(driver) -> None:
    with driver.session(database=NEO4J_DB) as session:
        session.run("CREATE CONSTRAINT IF NOT EXISTS FOR (v:Vulnerability) REQUIRE v.name IS UNIQUE")
        for lbl in ["Malware", "AttackPattern", "IntrusionSet", "ThreatActor", "Campaign", "Indicator", "Tool", "Identity", "Report"]:
            session.run(f"CREATE CONSTRAINT IF NOT EXISTS FOR (x:{lbl}) REQUIRE x.stix_id IS UNIQUE")

def upsert_vulnerability_by_name(tx, cve_name: str, props: Dict[str, Any]) -> None:
    tx.run(
        """
        MERGE (v:Vulnerability {name: $name})
        SET v += $props
        """,
        name=cve_name,
        props=props,
    )

def upsert_cti_node(tx, label: str, stix_id: str, props: Dict[str, Any]) -> None:
    tx.run(
        f"""
        MERGE (n:{label} {{stix_id: $stix_id}})
        SET n += $props
        """,
        stix_id=stix_id,
        props=props,
    )

def link_cti_to_cve_by_name(tx, src_label: str, src_stix_id: str, rel_type: str, cve_name: str, rel_props: Dict[str, Any]) -> None:
    tx.run(
        f"""
        MATCH (a:{src_label} {{stix_id: $src}})
        MATCH (v:Vulnerability {{name: $cve}})
        MERGE (a)-[r:{rel_type} {{stix_id: $rel_stix_id}}]->(v)
        SET r += $props
        """,
        src=src_stix_id,
        cve=cve_name,
        rel_stix_id=rel_props["stix_id"],
        props=rel_props,
    )

def main():
    cve_list = os.getenv("CVE_LIST", "")
    cve_names = [c.strip().upper() for c in cve_list.split(",") if c.strip()]
    if not cve_names:
        print("[SKIP] CVE_LIST is empty, nothing to enrich.")
        return

    if not all([NEO4J_URI, NEO4J_USER, NEO4J_PASS]):
        raise SystemExit("Neo4j env proměnné chybí: NEO4J_URI/NEO4J_USER/NEO4J_PASS")

    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASS))
    neo4j_init_constraints(driver)

    print(f"[NEO4J] uri={NEO4J_URI} user={NEO4J_USER} db={NEO4J_DB or '(default)'}")
    print(f"[OPENCTI] url={OPENCTI_URL} mode={MODE}")
    print(f"[CTI] CVEs to enrich: {len(cve_names)}")

    with driver.session(database=NEO4J_DB) as session:
        for cve_name in cve_names:
            cve_entity = client.vulnerability.read(
                filters={
                    "mode": "and",
                    "filters": [{"key": "name", "values": [cve_name]}],
                    "filterGroups": [],
                }
            )
            if not cve_entity:
                print(f"[SKIP] CVE nenalezeno v OpenCTI: {cve_name}")
                continue

            bundle = client.stix2.get_stix_bundle_or_object_from_entity_id(
                entity_type="Vulnerability",
                entity_id=cve_entity["id"],
                mode=MODE,
            )

            vuln_obj = find_vuln_obj_in_bundle(bundle, cve_name)
            if vuln_obj:
                session.execute_write(upsert_vulnerability_by_name, cve_name, to_neo4j_props(vuln_obj))

            edges = extract_edges_for_cve(bundle, cve_name)
            for e in edges:
                src = e["source"]
                rel = e["relationship"]

                src_label = stix_type_to_label(src.get("type", "unknown"))
                src_props = to_neo4j_props(src)
                if not src_props.get("stix_id"):
                    continue

                session.execute_write(upsert_cti_node, src_label, src_props["stix_id"], src_props)

                neo_rel_type = rel_type_to_neo4j(rel.get("relationship_type", "RELATED_TO"))
                rel_props = rel_props_from_relationship(rel)
                if not rel_props.get("stix_id"):
                    continue

                session.execute_write(
                    link_cti_to_cve_by_name,
                    src_label,
                    src_props["stix_id"],
                    neo_rel_type,
                    cve_name,
                    rel_props,
                )

        cnt_nodes = session.run("MATCH (n) RETURN count(n) AS c").single()["c"]
        cnt_rels = session.run("MATCH ()-[r]->() RETURN count(r) AS c").single()["c"]
        cnt_vulns = session.run("MATCH (:Vulnerability) RETURN count(*) AS c").single()["c"]
        print(f"[CHECK] nodes={cnt_nodes}, rels={cnt_rels}, vulns={cnt_vulns}")

    driver.close()
    print("[OK] CTI enrichment done.")

if __name__ == "__main__":
    main()