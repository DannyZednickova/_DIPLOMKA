from __future__ import annotations

import json
import logging
import os
from typing import Any, Dict, List, Optional

from dotenv import load_dotenv
from neo4j import GraphDatabase
from pycti import OpenCTIApiClient

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

REL_TYPE = "uses"
TARGET_STIX_TYPE = "attack-pattern"

client = OpenCTIApiClient(OPENCTI_URL, OPENCTI_TOKEN)


def to_neo4j_props(data: Dict[str, Any]) -> Dict[str, Any]:
    props: Dict[str, Any] = {}
    for key, value in data.items():
        if value is None:
            continue
        if isinstance(value, (str, int, float, bool)):
            props[key] = value
        elif isinstance(value, (list, dict)):
            props[key] = json.dumps(value, ensure_ascii=False)
        else:
            props[key] = str(value)
    return props


def pick_stix_id(entity: Dict[str, Any]) -> Optional[str]:
    return (
        entity.get("standard_id")
        or entity.get("stix_id")
        or entity.get("x_opencti_stix_ids")
        and entity.get("x_opencti_stix_ids")[0]
        or entity.get("id")
    )


def load_intrusion_sets_from_neo4j(driver) -> List[Dict[str, str]]:
    query = """
    MATCH (i:IntrusionSet)
    WHERE coalesce(i.opencti_id, '') <> '' AND coalesce(i.stix_id, '') <> ''
    RETURN i.name AS name, i.opencti_id AS opencti_id, i.stix_id AS stix_id
    ORDER BY i.name
    """
    with driver.session(database=NEO4J_DB) as session:
        rows = session.run(query)
        return [
            {
                "name": record.get("name") or "",
                "opencti_id": record.get("opencti_id") or "",
                "stix_id": record.get("stix_id") or "",
            }
            for record in rows
        ]


def index_bundle_objects(bundle: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    idx: Dict[str, Dict[str, Any]] = {}
    for obj in bundle.get("objects", []):
        oid = obj.get("id")
        if oid:
            idx[oid] = obj
    return idx


def fetch_intrusion_set_bundle(opencti_id: str) -> Dict[str, Any]:
    try:
        return client.stix2.get_stix_bundle_or_object_from_entity_id(
            entity_type="Intrusion-Set",
            entity_id=opencti_id,
            mode=MODE,
        )
    except Exception:
        return client.stix2.get_stix_bundle_or_object_from_entity_id(
            entity_type="IntrusionSet",
            entity_id=opencti_id,
            mode=MODE,
        )


def extract_uses_attackpattern_edges(opencti_id: str, intrusion_stix_id: str) -> List[Dict[str, Any]]:
    bundle = fetch_intrusion_set_bundle(opencti_id)
    objects_idx = index_bundle_objects(bundle)

    out: List[Dict[str, Any]] = []
    seen_rel_ids: set[str] = set()

    for rel in bundle.get("objects", []):
        if rel.get("type") != "relationship":
            continue
        if rel.get("relationship_type") != REL_TYPE:
            continue

        rel_id = rel.get("id")
        if not rel_id or rel_id in seen_rel_ids:
            continue
        seen_rel_ids.add(rel_id)

        if rel.get("source_ref") != intrusion_stix_id:
            continue

        target_ref = rel.get("target_ref")
        if not target_ref or not str(target_ref).startswith(f"{TARGET_STIX_TYPE}--"):
            continue

        ap_obj = objects_idx.get(target_ref) or {}
        if ap_obj.get("type") != TARGET_STIX_TYPE:
            continue

        attack_pattern_stix_id = pick_stix_id(ap_obj)
        if not attack_pattern_stix_id:
            continue

        rel_props = to_neo4j_props(rel)
        rel_props["stix_id"] = rel_id
        rel_props["opencti_id"] = rel.get("x_opencti_id")
        rel_props["relationship_type_norm"] = rel.get("relationship_type")

        out.append(
            {
                "attack_pattern_stix_id": attack_pattern_stix_id,
                "attack_pattern_name": ap_obj.get("name"),
                "relationship": rel_props,
            }
        )

    return out


def link_intrusion_set_to_existing_attackpattern(
    tx,
    intrusion_stix_id: str,
    intrusion_opencti_id: str,
    attack_pattern_stix_id: str,
    rel_props: Dict[str, Any],
) -> bool:
    result = tx.run(
        """
        MATCH (ap:AttackPattern {stix_id: $attack_pattern_stix_id})
        MATCH (i:IntrusionSet)
        WHERE i.stix_id = $intrusion_stix_id OR i.opencti_id = $intrusion_opencti_id
        MERGE (i)-[r:USES {stix_id: $rel_stix_id}]->(ap)
        SET r += $props
        RETURN count(r) AS c
        """,
        intrusion_stix_id=intrusion_stix_id,
        intrusion_opencti_id=intrusion_opencti_id,
        attack_pattern_stix_id=attack_pattern_stix_id,
        rel_stix_id=rel_props["stix_id"],
        props=rel_props,
    )
    row = result.single()
    return bool(row and row.get("c"))


def main() -> None:
    if not all([OPENCTI_URL, OPENCTI_TOKEN]):
        raise SystemExit("Chybí OPENCTI_URL/OPENCTI_TOKEN v .env")
    if not all([NEO4J_URI, NEO4J_USER, NEO4J_PASS]):
        raise SystemExit("Chybí NEO4J_URI/NEO4J_USER/NEO4J_PASS v .env")

    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASS))

    intrusion_sets = load_intrusion_sets_from_neo4j(driver)
    print(f"[NEO4J] IntrusionSet s opencti_id+stix_id: {len(intrusion_sets)}")

    linked = 0
    skipped_missing_attack_pattern = 0

    with driver.session(database=NEO4J_DB) as session:
        for intr in intrusion_sets:
            intr_name = intr["name"] or intr["stix_id"]
            edges = extract_uses_attackpattern_edges(intr["opencti_id"], intr["stix_id"])
            if not edges:
                continue

            for edge in edges:
                ok = session.execute_write(
                    link_intrusion_set_to_existing_attackpattern,
                    intr["stix_id"],
                    intr["opencti_id"],
                    edge["attack_pattern_stix_id"],
                    edge["relationship"],
                )
                if ok:
                    linked += 1
                else:
                    skipped_missing_attack_pattern += 1

            print(f"[OK] {intr_name}: candidates={len(edges)}")

        cnt_uses = session.run("MATCH (:IntrusionSet)-[r:USES]->(:AttackPattern) RETURN count(r) AS c").single()["c"]
        print(
            "[CHECK] USES->AttackPattern rels="
            f"{cnt_uses}, newly-linked={linked}, missing-attack-pattern={skipped_missing_attack_pattern}"
        )

    driver.close()
    print("[DONE] IntrusionSet -> USES -> AttackPattern sync finished.")


if __name__ == "__main__":
    main()
