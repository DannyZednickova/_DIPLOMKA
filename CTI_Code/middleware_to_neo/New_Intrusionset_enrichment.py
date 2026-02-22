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
PAGE_SIZE = int(os.getenv("OPENCTI_PAGE_SIZE", "200"))
MODE = os.getenv("MODE", "full")

REL_TYPE = "targets"
TARGET_STIX_TYPE = "location"

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
    """Prefer STIX standard_id; fallback to id if needed."""
    return (
        entity.get("standard_id")
        or entity.get("stix_id")
        or entity.get("x_opencti_stix_ids")
        and entity.get("x_opencti_stix_ids")[0]
        or entity.get("id")
    )


def neo4j_init_constraints(driver) -> None:
    with driver.session(database=NEO4J_DB) as session:
        session.run("CREATE CONSTRAINT IF NOT EXISTS FOR (i:IntrusionSet) REQUIRE i.stix_id IS UNIQUE")
        session.run("CREATE CONSTRAINT IF NOT EXISTS FOR (l:Location) REQUIRE l.stix_id IS UNIQUE")


def load_intrusion_sets_from_neo4j(driver) -> List[Dict[str, str]]:
    query = """
    MATCH (i:IntrusionSet)
    WHERE coalesce(i.opencti_id, '') <> ''
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
            if record.get("opencti_id")
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


def list_targets_locations_for_intrusion_set(opencti_id: str, intrusion_stix_id: str) -> List[Dict[str, Any]]:
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
        if not target_ref:
            continue
        if not str(target_ref).startswith(f"{TARGET_STIX_TYPE}--"):
            continue

        to_obj = objects_idx.get(target_ref) or {}
        if to_obj.get("type") != TARGET_STIX_TYPE:
            continue

        location_entity = to_obj
        location_props = to_neo4j_props(location_entity)

        location_stix_id = pick_stix_id(location_entity)
        if not location_stix_id:
            continue

        location_props["stix_id"] = location_stix_id
        location_props["opencti_id"] = location_entity.get("x_opencti_id")
        location_props["stix_type"] = "location"

        rel_props = to_neo4j_props(rel)
        rel_props["stix_id"] = rel_id
        rel_props["opencti_id"] = rel.get("x_opencti_id")
        rel_props["relationship_type_norm"] = rel.get("relationship_type")

        out.append({"location": location_props, "relationship": rel_props})

    return out


def upsert_location(tx, location_props: Dict[str, Any]) -> None:
    tx.run(
        """
        MERGE (l:Location {stix_id: $stix_id})
        SET l += $props
        """,
        stix_id=location_props["stix_id"],
        props=location_props,
    )


def link_intrusion_set_to_location(
    tx,
    intrusion_stix_id: str,
    intrusion_opencti_id: str,
    location_stix_id: str,
    rel_props: Dict[str, Any],
) -> None:
    tx.run(
        """
        MATCH (l:Location {stix_id: $location_stix_id})
        MATCH (i:IntrusionSet)
        WHERE i.stix_id = $intrusion_stix_id OR i.opencti_id = $intrusion_opencti_id
        MERGE (i)-[r:TARGETS {stix_id: $rel_stix_id}]->(l)
        SET r += $props
        """,
        intrusion_stix_id=intrusion_stix_id,
        intrusion_opencti_id=intrusion_opencti_id,
        location_stix_id=location_stix_id,
        rel_stix_id=rel_props["stix_id"],
        props=rel_props,
    )


def main() -> None:
    if not all([OPENCTI_URL, OPENCTI_TOKEN]):
        raise SystemExit("Chybí OPENCTI_URL/OPENCTI_TOKEN v .env")
    if not all([NEO4J_URI, NEO4J_USER, NEO4J_PASS]):
        raise SystemExit("Chybí NEO4J_URI/NEO4J_USER/NEO4J_PASS v .env")

    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASS))
    neo4j_init_constraints(driver)

    intrusion_sets = load_intrusion_sets_from_neo4j(driver)
    print(f"[NEO4J] IntrusionSet s opencti_id: {len(intrusion_sets)}")

    total_locations = 0
    total_rels = 0

    with driver.session(database=NEO4J_DB) as session:
        for intr in intrusion_sets:
            intr_name = intr["name"] or intr["stix_id"] or intr["opencti_id"]
            targets = list_targets_locations_for_intrusion_set(intr["opencti_id"], intr["stix_id"])
            if not targets:
                continue

            for item in targets:
                location_props = item["location"]
                rel_props = item["relationship"]

                if not location_props.get("stix_id") or not rel_props.get("stix_id"):
                    continue

                session.execute_write(upsert_location, location_props)
                session.execute_write(
                    link_intrusion_set_to_location,
                    intr["stix_id"],
                    intr["opencti_id"],
                    location_props["stix_id"],
                    rel_props,
                )

                total_locations += 1
                total_rels += 1

            print(f"[OK] {intr_name}: {len(targets)} targets Location")

        cnt_locations = session.run("MATCH (:Location) RETURN count(*) AS c").single()["c"]
        cnt_targets = session.run("MATCH (:IntrusionSet)-[r:TARGETS]->(:Location) RETURN count(r) AS c").single()["c"]
        print(f"[CHECK] Location nodes={cnt_locations}, TARGETS rels={cnt_targets}")

    driver.close()
    print(f"[DONE] upserted approx locations={total_locations}, rels={total_rels}")


if __name__ == "__main__":
    main()
