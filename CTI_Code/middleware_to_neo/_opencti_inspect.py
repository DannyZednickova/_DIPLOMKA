from __future__ import annotations
import os
import json
from dotenv import load_dotenv
from pycti import OpenCTIApiClient


"""
Slouzi jen pro inspekci objektu v OpenCTI podle jeho internal id (opencti_id).
"""

load_dotenv()
client = OpenCTIApiClient(os.getenv("OPENCTI_URL"), os.getenv("OPENCTI_TOKEN"))
STIX_ID="c9906d06-cf6b-4206-a7ea-aae1e58d1468"


def inspect_relationships(stix_id: str) -> None:
    def fg(filters):
        return {"mode": "and", "filters": filters, "filterGroups": []}

    rels = []
    rels += client.stix_core_relationship.list(
        filters=fg([{"key": "fromId", "values": [stix_id]}]),
        first=200, get_all=True
    )
    rels += client.stix_core_relationship.list(
        filters=fg([{"key": "toId", "values": [stix_id]}]),
        first=200, get_all=True
    )

    print("\n=== RELATIONSHIP TYPES ===")
    print(sorted({r.get("relationship_type") for r in rels if r.get("relationship_type")}))

    print("\n=== DIRECT ENTITY TYPES ===")
    seen = {}
    for r in rels:
        f = r.get("fromId") or (r.get("from") or {}).get("id")
        t = r.get("toId") or (r.get("to") or {}).get("id")
        other = t if f == stix_id else f
        if not other or other in seen:
            continue
        o = client.stix_domain_object.read(id=other)
        if o:
            seen[other] = o.get("entity_type")

    from collections import Counter
    print(Counter(seen.values()))



def inspect(stix_id: str) -> None:
    obj = client.stix_domain_object.read(id=stix_id)
    if not obj:
        print("NOT FOUND:", stix_id)
        return

    print("\n=== BASIC ===")
    print("id:", obj.get("id"))
    print("entity_type:", obj.get("entity_type"))
    print("name:", obj.get("name"))
    print("value:", obj.get("value"))

    print("\n=== TOP LEVEL KEYS ===")
    print(sorted(obj.keys()))

    interesting = [
        "description", "aliases", "confidence",
        "labels", "objectLabel",
        "x_opencti_source",
        "created", "modified",
        "createdBy", "objectMarking",
        "externalReferences",
    ]


    print("\n=== INTERESTING FIELDS (raw) ===")
    print(json.dumps({k: obj.get(k) for k in interesting}, ensure_ascii=False, indent=2))

if __name__ == "__main__":
    stix_id = STIX_ID
    if not stix_id:
        raise SystemExit("Set env STIX_ID to OpenCTI internal id (opencti_id).")
    inspect(stix_id)
    inspect_relationships(stix_id)

