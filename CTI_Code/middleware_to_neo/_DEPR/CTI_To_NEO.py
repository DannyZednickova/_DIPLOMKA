from __future__ import annotations
import os
from collections import Counter
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set, Tuple
import logging
from pycti import OpenCTIApiClient
from dotenv import load_dotenv

#### VELKA SPATNA, PROBLEM ######
#### problem CVE je jediná výjimka – tam děláme dvojuzel (business + STIX)... dela se to v
#### zkousla jsem sbirat vic info z Alienvaultu jako description atp., ale tam to vetsinou neni
#### pomoci hopu tam cpe i Attack Pattern ale neni k nemu zadne info, to dela az pak MITRE Json....
#### tady se vkladaji 2 cve uzly - business a stix
####

"""
priklad STIX Domain Obect.... SDO k pochopeni:
{
  "id": "a1d9b2c3-....",
  "entity_type": "stix-core-relationship",
  "relationship_type": "uses",
  "fromId": "11111111-....",
  "toId": "22222222-....",
  "from": { "id": "11111111-....", "entity_type": "Intrusion-Set", "name": "Some Group" },
  "to":   { "id": "22222222-....", "entity_type": "Malware",        "name": "Some Malware" }
}

A pak k tomu prdnem SCR  - Stix Core Relationship ... to jsou ty hrany

{
  "id": "a1d9b2c3-....",
  "entity_type": "stix-core-relationship",
  "relationship_type": "uses",
  "fromId": "11111111-....",
  "toId": "22222222-....",
  "from": { "id": "11111111-....", "entity_type": "Intrusion-Set", "name": "Some Group" },
  "to":   { "id": "22222222-....", "entity_type": "Malware",        "name": "Some Malware" }
}
"""

# ----------------------------
# CONFIG
# ----------------------------

# ZAKAZAT OTRAVNE INFO z pycti/api loggeru (ponecha WARNING/ERROR)
logging.basicConfig(level=logging.WARNING)
logging.getLogger("api").setLevel(logging.WARNING)
logging.getLogger("pycti").setLevel(logging.WARNING)

load_dotenv()
# OpenCTI connection
OPENCTI_URL = os.getenv("OPENCTI_URL")
OPENCTI_TOKEN = os.getenv("OPENCTI_TOKEN")
NEO4J_URI = os.getenv("NEO4J_URI")
NEO4J_USER = os.getenv("NEO4J_USER")
NEO4J_PASS = os.getenv("NEO4J_PASS")
NEO4J_DB   = os.getenv("NEO4J_DB")

# konfigurace vstupu do zpracovani

# CVE-2023-20862 - muj vlastni CVE z OpenVAS
# CVE-2024-21887 - nejkrasnejsi CVE z OpenCTI

# PRO TESTOVANI at nemusim zapinat cely midleware proster, tak jen jedno CVEcko


openvas_cves = ["CVE-2024-21887"]

# CVE_NAME = os.getenv("CVE_NAME", "CVE-2023-41928")
HOPS = int(os.getenv("HOPS", "1"))          # kolik "skoků" od CVE rozbalit
PAGE_SIZE = int(os.getenv("PAGE_SIZE", "200"))

# typy objektů, které chceme vypisovat a typicky ukládat do Neo4j
WANTED_ENTITY_TYPES = {
    "Vulnerability",
    "Malware",
    "Tool",
    "Intrusion-Set",
    "Threat-Actor",
    "Campaign",
    "Attack-Pattern",
    "Indicator",
    "Report",
    "Note",
    "Identity",
    "Sector",
    "Location",
}

# relationship typy, které chceš preferovat (ale nevynucujeme)
PREFERRED_REL_TYPES = {
    "exploits",
    "targets",
    "uses",
    "indicates",
    "attributed-to",
    "related-to",
}

# ----------------------------
# OpenCTI client
# ----------------------------
client = OpenCTIApiClient(OPENCTI_URL, OPENCTI_TOKEN)

# ----------------------------
# Helpers: robust relationship parsing
# ----------------------------
def rel_end_id(rel: dict, side: str) -> Optional[str]:
    """
    side: 'from' | 'to'
    supports:
      rel['fromId']/rel['toId']
      rel['from']['id']/rel['to']['id']
    """
    key_id = f"{side}Id"
    if key_id in rel and rel.get(key_id):
        return rel.get(key_id)

    side_obj = rel.get(side)
    if isinstance(side_obj, dict):
        sid = side_obj.get("id")
        if sid:
            return sid

    return None


def rel_other_id(rel: dict, pivot_id: str) -> Optional[str]:
    f = rel_end_id(rel, "from")
    t = rel_end_id(rel, "to")
    if not f or not t:
        return None
    if f == pivot_id:
        return t
    if t == pivot_id:
        return f
    return None


# helpery na ukladani metadat z objektu STIX, ktery muze byt nekonzistentni, takze se snazime vytahnout co jde a nepadnout, kdyz neco chybi

def safe_entity_type(obj: dict) -> str:
    return obj.get("entity_type") or obj.get("type") or "Unknown"


def safe_entity_name(obj: dict) -> str:
    return obj.get("name") or obj.get("value") or obj.get("standard_id") or obj.get("id") or "Unnamed"


# --- tyhle 4 helpery ti v paste chyběly, ale používáš je níž ---
def safe_entity_description(obj: dict) -> str | None:
    desc = obj.get("description")
    return desc if isinstance(desc, str) and desc.strip() else None


def safe_entity_aliases(obj: dict) -> tuple[str, ...]:
    aliases = obj.get("aliases")
    if isinstance(aliases, list):
        return tuple(str(a) for a in aliases if a is not None)
    return ()


def safe_entity_confidence(obj: dict) -> int | None:
    conf = obj.get("confidence")
    return conf if isinstance(conf, int) else None


def safe_entity_labels(obj: dict) -> tuple[str, ...]:
    labels = obj.get("labels")
    if isinstance(labels, list):
        return tuple(str(l) for l in labels if l is not None)
    return ()


def safe_entity_source(obj: dict) -> str:
    src = obj.get("x_opencti_source")
    return src if isinstance(src, str) and src.strip() else "opencti"


def safe_external_reference_ids(obj: dict) -> tuple[str, ...]:
    ids = obj.get("externalReferencesIds")
    if isinstance(ids, list):
        return tuple(str(x) for x in ids if x)
    refs = obj.get("externalReferences")
    if isinstance(refs, list):
        out = []
        for r in refs:
            if isinstance(r, dict) and r.get("id"):
                out.append(str(r["id"]))
        return tuple(out)
    return ()


def safe_kill_chain_phase_ids(obj: dict) -> tuple[str, ...]:
    ids = obj.get("killChainPhasesIds")
    if isinstance(ids, list):
        return tuple(str(x) for x in ids if x)
    phases = obj.get("killChainPhases")
    if isinstance(phases, list):
        out = []
        for p in phases:
            if isinstance(p, dict) and p.get("id"):
                out.append(str(p["id"]))
        return tuple(out)
    return ()


def safe_str(obj: dict, key: str) -> str | None:
    v = obj.get(key)
    return v if isinstance(v, str) and v.strip() else None


def safe_str_list(obj: dict, key: str) -> tuple[str, ...]:
    v = obj.get(key)
    if isinstance(v, list):
        return tuple(str(x) for x in v if x is not None)
    return ()


def safe_created_by_id(obj: dict) -> str | None:
    v = obj.get("createdById")
    if isinstance(v, str) and v:
        return v
    cb = obj.get("createdBy")
    if isinstance(cb, dict) and cb.get("id"):
        return str(cb["id"])
    return None


def safe_object_marking_ids(obj: dict) -> tuple[str, ...]:
    ids = obj.get("objectMarkingIds")
    if isinstance(ids, list):
        return tuple(str(x) for x in ids if x)
    marks = obj.get("objectMarking")
    if isinstance(marks, list):
        out = []
        for m in marks:
            if isinstance(m, dict) and m.get("id"):
                out.append(str(m["id"]))
        return tuple(out)
    return ()


# ----------------------------
# Fetch functions
# ----------------------------
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


def list_relationships_to_id(object_id: str, rel_type: Optional[str] = None) -> List[dict]:
    filters_list = [{"key": "toId", "values": [object_id]}]
    if rel_type:
        filters_list.insert(0, {"key": "relationship_type", "values": [rel_type]})

    return client.stix_core_relationship.list(
        filters={"mode": "and", "filters": filters_list, "filterGroups": []},
        first=PAGE_SIZE,
        get_all=True,
    )


def list_relationships_from_id(object_id: str, rel_type: Optional[str] = None) -> List[dict]:
    filters_list = [{"key": "fromId", "values": [object_id]}]
    if rel_type:
        filters_list.insert(0, {"key": "relationship_type", "values": [rel_type]})

    return client.stix_core_relationship.list(
        filters={"mode": "and", "filters": filters_list, "filterGroups": []},
        first=PAGE_SIZE,
        get_all=True,
    )


def read_sdo(object_id: str) -> Optional[dict]:
    try:
        return client.stix_domain_object.read(id=object_id)
    except Exception:
        return None


# ----------------------------
# Graph expansion
# ----------------------------
@dataclass(frozen=True)
class Node:
    id: str
    entity_type: str
    name: str

    description: str | None = None
    aliases: tuple[str, ...] = ()
    confidence: int | None = None
    labels: tuple[str, ...] = ()
    source: str = "opencti"

    external_references: tuple[str, ...] = ()
    kill_chain_phases: tuple[str, ...] = ()
    x_mitre_id: str | None = None
    x_mitre_platforms: tuple[str, ...] = ()
    x_mitre_detection: str | None = None
    x_mitre_permissions_required: str | None = None

    created_by_id: str | None = None
    object_marking_ids: tuple[str, ...] = ()
    created: str | None = None
    modified: str | None = None
    created_at: str | None = None
    updated_at: str | None = None


@dataclass(frozen=True)
class Edge:
    id: str
    relationship_type: str
    from_id: str
    to_id: str


def normalize_rel_type(rt: Optional[str]) -> str:
    return (rt or "related-to").lower()


def collect_cti_context(seed_ids: List[str], hops: int) -> Tuple[Dict[str, Node], Dict[str, Edge]]:
    nodes: Dict[str, Node] = {}
    edges: Dict[str, Edge] = {}

    visited: Set[str] = set()
    nodes_to_process: List[Tuple[str, int]] = [(sid, 0) for sid in seed_ids]

    while nodes_to_process:
        current_node_id, depth = nodes_to_process.pop(0)
        if current_node_id in visited:
            continue
        visited.add(current_node_id)

        obj = read_sdo(current_node_id)
        if obj:
            nodes[current_node_id] = Node(
                id=current_node_id,
                entity_type=safe_entity_type(obj),
                name=safe_entity_name(obj),

                description=safe_entity_description(obj),
                aliases=safe_entity_aliases(obj),
                confidence=safe_entity_confidence(obj),
                labels=safe_entity_labels(obj),  # <-- POZOR: labels, ne "labelS"
                source=safe_entity_source(obj),

                external_references=safe_external_reference_ids(obj),
                kill_chain_phases=safe_kill_chain_phase_ids(obj),
                x_mitre_id=safe_str(obj, "x_mitre_id"),
                x_mitre_platforms=safe_str_list(obj, "x_mitre_platforms"),
                x_mitre_detection=safe_str(obj, "x_mitre_detection"),
                x_mitre_permissions_required=safe_str(obj, "x_mitre_permissions_required"),

                created_by_id=safe_created_by_id(obj),
                object_marking_ids=safe_object_marking_ids(obj),
                created=safe_str(obj, "created"),
                modified=safe_str(obj, "modified"),
                created_at=safe_str(obj, "created_at"),
                updated_at=safe_str(obj, "updated_at"),
            )
        else:
            nodes[current_node_id] = Node(id=current_node_id, entity_type="Unknown", name=current_node_id)

        if depth >= hops:
            continue

        out_rels = list_relationships_from_id(current_node_id)
        for r in out_rels:
            rid = r.get("id") or f"{current_node_id}-out-{len(edges)}"
            rt = normalize_rel_type(r.get("relationship_type"))
            f = rel_end_id(r, "from") or r.get("fromId")
            t = rel_end_id(r, "to") or r.get("toId")
            if not f or not t:
                continue

            edges[rid] = Edge(id=rid, relationship_type=rt, from_id=f, to_id=t)

            if t not in visited:
                nodes_to_process.append((t, depth + 1))

        INCOMING_REL_TYPES = {"uses", "exploits", "indicates", "targets", "attributed-to"}

        if depth <= 2:
            for rt in INCOMING_REL_TYPES:
                for r in list_relationships_to_id(current_node_id, rel_type=rt):
                    rid = r.get("id") or f"{current_node_id}-in-{len(edges)}"
                    f = rel_end_id(r, "from") or r.get("fromId")
                    t = rel_end_id(r, "to") or r.get("toId")
                    if not f or not t:
                        continue

                    edges[rid] = Edge(
                        id=rid,
                        relationship_type=normalize_rel_type(r.get("relationship_type")),
                        from_id=f,
                        to_id=t,
                    )

                    if f not in visited:
                        nodes_to_process.append((f, depth + 1))

    return nodes, edges


# ----------------------------
# Main
# ----------------------------
def main():
    cve_list_env = os.getenv("CVE_LIST", "").strip()
    if cve_list_env:
        cve_list = [x.strip() for x in cve_list_env.split(",") if x.strip()]
    else:
        cve_list = openvas_cves[:]  # bereš tvůj list

    cve_list = sorted({c.upper().strip() for c in cve_list if c})

    print(f"[INPUT] CVEs: {len(cve_list)}")
    print(f"[INPUT] HOPS={HOPS} PAGE_SIZE={PAGE_SIZE}")

    all_nodes: Dict[str, Node] = {}
    all_edges: Dict[str, Edge] = {}

    missing: List[str] = []
    processed: List[str] = []

    for cve_name in cve_list:
        print("\n" + "=" * 80)
        print("[CVE]", cve_name)

        try:
            cve = get_cve_by_name(cve_name)
        except SystemExit:
            print(f"[SKIP] CVE nenalezeno v OpenCTI: {cve_name}")
            missing.append(cve_name)
            continue

        cve_id = cve["id"]
        processed.append(cve_name)
        print(f"CVE: {cve.get('name')} id: {cve_id}")

        rels_to = list_relationships_to_id(cve_id)
        rels_from = list_relationships_from_id(cve_id)
        rels = rels_to + rels_from

        rel_types = sorted({r.get("relationship_type") for r in rels if r.get("relationship_type")})
        print("rels_total:", len(rels), "relationship_types:", rel_types)

        other_ids = []
        for r in rels:
            oid = rel_other_id(r, cve_id)
            if oid:
                other_ids.append(oid)
        other_ids = list(set(other_ids))

        direct_objs = []
        for oid in other_ids:
            o = read_sdo(oid)
            if o:
                direct_objs.append(o)

        direct_types = Counter([safe_entity_type(o) for o in direct_objs])
        print("direct_entity_types:", dict(direct_types))

        nodes, edges = collect_cti_context([cve_id], hops=HOPS)

        # zaruč CVE uzel
        nodes[cve_id] = Node(id=cve_id, entity_type="Vulnerability", name=cve.get("name") or cve_name)

        all_nodes.update(nodes)
        all_edges.update(edges)

        print(f"[CVE DONE] nodes={len(nodes)} edges={len(edges)}")

    print("\n" + "=" * 80)
    print(f"[SUMMARY] processed={len(processed)} missing={len(missing)}")
    if missing:
        print("[SUMMARY] missing CVEs (not in OpenCTI):", missing[:20], ("..." if len(missing) > 20 else ""))

    print(f"[Neo4j] writing aggregated graph: nodes={len(all_nodes)} edges={len(all_edges)}")
    write_to_neo4j(all_nodes, all_edges)


# ----------------------------
# Optional: Neo4j writing (idempotent)
# ----------------------------
def write_to_neo4j(nodes: Dict[str, Node], edges: Dict[str, Edge]) -> None:
    """
    Idempotentní zápis do Neo4j:
      - uzly: (vše) jako :StixEntity s opencti_id + entity_type + name (+ metadata)
      - CVE navíc jako :Vulnerability s cve (name) + opencti_id
      - hrany: podle relationship_type -> :RELTYPE (uppercase)
    """
    from neo4j import GraphDatabase

    vuln_id_to_cve = {
        n.id: n.name.strip().upper()
        for n in nodes.values()
        if n.entity_type == "Vulnerability" and (n.name or "").upper().startswith("CVE-")
    }

    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASS))

    constraint_cypher = [
        """
        CREATE CONSTRAINT vuln_cve_unique IF NOT EXISTS
        FOR (v:Vulnerability) REQUIRE v.cve IS UNIQUE
        """,
        """
        CREATE CONSTRAINT stix_opencti_id_unique IF NOT EXISTS
        FOR (e:StixEntity) REQUIRE e.opencti_id IS UNIQUE
        """,
    ]

    def create_constraints(tx):
        for q in constraint_cypher:
            tx.run(q)

    def to_neo4j_label(entity_type: str) -> str:
        return (entity_type or "Unknown").replace("-", "")

    def upsert_node(tx, n: Node):
        et = n.entity_type or "Unknown"
        name = (n.name or "").strip()

        # --- SPECIAL CASE: Vulnerability / CVE ---
        if et == "Vulnerability" and name.upper().startswith("CVE-"):
            cve = name.upper()

            # 1) STIX uzel (OpenCTI) – samostatný CVE uzel pro CTI část grafu
            tx.run(
                """
                MERGE (e:StixEntity {opencti_id: $id})
                SET e:OpenCTI_Vulnerability,
                    e.name = $name,
                    e.entity_type = 'Vulnerability',

                    e.description = $description,
                    e.aliases = $aliases,
                    e.confidence = $confidence,
                    e.labels = $labels,
                    e.source = $source,

                    e.external_references = $external_references,
                    e.kill_chain_phases = $kill_chain_phases,
                    e.x_mitre_id = $x_mitre_id,
                    e.x_mitre_platforms = $x_mitre_platforms,
                    e.x_mitre_detection = $x_mitre_detection,
                    e.x_mitre_permissions_required = $x_mitre_permissions_required,

                    e.created_by_id = $created_by_id,
                    e.object_marking_ids = $object_marking_ids,
                    e.created = $created,
                    e.modified = $modified,
                    e.created_at = $created_at,
                    e.updated_at = $updated_at
                """,
                id=n.id,
                name=cve,
                description=n.description,
                aliases=list(n.aliases) if n.aliases else [],
                confidence=n.confidence,
                labels=list(n.labels) if n.labels else [],
                source=n.source or "opencti",

                external_references=list(n.external_references) if n.external_references else [],
                kill_chain_phases=list(n.kill_chain_phases) if n.kill_chain_phases else [],
                x_mitre_id=n.x_mitre_id,
                x_mitre_platforms=list(n.x_mitre_platforms) if n.x_mitre_platforms else [],
                x_mitre_detection=n.x_mitre_detection,
                x_mitre_permissions_required=n.x_mitre_permissions_required,

                created_by_id=n.created_by_id,
                object_marking_ids=list(n.object_marking_ids) if n.object_marking_ids else [],
                created=n.created,
                modified=n.modified,
                created_at=n.created_at,
                updated_at=n.updated_at,
            )

            # 2) business uzel (OpenVAS / exposure vrstva)
            tx.run(
                """
                MERGE (v:Vulnerability {cve: $cve})
                SET v.name = $cve,
                    v.opencti_id = $id
                """,
                cve=cve,
                id=n.id,
            )

            # 3) šipka business -> STIX
            tx.run(
                """
                MATCH (v:Vulnerability {cve: $cve})
                MATCH (e:StixEntity {opencti_id: $id})
                MERGE (v)-[:HAS_STIX]->(e)
                """,
                cve=cve,
                id=n.id,
            )
            return

        # --- DEFAULT: ostatní entity jako StixEntity + typový label ---
        stix_label = to_neo4j_label(et)
        tx.run(
            f"""
            MERGE (e:StixEntity {{opencti_id: $id}})
            SET e:{stix_label},
                e.name = $name,
                e.entity_type = $etype,

                e.description = $description,
                e.aliases = $aliases,
                e.confidence = $confidence,
                e.labels = $labels,
                e.source = $source,

                e.external_references = $external_references,
                e.kill_chain_phases = $kill_chain_phases,
                e.x_mitre_id = $x_mitre_id,
                e.x_mitre_platforms = $x_mitre_platforms,
                e.x_mitre_detection = $x_mitre_detection,
                e.x_mitre_permissions_required = $x_mitre_permissions_required,

                e.created_by_id = $created_by_id,
                e.object_marking_ids = $object_marking_ids,
                e.created = $created,
                e.modified = $modified,
                e.created_at = $created_at,
                e.updated_at = $updated_at
            """,
            id=n.id,
            name=name or n.id,
            etype=et,

            description=n.description,
            aliases=list(n.aliases) if n.aliases else [],
            confidence=n.confidence,
            labels=list(n.labels) if n.labels else [],
            source=n.source or "opencti",

            external_references=list(n.external_references) if n.external_references else [],
            kill_chain_phases=list(n.kill_chain_phases) if n.kill_chain_phases else [],
            x_mitre_id=n.x_mitre_id,
            x_mitre_platforms=list(n.x_mitre_platforms) if n.x_mitre_platforms else [],
            x_mitre_detection=n.x_mitre_detection,
            x_mitre_permissions_required=n.x_mitre_permissions_required,

            created_by_id=n.created_by_id,
            object_marking_ids=list(n.object_marking_ids) if n.object_marking_ids else [],
            created=n.created,
            modified=n.modified,
            created_at=n.created_at,
            updated_at=n.updated_at,
        )

    def upsert_edge(tx, e: Edge):
        reltype = e.relationship_type.upper().replace("-", "_")

        def resolve_endpoint(oid: str):
            if oid in vuln_id_to_cve:
                return ("Vulnerability", "cve", vuln_id_to_cve[oid])
            return ("StixEntity", "opencti_id", oid)

        a_label, a_key, a_val = resolve_endpoint(e.from_id)
        b_label, b_key, b_val = resolve_endpoint(e.to_id)

        tx.run(f"MERGE (a:{a_label} {{{a_key}: $a_val}})", a_val=a_val)
        tx.run(f"MERGE (b:{b_label} {{{b_key}: $b_val}})", b_val=b_val)

        tx.run(
            f"""
            MATCH (a:{a_label} {{{a_key}: $a_val}})
            MATCH (b:{b_label} {{{b_key}: $b_val}})
            MERGE (a)-[r:{reltype}]->(b)
            SET r.opencti_id = $rid
            """,
            a_val=a_val,
            b_val=b_val,
            rid=e.id,
        )

    with driver.session(database=NEO4J_DB) as session:
        session.execute_write(create_constraints)

        for n in nodes.values():
            session.execute_write(upsert_node, n)

        for e in edges.values():
            session.execute_write(upsert_edge, e)

    driver.close()
    print(f"[Neo4j] Import hotový do DB '{NEO4J_DB}'.")


if __name__ == "__main__":
    main()
