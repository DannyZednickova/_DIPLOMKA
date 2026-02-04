
from __future__ import annotations
import os
from collections import Counter
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set, Tuple
import logging
from pycti import OpenCTIApiClient
from dotenv import load_dotenv


#### VELKA SPATNA, PROBLEM ######
#### problem CVE je jediná výjimka – tam děláme dvojuzel (business + STIX)... velka spatna
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






#konfigurace vstupu do zpracovani

#CVE-2023-20862 - muj vlastni CVE z OpenVAS
#CVE-2024-21887 - nejkrasnejsi CVE z OpenCTI


#PRO TESTOVANI: PROTO TO TAM MAM V TE DB 2X TY VECI...

#openvas_cves = [
#        "CVE-2024-21887"
#    ]


#CVE_NAME = os.getenv("CVE_NAME", "CVE-2023-41928")
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


def safe_entity_type(obj: dict) -> str:
    # pycti používá 'entity_type' (např. "Malware", "Intrusion-Set")
    return obj.get("entity_type") or obj.get("type") or "Unknown"


def safe_name(obj: dict) -> str:
    return obj.get("name") or obj.get("value") or obj.get("standard_id") or obj.get("id") or "Unnamed"


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
    # stix_domain_object.read zvládne většinu doménových objektů (malware, attack-pattern, intrusion-set...)
    # Pro některé typy (např. observables) by byl jiný endpoint, ale pro tvé cíle stačí.
    try:
        return client.stix_domain_object.read(id=object_id)
    except Exception:
        return None


# ----------------------------
# Graph expansion (BFS)
# ----------------------------
@dataclass(frozen=True)
class Node:
    id: str
    entity_type: str
    name: str


@dataclass(frozen=True)
class Edge:
    id: str
    relationship_type: str
    from_id: str
    to_id: str


def normalize_rel_type(rt: Optional[str]) -> str:
    return (rt or "related-to").lower()


def expand_from_seed_ids(seed_ids: List[str], hops: int) -> Tuple[Dict[str, Node], Dict[str, Edge]]:
    """
    Expand outward using relationships where current node is 'fromId' (outgoing).
    For the first layer (CVE) we also include incoming (toId) to capture things pointing to CVE.
    """
    nodes: Dict[str, Node] = {}
    edges: Dict[str, Edge] = {}

    visited: Set[str] = set()
    frontier: List[Tuple[str, int]] = [(sid, 0) for sid in seed_ids]

    while frontier:
        current_id, depth = frontier.pop(0)
        if current_id in visited:
            continue
        visited.add(current_id)

        # read node details (may fail for some ids)
        obj = read_sdo(current_id)
        if obj:
            et = safe_entity_type(obj)
            nm = safe_name(obj)
            nodes[current_id] = Node(id=current_id, entity_type=et, name=nm)
        else:
            # fallback node
            nodes[current_id] = Node(id=current_id, entity_type="Unknown", name=current_id)

        if depth >= hops:
            continue

        # outgoing rels (fromId = current)
        out_rels = list_relationships_from_id(current_id)
        for r in out_rels:
            rid = r.get("id") or f"{current_id}-out-{len(edges)}"
            rt = normalize_rel_type(r.get("relationship_type"))
            f = rel_end_id(r, "from") or r.get("fromId")
            t = rel_end_id(r, "to") or r.get("toId")
            if not f or not t:
                continue

            edges[rid] = Edge(id=rid, relationship_type=rt, from_id=f, to_id=t)

            if t not in visited:
                frontier.append((t, depth + 1))

        # optional: also include incoming (toId = current) — useful at depth 0 (CVE) and sometimes beyond
        # Aby to nebylo explozivní, omezíme na depth == 0 (tj. pro CVE).
        if depth == 0:
            in_rels = list_relationships_to_id(current_id)
            for r in in_rels:
                rid = r.get("id") or f"{current_id}-in-{len(edges)}"
                rt = normalize_rel_type(r.get("relationship_type"))
                f = rel_end_id(r, "from") or r.get("fromId")
                t = rel_end_id(r, "to") or r.get("toId")
                if not f or not t:
                    continue

                edges[rid] = Edge(id=rid, relationship_type=rt, from_id=f, to_id=t)

                if f not in visited:
                    frontier.append((f, depth + 1))

    return nodes, edges


# MALWARE EXTENSIONS

def fg(filters):
    """FilterGroup helper ve formátu co chce OpenCTI"""
    return {"mode": "and", "filters": filters, "filterGroups": []}

def rel_end_id(rel: dict, side: str):
    """Zvládne rel['fromId']/rel['toId'] i rel['from']['id']/rel['to']['id']"""
    key = f"{side}Id"
    if key in rel and rel.get(key):
        return rel.get(key)
    obj = rel.get(side)
    if isinstance(obj, dict) and obj.get("id"):
        return obj["id"]
    return None

def list_rels_to(obj_id: str, rel_type: str | None = None, first: int = 200):
    flt = [{"key": "toId", "values": [obj_id]}]
    if rel_type:
        flt.insert(0, {"key": "relationship_type", "values": [rel_type]})
    return client.stix_core_relationship.list(filters=fg(flt), first=first, get_all=True)

def list_rels_from(obj_id: str, rel_type: str | None = None, first: int = 200):
    flt = [{"key": "fromId", "values": [obj_id]}]
    if rel_type:
        flt.insert(0, {"key": "relationship_type", "values": [rel_type]})
    return client.stix_core_relationship.list(filters=fg(flt), first=first, get_all=True)

def read_sdo(obj_id: str):
    try:
        return client.stix_domain_object.read(id=obj_id)
    except Exception:
        return None

def add_node_from_obj(nodes: Dict[str, Node], obj: dict) -> None:
    oid = obj.get("id")
    if not oid:
        return
    nodes[oid] = Node(
        id=oid,
        entity_type=obj.get("entity_type") or "Unknown",
        name=obj.get("name") or oid,
    )


def add_edge_simple(
    edges: Dict[str, Edge],
    rel_id: str,
    rel_type: str,
    from_id: str,
    to_id: str,
) -> None:
    if not from_id or not to_id:
        return
    edges[rel_id] = Edge(
        id=rel_id,
        relationship_type=normalize_rel_type(rel_type),
        from_id=from_id,
        to_id=to_id,
    )

# ----------------------------
# Main
# ----------------------------
def main():
    # --- MULTI-CVE INPUT ---
    # Pokud chceš, můžeš brát CVE z env jako CSV: CVE_LIST="CVE-2020-1938,CVE-2023-20862"
    cve_list_env = os.getenv("CVE_LIST", "").strip()
    if cve_list_env:
        cve_list = [x.strip() for x in cve_list_env.split(",") if x.strip()]
    else:
        cve_list = openvas_cves[:]  # bereš tvůj list

    # de-dup + normalizace
    cve_list = sorted({c.upper().strip() for c in cve_list if c})

    print(f"[INPUT] CVEs: {len(cve_list)}")
    print(f"[INPUT] HOPS={HOPS} PAGE_SIZE={PAGE_SIZE}")

    # --- AGGREGACE pro Neo4j ---
    all_nodes: Dict[str, Node] = {}
    all_edges: Dict[str, Edge] = {}

    # --- STATISTIKY ---
    missing: List[str] = []
    processed: List[str] = []

    for cve_name in cve_list:
        print("\n" + "=" * 80)
        print("[CVE]", cve_name)

        # 1) najdi CVE v OpenCTI
        try:
            cve = get_cve_by_name(cve_name)
        except SystemExit:
            print(f"[SKIP] CVE nenalezeno v OpenCTI: {cve_name}")
            missing.append(cve_name)
            continue

        cve_id = cve["id"]
        processed.append(cve_name)
        print(f"CVE: {cve.get('name')} id: {cve_id}")

        # 2) direct relationships (rychlý overview)
        rels_to = list_relationships_to_id(cve_id)
        rels_from = list_relationships_from_id(cve_id)
        rels = rels_to + rels_from

        rel_types = sorted({r.get("relationship_type") for r in rels if r.get("relationship_type")})
        print("rels_total:", len(rels), "relationship_types:", rel_types)

        # 3) direct "other side" objects
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

        # 4) BFS expand z CVE (seed)
        nodes, edges = expand_from_seed_ids([cve_id], hops=HOPS)

        # zaruč CVE uzel
        nodes[cve_id] = Node(id=cve_id, entity_type="Vulnerability", name=cve.get("name") or cve_name)

        # 5) MALWARE EXTENSION -> doplň do nodes/edges (aby se to propsalo do Neo4j)
        print("=== Malware expansion (find group/actor/campaign) ===")
        for o in direct_objs:
            if o.get("entity_type") != "Malware":
                continue

            malware_id = o["id"]
            malware_name = o.get("name")
            print(f"MALWARE: {malware_name} ({malware_id})")

            # incoming uses: IntrusionSet/ThreatActor/Campaign -> uses -> Malware
            incoming_uses = list_rels_to(malware_id, rel_type="uses")
            used_by = []
            for r in incoming_uses:
                src_id = rel_end_id(r, "from")
                src = client.stix_domain_object.read(id=src_id) if src_id else None
                if src and src.get("entity_type") in ("Intrusion-Set", "Threat-Actor", "Campaign"):
                    used_by.append(src)

            if used_by:
                print("  USED_BY (incoming uses):")
                for x in {u["id"]: u for u in used_by}.values():
                    print("    *", x["entity_type"], x.get("name"))

                    # ✅ přidej do lokálního grafu pro tento CVE
                    add_node_from_obj(nodes, x)  # Intrusion-Set / Threat-Actor / Campaign
                    add_node_from_obj(nodes, o)  # Malware
                    add_edge_simple(
                        edges,
                        rel_id=f"uses-{x['id']}-{malware_id}",
                        rel_type="uses",
                        from_id=x["id"],
                        to_id=malware_id,
                    )
            else:
                print("  USED_BY (incoming uses): nic")

            # outgoing attributed-to (pokud existuje)
            attributed = list_rels_from(malware_id, rel_type="attributed-to")
            attrib_to = []
            for r in attributed:
                dst_id = rel_end_id(r, "to")
                dst = client.stix_domain_object.read(id=dst_id) if dst_id else None
                if dst and dst.get("entity_type") in ("Intrusion-Set", "Threat-Actor"):
                    attrib_to.append(dst)

            if attrib_to:
                print("  ATTRIBUTED_TO:")
                for x in {a["id"]: a for a in attrib_to}.values():
                    print("    *", x["entity_type"], x.get("name"))
                    add_node_from_obj(nodes, x)
                    add_node_from_obj(nodes, o)
                    add_edge_simple(
                        edges,
                        rel_id=f"attributed-to-{malware_id}-{x['id']}",
                        rel_type="attributed-to",
                        from_id=malware_id,
                        to_id=x["id"],
                    )
            else:
                print("  ATTRIBUTED_TO: nic")

        # 6) sloučení do globální agregace (MERGE přes opencti_id)
        all_nodes.update(nodes)
        all_edges.update(edges)

        print(f"[CVE DONE] nodes={len(nodes)} edges={len(edges)}")

    # 7) ZÁVĚR: zapiš jednou do Neo4j
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
      - uzly: (vše) jako :StixEntity s opencti_id + entity_type + name
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

    # Constraints (spusť jednou; tady safe IF NOT EXISTS)
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
        # "Intrusion-Set" -> "IntrusionSet", "Attack-Pattern" -> "AttackPattern"
        return (entity_type or "Unknown").replace("-", "")

    def upsert_node(tx, n: Node):
        et = n.entity_type or "Unknown"
        name = (n.name or "").strip()

        def to_neo4j_label(entity_type: str) -> str:
            return (entity_type or "Unknown").replace("-", "")

        # --- SPECIAL CASE: Vulnerability / CVE ---
        if et == "Vulnerability" and name.upper().startswith("CVE-"):
            cve = name.upper()

            # 1) STIX uzel (OpenCTI) – samostatný CVE uzel pro CTI část grafu
            tx.run(
                """
                MERGE (e:StixEntity {opencti_id: $id})
                SET e:OpenCTI_Vulnerability,
                    e.name = $name,
                    e.entity_type = 'Vulnerability'
                """,
                id=n.id,
                name=cve,
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

            # 3) šipka business -> STIX (to chceš do vizualizace)
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
                e.entity_type = $etype
            """,
            id=n.id,
            name=name or n.id,
            etype=et,
        )

    def upsert_edge(tx, e: Edge):
        reltype = e.relationship_type.upper().replace("-", "_")

        def resolve_endpoint(oid: str):
            # Pokud je to OpenCTI vulnerability id, mapuj na business Vulnerability(cve)
            if oid in vuln_id_to_cve:
                return ("Vulnerability", "cve", vuln_id_to_cve[oid])
            # Jinak běžný STIX uzel
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

    # DŮLEŽITÉ: zapisuj do DB_NAME
    with driver.session(database=NEO4J_DB ) as session:
        session.execute_write(create_constraints)

        for n in nodes.values():
            session.execute_write(upsert_node, n)

        for e in edges.values():
            session.execute_write(upsert_edge, e)  # ✅

    driver.close()
    print(f"[Neo4j] Import hotový do DB '{NEO4J_DB }'.")


if __name__ == "__main__":
    main()
