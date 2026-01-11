from __future__ import annotations

import os
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple
from collections import Counter

from pycti import OpenCTIApiClient

#tento kod ted zkousi metadata do neo4j 11.1.2026s
# ----------------------------
# LOGGING (quiet)
# ----------------------------
logging.basicConfig(level=logging.WARNING)
logging.getLogger("api").setLevel(logging.WARNING)
logging.getLogger("pycti").setLevel(logging.WARNING)

# ----------------------------
# INPUT
# ----------------------------


#CVE-2023-20862 - muj vlastni CVE z OpenVAS
#CVE-2024-21887 - nejkrasnejsi CVE z OpenCTI
openvas_cves = [
    "CVE-2024-21887","CVE-2023-20862"
]

HOPS = int(os.getenv("HOPS", "1"))
PAGE_SIZE = int(os.getenv("PAGE_SIZE", "200"))

OPENCTI_URL = os.getenv("OPENCTI_URL", "http://localhost:8080/graphql")
OPENCTI_TOKEN = os.getenv("OPENCTI_TOKEN", "2cf990a2-5b35-4894-a214-da959ee51b31")

NEO4J_URI = os.getenv("NEO4J_URI", "bolt://127.0.0.1:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASS = os.getenv("NEO4J_PASS", "82008200aA")
DB_NAME = os.getenv("NEO4J_DB", "metatest")

SDO_CUSTOM_ATTRS = """
id
entity_type
name
standard_id
created
modified
confidence
revoked
externalReferences {
  source_name
  external_id
  url
}
objectLabel {
  value
}
aliases
x_mitre_id
x_mitre_platforms
x_mitre_is_subtechnique
killChainPhases {
  kill_chain_name
  phase_name
}
is_family
malware_types
architecture_execution_envs
first_seen
last_seen
"""

REL_CUSTOM_ATTRS = """
id
relationship_type
confidence
start_time
stop_time
fromId
toId
"""

# ----------------------------
# OpenCTI client (pycti)
# ----------------------------
client = OpenCTIApiClient(OPENCTI_URL, OPENCTI_TOKEN)

# ----------------------------
# Dataclasses
# ----------------------------
@dataclass(frozen=True)
class Node:
    id: str
    entity_type: str
    name: str
    props: Dict[str, Any] = field(default_factory=dict)

@dataclass(frozen=True)
class Edge:
    id: str
    relationship_type: str
    from_id: str
    to_id: str
    props: Dict[str, Any] = field(default_factory=dict)

# ----------------------------
# Helpers
# ----------------------------
def normalize_rel_type(rt: Optional[str]) -> str:
    return (rt or "related-to").lower()

def rel_end_id(rel: dict, side: str) -> Optional[str]:
    """
    side: 'from' | 'to'
    supports:
      rel['fromId']/rel['toId']
      rel['from']['id']/rel['to']['id']
    """
    key_id = f"{side}Id"
    if rel.get(key_id):
        return rel.get(key_id)
    side_obj = rel.get(side)
    if isinstance(side_obj, dict) and side_obj.get("id"):
        return side_obj["id"]
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
    return obj.get("entity_type") or obj.get("type") or "Unknown"

def safe_name(obj: dict) -> str:
    return obj.get("name") or obj.get("value") or obj.get("standard_id") or obj.get("id") or "Unnamed"

def strip_nones(d: Dict[str, Any]) -> Dict[str, Any]:
    """Neo4j nemá rád null hodnoty v SET += map."""
    out: Dict[str, Any] = {}
    for k, v in d.items():
        if v is None:
            continue
        if isinstance(v, list):
            vv = [x for x in v if x is not None]
            if vv == []:
                continue
            out[k] = vv
        else:
            out[k] = v
    return out

def extract_source_names(external_refs: Any) -> List[str]:
    """
    External references v OpenCTI bývají list dictů, typicky:
      [{"source_name":"mitre-attack","external_id":"T1222", ...}, ...]
    """
    if not isinstance(external_refs, list):
        return []
    srcs = []
    for r in external_refs:
        if isinstance(r, dict) and r.get("source_name"):
            srcs.append(r["source_name"])
    # unique preserve order
    seen = set()
    uniq = []
    for s in srcs:
        if s not in seen:
            uniq.append(s)
            seen.add(s)
    return uniq

def find_external_id(external_refs: Any, preferred_sources: List[str]) -> Optional[str]:
    """
    Zkus najít external_id podle preferovaných source_name (např. cve, mitre-attack, malpedia).
    """
    if not isinstance(external_refs, list):
        return None
    # 1) preferované zdroje
    for ps in preferred_sources:
        for r in external_refs:
            if isinstance(r, dict) and r.get("source_name") == ps and r.get("external_id"):
                return r["external_id"]
    # 2) fallback: první external_id
    for r in external_refs:
        if isinstance(r, dict) and r.get("external_id"):
            return r["external_id"]
    return None

def looks_like_cve(name: str) -> bool:
    return (name or "").upper().startswith("CVE-")

def guess_kev(obj: dict) -> Tuple[Optional[bool], Optional[str]]:
    """
    Best-effort detekce, protože závisí na tom, jak CISA KEV connector mapuje do OpenCTI.
    Zkouší:
      - label/tag obsahující 'kev' / 'known exploited'
      - external_reference source_name obsahující 'cisa'/'kev'
    """
    labels = obj.get("objectLabel") or obj.get("labels") or []
    # OpenCTI někdy vrací objectLabel jako list dictů {"value": "..."}
    label_values: List[str] = []
    if isinstance(labels, list):
        for x in labels:
            if isinstance(x, dict) and x.get("value"):
                label_values.append(str(x["value"]).lower())
            elif isinstance(x, str):
                label_values.append(x.lower())

    external_refs = obj.get("external_references") or obj.get("externalReferences") or []
    srcs = [s.lower() for s in extract_source_names(external_refs)]

    kev_hit = any("kev" in lv or "known exploited" in lv for lv in label_values) or any(
        ("cisa" in s and "kev" in s) or ("known" in s and "exploited" in s) or (s == "cisa-kev")
        for s in srcs
    )

    # datum přidání se může někdy objevit v "x_opencti_*" nebo notes – nebudu si vymýšlet.
    # Pokud to máš v OpenCTI jako field, doplň si sem mapování.
    kev_added = obj.get("x_opencti_kev_added") or obj.get("x_opencti_cisa_kev_added")  # best-effort
    return (True if kev_hit else None), (kev_added if isinstance(kev_added, str) else None)

# ----------------------------
# OpenCTI fetch
# ----------------------------
def get_cve_by_name(cve_name: str) -> dict:
    cve = client.vulnerability.read(
        filters={
            "mode": "and",
            "filters": [{"key": "name", "values": [cve_name]}],
            "filterGroups": [],
        },
        customAttributes=SDO_CUSTOM_ATTRS,  # <<<<<< KLÍČOVÉ
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
        customAttributes=REL_CUSTOM_ATTRS,
    )

def list_relationships_from_id(object_id: str, rel_type: Optional[str] = None) -> List[dict]:
    filters_list = [{"key": "fromId", "values": [object_id]}]
    if rel_type:
        filters_list.insert(0, {"key": "relationship_type", "values": [rel_type]})

    return client.stix_core_relationship.list(
        filters={"mode": "and", "filters": filters_list, "filterGroups": []},
        first=PAGE_SIZE,
        get_all=True,
        customAttributes=REL_CUSTOM_ATTRS,
    )

def read_any(obj_id: str) -> Optional[dict]:
    # 1) Zkus SDO
    try:
        x = client.stix_domain_object.read(id=obj_id)
        if x:
            return x
    except Exception:
        pass

    # 2) Zkus CoreObject (coverne i observables apod.)
    try:
        x = client.stix_core_object.read(id=obj_id)
        if x:
            return x
    except Exception:
        pass

    return None

# ----------------------------
# Metadata extraction (core)
# ----------------------------
def extract_metadata(obj: dict) -> Dict[str, Any]:
    """
    Tady rozhodujeme, co z OpenCTI chceme promítnout do Neo4j (useful metadata).
    """
    et = safe_entity_type(obj)
    name = safe_name(obj)

    external_refs = obj.get("external_references") or obj.get("externalReferences") or []
    sources = extract_source_names(external_refs)

    base: Dict[str, Any] = {
        "name": name,
        "entity_type": et,
        "standard_id": obj.get("standard_id"),
        "confidence": obj.get("confidence"),
        "created": obj.get("created"),
        "modified": obj.get("modified"),
        "revoked": obj.get("revoked"),
        "sources": sources,  # list
    }

    # Type-specific extras
    if et == "Vulnerability":
        cve_id = None
        # prefer CVE external_id if present
        cve_id = find_external_id(external_refs, preferred_sources=["cve", "nvd", "mitre"])
        if not cve_id and looks_like_cve(name):
            cve_id = name.upper()

        # OpenCTI má různá pole dle verzí/connectorů: best-effort
        cvss = (
            obj.get("x_opencti_cvss_base_score")
            or obj.get("x_opencti_cvss_score")
            or obj.get("cvss_base_score")
        )
        severity = (
            obj.get("x_opencti_cvss_base_severity")
            or obj.get("x_opencti_cvss_severity")
            or obj.get("cvss_base_severity")
        )
        epss_score = obj.get("x_opencti_epss_score") or obj.get("epss_score")
        epss_percentile = obj.get("x_opencti_epss_percentile") or obj.get("epss_percentile")

        kev, kev_added = guess_kev(obj)

        base.update(
            {
                "cve_id": cve_id,
                "cvss_base_score": cvss,
                "cvss_severity": severity,
                "epss_score": epss_score,
                "epss_percentile": epss_percentile,
                "cisa_kev": kev,
                "kev_added": kev_added,
            }
        )

    elif et == "Attack-Pattern":
        # MITRE technique ID
        mitre_id = obj.get("x_mitre_id") or find_external_id(external_refs, preferred_sources=["mitre-attack"])
        tactics = []

        # kill_chain_phases: list dicts {kill_chain_name, phase_name}
        kcp = obj.get("kill_chain_phases") or obj.get("killChainPhases") or []
        if isinstance(kcp, list):
            for x in kcp:
                if isinstance(x, dict) and x.get("phase_name"):
                    tactics.append(x["phase_name"])

        platforms = obj.get("x_mitre_platforms") or obj.get("x_mitre_platforms_list") or obj.get("platforms")
        is_sub = obj.get("x_mitre_is_subtechnique")

        base.update(
            {
                "mitre_id": mitre_id,
                "tactics": list(dict.fromkeys([t for t in tactics if t])),
                "platforms": platforms if isinstance(platforms, list) else ([platforms] if isinstance(platforms, str) else None),
                "is_subtechnique": is_sub,
            }
        )

    elif et == "Malware":
        aliases = obj.get("aliases")
        malware_types = obj.get("malware_types") or obj.get("malwareTypes")
        is_family = obj.get("is_family") or obj.get("isFamily")
        platforms = obj.get("x_mitre_platforms") or obj.get("platforms")
        arch_env = obj.get("architecture_execution_envs") or obj.get("architectureExecutionEnvs")

        catalog_id = find_external_id(external_refs, preferred_sources=["malpedia", "virus-total", "mitre"])
        base.update(
            {
                "catalog_id": catalog_id,
                "aliases": aliases if isinstance(aliases, list) else None,
                "malware_types": malware_types if isinstance(malware_types, list) else None,
                "is_family": is_family,
                "platforms": platforms if isinstance(platforms, list) else ([platforms] if isinstance(platforms, str) else None),
                "architecture_execution_envs": arch_env if isinstance(arch_env, list) else None,
            }
        )

    elif et == "Intrusion-Set":
        aliases = obj.get("aliases")
        base.update(
            {
                "aliases": aliases if isinstance(aliases, list) else None,
                "first_seen": obj.get("first_seen") or obj.get("firstSeen"),
                "last_seen": obj.get("last_seen") or obj.get("lastSeen"),
            }
        )

    elif et == "Threat-Actor":
        aliases = obj.get("aliases")
        base.update(
            {
                "aliases": aliases if isinstance(aliases, list) else None,
                "first_seen": obj.get("first_seen") or obj.get("firstSeen"),
                "last_seen": obj.get("last_seen") or obj.get("lastSeen"),
            }
        )

    return strip_nones(base)

def node_from_obj(obj: dict) -> Node:
    oid = obj.get("id")
    et = safe_entity_type(obj)
    nm = safe_name(obj)
    props = extract_metadata(obj)
    return Node(id=oid, entity_type=et, name=nm, props=props)

# ----------------------------
# Graph expansion (BFS)
# ----------------------------
def expand_from_seed_ids(seed_ids: List[str], hops: int) -> Tuple[Dict[str, Node], Dict[str, Edge]]:
    nodes: Dict[str, Node] = {}
    edges: Dict[str, Edge] = {}

    visited: Set[str] = set()
    frontier: List[Tuple[str, int]] = [(sid, 0) for sid in seed_ids]

    while frontier:
        current_id, depth = frontier.pop(0)
        if current_id in visited:
            continue
        visited.add(current_id)

        obj = read_any(current_id)

        if obj:
            n = node_from_obj(obj)
            nodes[current_id] = n
        else:
            nodes[current_id] = Node(
                id=current_id,
                entity_type="Unknown",
                name=current_id,
                props={"name": current_id, "entity_type": "Unknown"},
            )

        if depth >= hops:
            continue

        # outgoing
        out_rels = list_relationships_from_id(current_id)
        for r in out_rels:
            rid = r.get("id") or f"{current_id}-out-{len(edges)}"
            rt = normalize_rel_type(r.get("relationship_type"))
            f = rel_end_id(r, "from")
            t = rel_end_id(r, "to")
            if not f or not t:
                continue

            edges[rid] = Edge(
                id=rid,
                relationship_type=rt,
                from_id=f,
                to_id=t,
                props=strip_nones(
                    {
                        "opencti_id": rid,
                        "relationship_type": rt,
                        "confidence": r.get("confidence"),
                        "start_time": r.get("start_time") or r.get("startTime"),
                        "stop_time": r.get("stop_time") or r.get("stopTime"),
                    }
                ),
            )

            if t not in visited:
                frontier.append((t, depth + 1))

        # incoming only at depth 0 (CVE layer)
        if depth == 0:
            in_rels = list_relationships_to_id(current_id)
            for r in in_rels:
                rid = r.get("id") or f"{current_id}-in-{len(edges)}"
                rt = normalize_rel_type(r.get("relationship_type"))
                f = rel_end_id(r, "from")
                t = rel_end_id(r, "to")
                if not f or not t:
                    continue

                edges[rid] = Edge(
                    id=rid,
                    relationship_type=rt,
                    from_id=f,
                    to_id=t,
                    props=strip_nones(
                        {
                            "opencti_id": rid,
                            "relationship_type": rt,
                            "confidence": r.get("confidence"),
                            "start_time": r.get("start_time") or r.get("startTime"),
                            "stop_time": r.get("stop_time") or r.get("stopTime"),
                        }
                    ),
                )

                if f not in visited:
                    frontier.append((f, depth + 1))

    return nodes, edges

# ----------------------------
# Malware extension (intrusion set / threat actor / campaign -> uses -> malware, etc.)
# ----------------------------
def fg(filters):
    return {"mode": "and", "filters": filters, "filterGroups": []}

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

def add_node(nodes: Dict[str, Node], obj: dict) -> None:
    if not obj or not obj.get("id"):
        return
    nodes[obj["id"]] = node_from_obj(obj)

def add_edge(
    edges: Dict[str, Edge],
    rel_id: str,
    rel_type: str,
    from_id: str,
    to_id: str,
    props: Optional[Dict[str, Any]] = None,
) -> None:
    if not from_id or not to_id:
        return
    edges[rel_id] = Edge(
        id=rel_id,
        relationship_type=normalize_rel_type(rel_type),
        from_id=from_id,
        to_id=to_id,
        props=strip_nones(props or {"opencti_id": rel_id, "relationship_type": normalize_rel_type(rel_type)}),
    )

# ----------------------------
# Neo4j writing (idempotent) with metadata
# ----------------------------
def write_to_neo4j(nodes: Dict[str, Node], edges: Dict[str, Edge]) -> None:
    """
    Idempotentní zápis do Neo4j:
      - uzly: :StixEntity + typový label (AttackPattern/Malware/...)
        + properties map (SET e += $props)
      - CVE navíc: :Vulnerability {cve} jako "business node" (volitelné) a metadata i na něm
      - hrany: reltype uppercase; SET r += $props
    """
    from neo4j import GraphDatabase

    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASS))

    # Constraints (safe IF NOT EXISTS)
    constraint_cypher = [
        """
        CREATE CONSTRAINT stix_opencti_id_unique IF NOT EXISTS
        FOR (e:StixEntity) REQUIRE e.opencti_id IS UNIQUE
        """,
        """
        CREATE CONSTRAINT vuln_cve_unique IF NOT EXISTS
        FOR (v:Vulnerability) REQUIRE v.cve IS UNIQUE
        """,
        # Doporučené (volitelné): technique ID
        """
        CREATE CONSTRAINT attackpattern_mitre_id_unique IF NOT EXISTS
        FOR (t:AttackPattern) REQUIRE t.mitre_id IS UNIQUE
        """,
    ]

    def create_constraints(tx):
        for q in constraint_cypher:
            tx.run(q)

    def to_neo4j_label(entity_type: str) -> str:
        # "Intrusion-Set" -> "IntrusionSet", "Attack-Pattern" -> "AttackPattern"
        return (entity_type or "Unknown").replace("-", "")

    def upsert_node(tx, n: Node):
        label = to_neo4j_label(n.entity_type)
        props = strip_nones(dict(n.props or {}))
        # vždycky ukládej opencti_id (pro MERGE) + základ
        props["opencti_id"] = n.id
        props.setdefault("name", n.name)
        props.setdefault("entity_type", n.entity_type)

        tx.run(
            f"""
            MERGE (e:StixEntity {{opencti_id: $id}})
            SET e:{label}
            SET e += $props
            """,
            id=n.id,
            props=props,
        )

        # Volitelný "business" node pro CVE, pokud to je Vulnerability a má cve_id
        if n.entity_type == "Vulnerability":
            cve_id = props.get("cve_id")
            if isinstance(cve_id, str) and cve_id.upper().startswith("CVE-"):
                # meta pro business node
                vprops = strip_nones(
                    {
                        "cve": cve_id.upper(),
                        "opencti_id": n.id,
                        "name": cve_id.upper(),
                        "cvss_base_score": props.get("cvss_base_score"),
                        "cvss_severity": props.get("cvss_severity"),
                        "epss_score": props.get("epss_score"),
                        "epss_percentile": props.get("epss_percentile"),
                        "cisa_kev": props.get("cisa_kev"),
                        "kev_added": props.get("kev_added"),
                        "modified": props.get("modified"),
                        "created": props.get("created"),
                        "sources": props.get("sources"),
                    }
                )

                tx.run(
                    """
                    MERGE (v:Vulnerability {cve: $cve})
                    SET v += $vprops
                    """,
                    cve=cve_id.upper(),
                    vprops=vprops,
                )
                tx.run(
                    """
                    MATCH (e:StixEntity {opencti_id: $id})
                    MATCH (v:Vulnerability {cve: $cve})
                    MERGE (e)-[:IS]->(v)
                    """,
                    id=n.id,
                    cve=cve_id.upper(),
                )

    def upsert_edge(tx, e: Edge):
        reltype = e.relationship_type.upper().replace("-", "_")

        tx.run(
            """
            MERGE (a:StixEntity {opencti_id: $from_id})
            MERGE (b:StixEntity {opencti_id: $to_id})
            """,
            from_id=e.from_id,
            to_id=e.to_id,
        )

        props = strip_nones(dict(e.props or {}))
        props.setdefault("opencti_id", e.id)
        props.setdefault("relationship_type", e.relationship_type)

        tx.run(
            f"""
            MATCH (a:StixEntity {{opencti_id: $from_id}})
            MATCH (b:StixEntity {{opencti_id: $to_id}})
            MERGE (a)-[r:{reltype}]->(b)
            SET r += $props
            """,
            from_id=e.from_id,
            to_id=e.to_id,
            props=props,
        )

    with driver.session(database=DB_NAME) as session:
        session.execute_write(create_constraints)

        for n in nodes.values():
            session.execute_write(upsert_node, n)

        for e in edges.values():
            session.execute_write(upsert_edge, e)

    driver.close()
    print(f"[Neo4j] Import hotový do DB '{DB_NAME}'.")

# ----------------------------
# Main
# ----------------------------
def main():
    cve_list_env = os.getenv("CVE_LIST", "").strip()
    if cve_list_env:
        cve_list = [x.strip() for x in cve_list_env.split(",") if x.strip()]
    else:
        cve_list = openvas_cves[:]

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

        other_ids: List[str] = []
        for r in rels:
            oid = rel_other_id(r, cve_id)
            if oid:
                other_ids.append(oid)
        other_ids = list(set(other_ids))

        direct_objs: List[dict] = []
        for oid in other_ids:
            o = read_any(oid)
            if not o:
                print("[WARN] read_sdo returned None for id:", oid)
                continue

            print("KEYS:", sorted(list(o.keys()))[:60])
            print("HAS externalReferences:", "externalReferences" in o)
            print("HAS aliases:", "aliases" in o, "value:", o.get("aliases"))
            print("HAS x_mitre_id:", "x_mitre_id" in o, "value:", o.get("x_mitre_id"))
            print("HAS killChainPhases:", "killChainPhases" in o)
            if o:
                direct_objs.append(o)

        direct_types = Counter([safe_entity_type(o) for o in direct_objs])
        print("direct_entity_types:", dict(direct_types))

        # BFS expand
        nodes, edges = expand_from_seed_ids([cve_id], hops=HOPS)

        # ensure CVE node exists (with metadata)
        nodes[cve_id] = node_from_obj(cve)

        # Malware expansion: find group/actor/campaign that uses malware
        print("=== Malware expansion (find group/actor/campaign) ===")
        for o in direct_objs:
            if o.get("entity_type") != "Malware":
                continue

            malware_id = o["id"]
            malware_name = o.get("name")
            print(f"MALWARE: {malware_name} ({malware_id})")

            # incoming uses: IntrusionSet/ThreatActor/Campaign -> uses -> Malware
            incoming_uses = list_rels_to(malware_id, rel_type="uses")
            used_by: List[dict] = []
            for r in incoming_uses:
                src_id = rel_end_id(r, "from")
                src = read_any(src_id) if src_id else None
                if src and src.get("entity_type") in ("Intrusion-Set", "Threat-Actor", "Campaign"):
                    used_by.append(src)

            if used_by:
                print("  USED_BY (incoming uses):")
                uniq = {u["id"]: u for u in used_by}.values()
                for x in uniq:
                    print("    *", x["entity_type"], x.get("name"))

                    add_node(nodes, x)
                    add_node(nodes, o)
                    add_edge(
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
            attrib_to: List[dict] = []
            for r in attributed:
                dst_id = rel_end_id(r, "to")
                dst = read_any(dst_id) if dst_id else None
                if dst and dst.get("entity_type") in ("Intrusion-Set", "Threat-Actor"):
                    attrib_to.append(dst)

            if attrib_to:
                print("  ATTRIBUTED_TO:")
                uniq = {a["id"]: a for a in attrib_to}.values()
                for x in uniq:
                    print("    *", x["entity_type"], x.get("name"))

                    add_node(nodes, x)
                    add_node(nodes, o)
                    add_edge(
                        edges,
                        rel_id=f"attributed-to-{malware_id}-{x['id']}",
                        rel_type="attributed-to",
                        from_id=malware_id,
                        to_id=x["id"],
                    )
            else:
                print("  ATTRIBUTED_TO: nic")

        all_nodes.update(nodes)
        all_edges.update(edges)

        print(f"[CVE DONE] nodes={len(nodes)} edges={len(edges)}")

    print("\n" + "=" * 80)
    print(f"[SUMMARY] processed={len(processed)} missing={len(missing)}")
    if missing:
        print("[SUMMARY] missing CVEs (not in OpenCTI):", missing[:20], ("..." if len(missing) > 20 else ""))

    print(f"[Neo4j] writing aggregated graph: nodes={len(all_nodes)} edges={len(all_edges)}")
    write_to_neo4j(all_nodes, all_edges)

if __name__ == "__main__":
    main()
