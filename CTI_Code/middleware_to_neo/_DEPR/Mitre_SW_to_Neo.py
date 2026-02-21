import json
import re
from pathlib import Path
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from neo4j import GraphDatabase
from dotenv import load_dotenv
import os

load_dotenv()
# OpenCTI connection
OPENCTI_URL = os.getenv("OPENCTI_URL")
OPENCTI_TOKEN = os.getenv("OPENCTI_TOKEN")
NEO4J_URI = os.getenv("NEO4J_URI")
NEO4J_USER = os.getenv("NEO4J_USER")
NEO4J_PASS = os.getenv("NEO4J_PASS")
NEO4J_DB   = os.getenv("NEO4J_DB")



driver = GraphDatabase.driver(
    NEO4J_URI,
    auth=(NEO4J_USER, NEO4J_PASS)
)

with driver.session(database=NEO4J_DB) as session:
    result = session.run("RETURN 1 AS ok")
    print("Connected, result:", result.single()["ok"])

driver.close()
# stáhni enterprise-attack.json z MITRE ATT&CK STIX datasetu a dej sem cestu
ATTACK_JSON_PATH = Path("D:\_DIPLOMKA\DATA\mitre.json")


# Mapování OpenCTI Malware -> MITRE Software: jen exact match
MAP_ONLY_EXACT = True


# =========================
# TEXT NORMALIZATION
# =========================
_nonword = re.compile(r"[^a-z0-9]+")

def norm(s: str) -> str:
    s = (s or "").lower().strip()
    return _nonword.sub("", s)  # odstraní mezery, pomlčky, tečky...


def as_str_list(v: Any) -> List[str]:
    if not v:
        return []
    if isinstance(v, list):
        return [x.strip() for x in v if isinstance(x, str) and x.strip()]
    return []


def get_external_id(obj: dict, prefix: str) -> Optional[str]:
    """
    MITRE IDs jsou v external_references[].external_id:
      - Software: Sxxxx
      - Groups: Gxxxx
      - Techniques: Txxxx
    """
    for ref in obj.get("external_references", []) or []:
        ext_id = ref.get("external_id")
        if isinstance(ext_id, str) and ext_id.startswith(prefix):
            return ext_id.strip()
    return None


def get_tactics(obj: dict) -> List[str]:
    tactics = []
    for kcp in obj.get("kill_chain_phases", []) or []:
        if kcp.get("kill_chain_name") == "mitre-attack":
            pn = kcp.get("phase_name")
            if isinstance(pn, str) and pn.strip():
                tactics.append(pn.strip())
    # unique preserve order
    out = []
    for t in tactics:
        if t not in out:
            out.append(t)
    return out


# =========================
# NEO4J SCHEMA
# =========================
def ensure_schema(session) -> None:
    # MITRE software unikátně podle Sxxxx
    session.run("""
    CREATE CONSTRAINT mitre_software_mitre_id_unique IF NOT EXISTS
    FOR (n:MitreSoftware) REQUIRE n.mitre_id IS UNIQUE
    """)

    # MITRE group unikátně podle Gxxxx (pokud už máš, neuškodí)
    session.run("""
    CREATE CONSTRAINT mitre_intrusionset_mitre_id_unique IF NOT EXISTS
    FOR (n:MitreIntrusionSet) REQUIRE n.mitre_id IS UNIQUE
    """)

    # MITRE technique unikátně podle Txxxx/Txxxx.yyy (pokud už máš, neuškodí)
    session.run("""
    CREATE CONSTRAINT attack_pattern_mitre_id_unique IF NOT EXISTS
    FOR (n:AttackPattern) REQUIRE n.mitre_id IS UNIQUE
    """)

    # index pro rychlé lookupy
    session.run("""
    CREATE INDEX malware_standard_id_idx IF NOT EXISTS
    FOR (n:Malware) ON (n.standard_id)
    """)


# =========================
# IMPORT: MITRE SOFTWARE (malware + tool)
# =========================
def import_mitre_software(session, stix_objects: List[dict]) -> int:
    """
    MITRE ATT&CK Software je v STIX jako:
      - type='malware'
      - type='tool'
    Obě mají MITRE external_id Sxxxx
    """
    sw = [
        o for o in stix_objects
        if isinstance(o, dict)
        and o.get("type") in ("malware", "tool")
        and not o.get("revoked", False)
        and not o.get("x_mitre_deprecated", False)
    ]

    imported, skipped = 0, 0

    for o in sw:
        mitre_id = get_external_id(o, "S")
        if not mitre_id:
            skipped += 1
            continue

        props = {
            "mitre_id": mitre_id,
            "stix_id": o.get("id"),
            "name": o.get("name"),
            "description": o.get("description"),
            "type": o.get("type"),  # malware|tool
            "platforms": as_str_list(o.get("x_mitre_platforms")),
            "aliases": as_str_list(o.get("x_mitre_aliases")) + as_str_list(o.get("aliases")),
            "created": o.get("created"),
            "modified": o.get("modified"),
        }

        # idempotentní upsert podle Sxxxx
        session.run("""
        MERGE (n:MitreSoftware {mitre_id: $mitre_id})
        SET n:AttackObject
        SET n.name = coalesce($name, n.name)
        SET n.description = coalesce($description, n.description)
        SET n.software_type = coalesce($type, n.software_type)
        SET n.platforms = CASE WHEN size($platforms) > 0 THEN $platforms ELSE coalesce(n.platforms, []) END
        SET n.aliases = CASE WHEN size($aliases) > 0 THEN $aliases ELSE coalesce(n.aliases, []) END
        SET n.created = coalesce($created, n.created)
        SET n.modified = coalesce($modified, n.modified)
        SET n.stix_id = coalesce(n.stix_id, $stix_id)
        """, **props)

        imported += 1

    print(f"[+] MITRE software objects (malware+tool) in bundle: {len(sw)}")
    print(f"[+] Imported/Upserted MitreSoftware: {imported}")
    print(f"[i] Skipped (no Sxxxx): {skipped}")
    return imported


# =========================
# IMPORT: MITRE RELATIONSHIPS "uses"
# =========================
def build_stix_to_mitre_maps(stix_objects: List[dict]) -> Tuple[Dict[str, str], Dict[str, str], Dict[str, str]]:
    """
    Vrátí mapy:
      intrusion-set STIX id -> Gxxxx
      software STIX id -> Sxxxx
      attack-pattern STIX id -> Txxxx(.yyy)
    """
    g_map: Dict[str, str] = {}
    s_map: Dict[str, str] = {}
    t_map: Dict[str, str] = {}

    for o in stix_objects:
        if not isinstance(o, dict):
            continue
        oid = o.get("id")
        if not isinstance(oid, str) or not oid:
            continue

        if o.get("type") == "intrusion-set":
            mid = get_external_id(o, "G")
            if mid:
                g_map[oid] = mid
        elif o.get("type") in ("malware", "tool"):
            mid = get_external_id(o, "S")
            if mid:
                s_map[oid] = mid
        elif o.get("type") == "attack-pattern":
            mid = get_external_id(o, "T")
            if mid:
                t_map[oid] = mid

    return g_map, s_map, t_map


def import_mitre_uses_relationships(session, stix_objects: List[dict]) -> int:
    """
    Importuje relationship_type='uses' z MITRE STIX.
    Napojí podle MITRE ID:
      MitreIntrusionSet(G) -[:USES]-> MitreSoftware(S)
      MitreIntrusionSet(G) -[:USES]-> AttackPattern(T)
      MitreSoftware(S)     -[:USES]-> AttackPattern(T)
      MitreSoftware(S)     -[:USES]-> MitreSoftware(S) (vzácné, ale může být)
    """
    rels = [
        o for o in stix_objects
        if isinstance(o, dict)
        and o.get("type") == "relationship"
        and o.get("relationship_type") == "uses"
        and not o.get("revoked", False)
    ]

    g_map, s_map, t_map = build_stix_to_mitre_maps(stix_objects)

    imported = 0
    for r in rels:
        src = r.get("source_ref")
        dst = r.get("target_ref")
        rid = r.get("id")
        if not (isinstance(src, str) and isinstance(dst, str) and isinstance(rid, str)):
            continue

        # Resolve source/target to node labels + ids
        src_g = g_map.get(src)
        src_s = s_map.get(src)

        dst_t = t_map.get(dst)
        dst_s = s_map.get(dst)

        # Group -> Software
        if src_g and dst_s:
            session.run("""
            MATCH (a:MitreIntrusionSet {mitre_id: $src})
            MATCH (b:MitreSoftware {mitre_id: $dst})
            MERGE (a)-[rel:USES]->(b)
            SET rel.stix_id = $rid, rel.source = 'MITRE'
            """, src=src_g, dst=dst_s, rid=rid)
            imported += 1
            continue

        # Group -> Technique
        if src_g and dst_t:
            session.run("""
            MATCH (a:MitreIntrusionSet {mitre_id: $src})
            MATCH (b:AttackPattern {mitre_id: $dst})
            MERGE (a)-[rel:USES]->(b)
            SET rel.stix_id = $rid, rel.source = 'MITRE'
            """, src=src_g, dst=dst_t, rid=rid)
            imported += 1
            continue

        # Software -> Technique
        if src_s and dst_t:
            session.run("""
            MATCH (a:MitreSoftware {mitre_id: $src})
            MATCH (b:AttackPattern {mitre_id: $dst})
            MERGE (a)-[rel:USES]->(b)
            SET rel.stix_id = $rid, rel.source = 'MITRE'
            """, src=src_s, dst=dst_t, rid=rid)
            imported += 1
            continue

        # Software -> Software (rare)
        if src_s and dst_s:
            session.run("""
            MATCH (a:MitreSoftware {mitre_id: $src})
            MATCH (b:MitreSoftware {mitre_id: $dst})
            MERGE (a)-[rel:USES]->(b)
            SET rel.stix_id = $rid, rel.source = 'MITRE'
            """, src=src_s, dst=dst_s, rid=rid)
            imported += 1
            continue

    print(f"[+] MITRE uses relationship objects in bundle: {len(rels)}")
    print(f"[+] Imported/Upserted USES edges (resolved): {imported}")
    return imported


# =========================
# MAPPING: OpenCTI Malware -> MitreSoftware (exact name only)
# =========================
def load_mitre_software_name_index(session) -> Dict[str, str]:
    """
    Vytvoří mapu norm(name_or_alias) -> Sxxxx
    """
    idx: Dict[str, str] = {}
    q = """
    MATCH (s:MitreSoftware)
    RETURN s.mitre_id AS id, s.name AS name, s.aliases AS aliases
    """
    for r in session.run(q):
        sid = r["id"]
        name = r.get("name") or ""
        aliases = r.get("aliases") or []
        if isinstance(name, str) and name.strip():
            idx[norm(name)] = sid
        if isinstance(aliases, list):
            for a in aliases:
                if isinstance(a, str) and a.strip():
                    idx[norm(a)] = sid
    return idx


def map_opencti_malware_to_mitre(session) -> Dict[str, int]:
    """
    Mapuje vaše existující :Malware uzly (OpenCTI) na :MitreSoftware přes exact match.
    Vytvoří hrany: (m:Malware)-[:MAPPED_TO {method, updated_at}]->(s:MitreSoftware)
    """
    idx = load_mitre_software_name_index(session)
    now = datetime.now(timezone.utc).isoformat()

    q = """
    MATCH (m:Malware)
    RETURN m.opencti_id AS opencti_id, m.standard_id AS standard_id, m.name AS name
    """
    rows = list(session.run(q))

    mapped = 0
    no_name = 0
    no_match = 0

    for r in rows:
        name = r.get("name") or ""
        if not isinstance(name, str) or not name.strip():
            no_name += 1
            continue

        key = norm(name)
        mitre_sid = idx.get(key)
        if not mitre_sid:
            no_match += 1
            continue

        session.run("""
        MATCH (m:Malware {standard_id: $standard_id})
        MATCH (s:MitreSoftware {mitre_id: $mitre_id})
        MERGE (m)-[rel:MAPPED_TO]->(s)
        SET rel.method = 'name-exact',
            rel.updated_at = $now
        """, standard_id=r.get("standard_id"), mitre_id=mitre_sid, now=now)

        mapped += 1

    return {
        "total_opencti_malware": len(rows),
        "mapped": mapped,
        "no_name": no_name,
        "no_match": no_match,
    }


# =========================
# MAIN
# =========================
def main():
    if not ATTACK_JSON_PATH.exists():
        raise FileNotFoundError(f"Missing file: {ATTACK_JSON_PATH.resolve()}")

    bundle = json.loads(ATTACK_JSON_PATH.read_text(encoding="utf-8"))
    objects = bundle.get("objects", [])
    if not isinstance(objects, list):
        raise ValueError("STIX bundle does not contain 'objects' list")

    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASS))
    try:
        with driver.session(database=NEO4J_DB) as session:
            ensure_schema(session)

            # 1) Import software
            import_mitre_software(session, objects)

            # 2) Import USES relationships (needs groups+techniques present too; if not, část edges se nenaimportuje)
            import_mitre_uses_relationships(session, objects)

            # 3) Map your OpenCTI Malware -> MitreSoftware (exact name only)
            stats = map_opencti_malware_to_mitre(session)
            print("[=] Malware mapping stats:", stats)

            # quick counts
            c_sw = session.run("MATCH (s:MitreSoftware) RETURN count(s) AS c").single()["c"]
            c_uses = session.run("MATCH ()-[r:USES]->() RETURN count(r) AS c").single()["c"]
            c_map = session.run("MATCH (:Malware)-[r:MAPPED_TO]->(:MitreSoftware) RETURN count(r) AS c").single()["c"]
            print(f"[=] MitreSoftware nodes: {c_sw}")
            print(f"[=] USES edges (MITRE): {c_uses}")
            print(f"[=] Malware->MitreSoftware MAPPED_TO edges: {c_map}")

    finally:
        driver.close()


if __name__ == "__main__":
    main()