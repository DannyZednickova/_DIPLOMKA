
import json
import re
from pathlib import Path
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from difflib import SequenceMatcher

from neo4j import GraphDatabase


NEO4J_URI = "bolt://127.0.0.1:7687"
NEO4J_USER = "neo4j"
NEO4J_PASS = "82008200aA"
NEO4J_DB = "openvastest"

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

#MITRE Group je kurátorovaný IntrusionSet s ID Gxxxx.
#IntrusionSet je obecný koncept – MITRE Group je jeho podmnožina.

# mapování vytvoří jen pokud score >= threshold
MAP_THRESHOLD = 0.92  # doporučuju 0.92–0.97 (nižší = víc false positive)


# =========================
# TEXT NORMALIZATION
# =========================
_nonword = re.compile(r"[^a-z0-9]+")

def norm(s: str) -> str:
    s = s.lower().strip()
    s = _nonword.sub("", s)  # odstraní mezery, pomlčky, tečky, atd.
    return s

def as_str_list(v: Any) -> List[str]:
    if not v:
        return []
    if isinstance(v, list):
        out = []
        for x in v:
            if isinstance(x, str) and x.strip():
                out.append(x.strip())
        return out
    return []

def get_external_id(obj: dict, prefix: str) -> Optional[str]:
    for ref in obj.get("external_references", []) or []:
        ext_id = ref.get("external_id")
        if isinstance(ext_id, str) and ext_id.startswith(prefix):
            return ext_id.strip()
    return None


# =========================
# NEO4J SCHEMA
# =========================
def ensure_schema(session) -> None:
    # MITRE group unikátně podle Gxxxx
    session.run("""
    CREATE CONSTRAINT mitre_intrusionset_mitre_id_unique IF NOT EXISTS
    FOR (n:MitreIntrusionSet) REQUIRE n.mitre_id IS UNIQUE
    """)
    # index pro rychlejší lookup (OpenCTI intrusion sets podle opencti_id)
    session.run("""
    CREATE INDEX intrusion_set_opencti_id_idx IF NOT EXISTS
    FOR (n:IntrusionSet) ON (n.opencti_id)
    """)


# =========================
# 1) IMPORT MITRE GROUPS
# =========================
def import_mitre_intrusion_sets(session, stix_objects: List[dict]) -> int:
    """
    V MITRE STIX je group jako: type='intrusion-set'
    Klíč: external_references[].external_id = Gxxxx
    """
    mitre_groups = [
        o for o in stix_objects
        if isinstance(o, dict)
        and o.get("type") == "intrusion-set"
        and not o.get("revoked", False)
        and not o.get("x_mitre_deprecated", False)
    ]

    imported, skipped = 0, 0
    for g in mitre_groups:
        mitre_id = get_external_id(g, "G")
        if not mitre_id:
            skipped += 1
            continue

        props = {
            "mitre_id": mitre_id,
            "stix_id": g.get("id"),
            "name": g.get("name"),
            "description": g.get("description"),
            "aliases": as_str_list(g.get("aliases")),
            "created": g.get("created"),
            "modified": g.get("modified"),
        }

        # idempotentní upsert
        session.run("""
        MERGE (n:MitreIntrusionSet {mitre_id: $mitre_id})
        SET n.stix_id = coalesce(n.stix_id, $stix_id)
        SET n.name = coalesce($name, n.name)
        SET n.description = coalesce($description, n.description)
        SET n.aliases = CASE WHEN size($aliases) > 0 THEN $aliases ELSE coalesce(n.aliases, []) END
        SET n.created = coalesce($created, n.created)
        SET n.modified = coalesce($modified, n.modified)
        """, **props)

        imported += 1

    print(f"[+] MITRE intrusion-set objects in bundle: {len(mitre_groups)}")
    print(f"[+] Imported/Upserted MitreIntrusionSet: {imported}")
    print(f"[i] Skipped (no Gxxxx): {skipped}")
    return imported


# =========================
# 2) LOAD LOOKUP TABLES (MITRE)
# =========================
def load_mitre_group_lookup(session) -> Tuple[Dict[str, str], Dict[str, Dict[str, Any]]]:
    """
    Vrátí:
    - exact_map: norm(alias_or_name) -> mitre_id
    - mitre_meta: mitre_id -> {name, aliases}
    """
    exact_map: Dict[str, str] = {}
    mitre_meta: Dict[str, Dict[str, Any]] = {}

    q = """
    MATCH (m:MitreIntrusionSet)
    RETURN m.mitre_id AS mitre_id, m.name AS name, m.aliases AS aliases
    """
    for r in session.run(q):
        mid = r["mitre_id"]
        name = r.get("name") or ""
        aliases = r.get("aliases") or []
        if not isinstance(aliases, list):
            aliases = []

        mitre_meta[mid] = {"name": name, "aliases": aliases}

        # exact match keys
        if name:
            exact_map[norm(name)] = mid
        for a in aliases:
            if isinstance(a, str) and a.strip():
                exact_map[norm(a)] = mid

    return exact_map, mitre_meta


# =========================
# 3) LOAD OPENCTI INTRUSION SETS
# =========================
def load_opencti_intrusion_sets(session) -> List[Dict[str, Any]]:
    """
    Načte tvoje existující IntrusionSet uzly (OpenCTI).
    Klíčová pole: opencti_id, name (+ případně aliases pokud je máte)
    """
    q = """
    MATCH (o:IntrusionSet)
    RETURN
      o.opencti_id AS opencti_id,
      o.standard_id AS standard_id,
      o.name AS name,
      o.aliases AS aliases,
      o.x_opencti_aliases AS x_opencti_aliases
    """
    out = []
    for r in session.run(q):
        aliases = []
        for k in ("aliases", "x_opencti_aliases"):
            v = r.get(k)
            if isinstance(v, list):
                aliases.extend([x for x in v if isinstance(x, str) and x.strip()])

        out.append({
            "opencti_id": r.get("opencti_id"),
            "standard_id": r.get("standard_id"),
            "name": r.get("name") or "",
            "aliases": list(dict.fromkeys(aliases)),  # unique preserve order
        })
    return out


# =========================
# 4) SCORING / MATCHING
# =========================
def best_match_for_opencti(
    open_name: str,
    open_aliases: List[str],
    exact_map: Dict[str, str],
    mitre_meta: Dict[str, Dict[str, Any]],
) -> Optional[Tuple[str, float, str]]:
    """
    Vrátí (mitre_id, score, method) nebo None.
    Metody:
      - exact (1.0)
      - substring (0.9)
      - fuzzy (0..1)
    """
    keys = []
    if open_name:
        keys.append(open_name)
    keys.extend(open_aliases)

    # 1) exact na normalizovaném textu
    for k in keys:
        nk = norm(k)
        if nk in exact_map:
            return exact_map[nk], 1.0, "exact"

    # 2) substring (typicky když alias obsahuje dlouhé jméno)
    # Pozor: dává falešné shody, proto score 0.9
    for k in keys:
        nk = norm(k)
        if not nk or len(nk) < 6:
            continue
        for candidate_norm, mid in exact_map.items():
            if nk in candidate_norm or candidate_norm in nk:
                # substring je slabší než exact
                return mid, 0.90, "substring"

    # 3) fuzzy přes difflib na name+aliases MITRE
    # Ber nejlepší podobnost proti MITRE name i aliasům.
    best_mid = None
    best_score = 0.0

    def sim(a: str, b: str) -> float:
        return SequenceMatcher(None, norm(a), norm(b)).ratio()

    for mid, meta in mitre_meta.items():
        candidates = []
        if meta.get("name"):
            candidates.append(meta["name"])
        candidates.extend([a for a in meta.get("aliases", []) if isinstance(a, str)])

        for k in keys:
            for c in candidates:
                s = sim(k, c)
                if s > best_score:
                    best_score = s
                    best_mid = mid

    if best_mid is None:
        return None
    return best_mid, best_score, "fuzzy"


# =========================
# 5) WRITE MAPPINGS
# =========================
def upsert_mapping(session, opencti_id: str, mitre_id: str, score: float, method: str) -> None:
    now = datetime.now(timezone.utc).isoformat()

    session.run("""
    MATCH (o:IntrusionSet {opencti_id: $opencti_id})
    MATCH (m:MitreIntrusionSet {mitre_id: $mitre_id})
    MERGE (o)-[r:MAPPED_TO]->(m)
    SET r.score = $score,
        r.method = $method,
        r.updated_at = $now
    """, opencti_id=opencti_id, mitre_id=mitre_id, score=score, method=method, now=now)


def map_opencti_to_mitre_groups(session) -> Dict[str, int]:
    exact_map, mitre_meta = load_mitre_group_lookup(session)
    open_sets = load_opencti_intrusion_sets(session)

    mapped = 0
    skipped_no_opencti_id = 0
    below_threshold = 0

    for o in open_sets:
        opencti_id = o.get("opencti_id")
        if not isinstance(opencti_id, str) or not opencti_id:
            skipped_no_opencti_id += 1
            continue

        m = best_match_for_opencti(
            open_name=o.get("name", ""),
            open_aliases=o.get("aliases", []),
            exact_map=exact_map,
            mitre_meta=mitre_meta,
        )

        if not m:
            below_threshold += 1
            continue

        mitre_id, score, method = m
        if score < MAP_THRESHOLD:
            below_threshold += 1
            continue

        upsert_mapping(session, opencti_id=opencti_id, mitre_id=mitre_id, score=score, method=method)
        mapped += 1

    return {
        "mapped": mapped,
        "skipped_no_opencti_id": skipped_no_opencti_id,
        "below_threshold_or_no_match": below_threshold,
        "total_opencti_intrusion_sets": len(open_sets),
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

            # 1) Import MITRE groups
            import_mitre_intrusion_sets(session, objects)

            # 2) Create candidate mappings
            stats = map_opencti_to_mitre_groups(session)
            print("[=] Mapping stats:", stats)

            # 3) quick count
            c = session.run("""
            MATCH (o:IntrusionSet)-[r:MAPPED_TO]->(m:MitreIntrusionSet)
            RETURN count(r) AS c
            """).single()["c"]
            print(f"[=] Total MAPPED_TO edges: {c}")

    finally:
        driver.close()


if __name__ == "__main__":
    main()


