from neo4j import GraphDatabase
import json
from pathlib import Path
from typing import Any, Optional, Dict, List

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


# =========================
# HELPERS (STIX parsing)
# =========================
def as_str_list(v: Any) -> List[str]:
    if not v:
        return []
    if isinstance(v, list):
        out = []
        for x in v:
            if isinstance(x, str):
                x = x.strip()
                if x:
                    out.append(x)
        return out
    return []


def get_external_id(obj: dict, prefix: str) -> Optional[str]:
    """
    MITRE IDs jsou v external_references[].external_id:
      - Techniques: Txxxx / Txxxx.yyy
      - Groups:     Gxxxx
      - Software:   Sxxxx
    """
    for ref in obj.get("external_references", []) or []:
        ext_id = ref.get("external_id")
        if isinstance(ext_id, str) and ext_id.startswith(prefix):
            return ext_id.strip()
    return None


def get_tactics(obj: dict) -> List[str]:
    """
    Tactics jsou v kill_chain_phases (kill_chain_name=mitre-attack, phase_name=tactic)
    """
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
    # unikátní klíč pro techniky
    session.run("""
    CREATE CONSTRAINT attack_pattern_mitre_id_unique IF NOT EXISTS
    FOR (n:AttackPattern) REQUIRE n.mitre_id IS UNIQUE
    """)
    # index pro rychlé lookupy podle stix_id (není unikátní, protože může být alt_stix_ids)
    session.run("""
    CREATE INDEX attack_object_stix_id_idx IF NOT EXISTS
    FOR (n:AttackObject) ON (n.stix_id)
    """)


# =========================
# UPSERT LOGIC
# =========================
def upsert_attack_pattern(session, props: Dict[str, Any]) -> None:
    """
    Idempotentní upsert podle mitre_id.
    - MERGE (AttackPattern {mitre_id})
    - stix_id uloží do n.stix_id pokud je prázdné
    - pokud se liší, přidá do n.alt_stix_ids (bez duplicit)
    """
    session.run("""
    MERGE (n:AttackPattern {mitre_id: $mitre_id})
    SET n:AttackObject
    SET n.name = coalesce($name, n.name)
    SET n.description = coalesce($description, n.description)
    SET n.platforms = CASE WHEN size($platforms) > 0 THEN $platforms ELSE coalesce(n.platforms, []) END
    SET n.tactics   = CASE WHEN size($tactics) > 0 THEN $tactics   ELSE coalesce(n.tactics, []) END
    SET n.is_subtechnique = coalesce($is_subtechnique, n.is_subtechnique)
    SET n.modified = coalesce($modified, n.modified)
    SET n.created  = coalesce($created,  n.created)
    SET n.version  = coalesce($version,  n.version)

    // primary stix_id
    SET n.stix_id = coalesce(n.stix_id, $stix_id)

    // if incoming stix_id differs from stored stix_id, store in alt_stix_ids (unique)
    FOREACH (_ IN CASE WHEN n.stix_id <> $stix_id THEN [1] ELSE [] END |
        SET n.alt_stix_ids = coalesce(n.alt_stix_ids, [])
        FOREACH (__ IN CASE WHEN NOT $stix_id IN n.alt_stix_ids THEN [1] ELSE [] END |
            SET n.alt_stix_ids = n.alt_stix_ids + $stix_id
        )
    )
    """, **props)


# =========================
# IMPORTERS
# =========================
def import_attack_patterns(session, stix_objects: List[dict]) -> int:
    """
    Importuje AttackPattern (techniky) a jejich metadata.
    """
    attack_patterns = [
        o for o in stix_objects
        if isinstance(o, dict)
        and o.get("type") == "attack-pattern"
        and not o.get("revoked", False)
        and not o.get("x_mitre_deprecated", False)
    ]

    imported = 0
    skipped_no_mitre_id = 0

    for ap in attack_patterns:
        mitre_id = get_external_id(ap, "T")
        if not mitre_id:
            skipped_no_mitre_id += 1
            continue

        props = {
            "mitre_id": mitre_id,
            "stix_id": ap.get("id"),
            "name": ap.get("name"),
            "description": ap.get("description"),
            "platforms": as_str_list(ap.get("x_mitre_platforms")),
            "tactics": get_tactics(ap),
            "is_subtechnique": bool(ap.get("x_mitre_is_subtechnique", False)),
            "created": ap.get("created"),
            "modified": ap.get("modified"),
            "version": ap.get("x_mitre_version"),
        }

        # bezpečnost: stix_id musí existovat, jinak skip
        if not isinstance(props["stix_id"], str) or not props["stix_id"]:
            continue

        upsert_attack_pattern(session, props)
        imported += 1

    print(f"[+] AttackPattern objects in bundle: {len(attack_patterns)}")
    print(f"[+] Imported/Upserted AttackPattern: {imported}")
    print(f"[i] Skipped (no mitre_id): {skipped_no_mitre_id}")
    return imported


def build_stix_to_mitre_map(stix_objects: List[dict]) -> Dict[str, str]:
    """
    Map STIX attack-pattern ID -> MITRE technique ID (Txxxx/Txxxx.yyy)
    Pro relace (subtechnique-of), které jsou v STIX ID.
    """
    m: Dict[str, str] = {}
    for o in stix_objects:
        if isinstance(o, dict) and o.get("type") == "attack-pattern":
            sid = o.get("id")
            mid = get_external_id(o, "T")
            if isinstance(sid, str) and sid and isinstance(mid, str) and mid:
                m[sid] = mid
    return m


def import_subtechnique_of(session, stix_objects: List[dict]) -> int:
    """
    Importuje relace subtechnique-of jako:
      (sub:AttackPattern)-[:SUBTECHNIQUE_OF]->(parent:AttackPattern)
    napojení dělá přes mitre_id (Txxxx) díky mapě stix->mitre.
    """
    stix2mitre = build_stix_to_mitre_map(stix_objects)

    rels = [
        o for o in stix_objects
        if isinstance(o, dict)
        and o.get("type") == "relationship"
        and o.get("relationship_type") == "subtechnique-of"
        and not o.get("revoked", False)
    ]

    imported = 0
    for r in rels:
        src_stix = r.get("source_ref")
        dst_stix = r.get("target_ref")
        rel_id = r.get("id")

        src_mid = stix2mitre.get(src_stix)
        dst_mid = stix2mitre.get(dst_stix)

        if not (isinstance(src_mid, str) and isinstance(dst_mid, str)):
            continue
        if not isinstance(rel_id, str) or not rel_id:
            continue

        session.run("""
        MATCH (a:AttackPattern {mitre_id: $src})
        MATCH (b:AttackPattern {mitre_id: $dst})
        MERGE (a)-[rel:SUBTECHNIQUE_OF]->(b)
        SET rel.stix_id = $rel_id
        """, src=src_mid, dst=dst_mid, rel_id=rel_id)

        imported += 1

    print(f"[+] subtechnique-of rel objects in bundle: {len(rels)}")
    print(f"[+] Imported/Upserted SUBTECHNIQUE_OF: {imported}")
    return imported


# =========================
# OPTIONAL: CLEANUP (Python-only)
# =========================
def optional_cleanup_attack_import(session, really: bool = False) -> None:
    """
    Když chceš smazat jen MITRE import část:
    smaže uzly označené :AttackObject (a s nimi i relace).
    """
    if not really:
        return
    session.run("MATCH (n:AttackObject) DETACH DELETE n")
    print("[!] Cleanup done: deleted all :AttackObject nodes")


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
            # pokud potřebuješ vyčistit předchozí rozbitý import, nastav really=True
            # optional_cleanup_attack_import(session, really=True)

            ensure_schema(session)

            import_attack_patterns(session, objects)
            import_subtechnique_of(session, objects)

            # quick stats
            c1 = session.run("MATCH (t:AttackPattern) RETURN count(t) AS c").single()["c"]
            c2 = session.run("MATCH ()-[r:SUBTECHNIQUE_OF]->() RETURN count(r) AS c").single()["c"]
            print(f"[=] DB '{NEO4J_DB}' now has AttackPattern nodes: {c1}")
            print(f"[=] DB '{NEO4J_DB}' now has SUBTECHNIQUE_OF rels: {c2}")

    finally:
        driver.close()


if __name__ == "__main__":
    main()

