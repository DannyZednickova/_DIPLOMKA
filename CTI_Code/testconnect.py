from neo4j import GraphDatabase

NEO4J_URI = "bolt://127.0.0.1:7687"
NEO4J_USER = "neo4j"
NEO4J_PASS = "82008200aA"
DB_NAME = "metatest"

driver = GraphDatabase.driver(
    NEO4J_URI,
    auth=(NEO4J_USER, NEO4J_PASS)
)

with driver.session(database=DB_NAME) as session:
    result = session.run("RETURN 1 AS ok")
    print("Connected, result:", result.single()["ok"])

driver.close()

driver = GraphDatabase.driver("bolt://localhost:7687", auth=("neo4j","82008200aA"))


# tests/test_neo_consistency.py
import os
import re
from dataclasses import dataclass
from neo4j import GraphDatabase

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE)

NEO4J_URI  = os.getenv("NEO4J_URI", "bolt://127.0.0.1:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASS = os.getenv("NEO4J_PASS", "82008200aA")
NEO4J_DB   = os.getenv("NEO4J_DB", "openvastest")

@dataclass
class Metric:
    name: str
    value: int

def one(session, q, **p):
    return session.run(q, **p).single()

def scalar(session, q, **p) -> int:
    r = one(session, q, **p)
    return int(list(r.values())[0]) if r else 0

def main():
    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASS))
    with driver.session(database=NEO4J_DB) as session:

        # --- základní počty (baseline snapshot) ---
        metrics = [
            Metric("hosts", scalar(session, "MATCH (h:Host) RETURN count(h)")),
            Metric("nvts", scalar(session, "MATCH (n:NVT) RETURN count(n)")),
            Metric("vulns", scalar(session, "MATCH (v:Vulnerability) RETURN count(v)")),
            Metric("vulnerable_to_edges", scalar(session, "MATCH (:Host)-[r:VULNERABLE_TO]->(:Vulnerability) RETURN count(r)")),
            Metric("has_nvt_edges", scalar(session, "MATCH (:Host)-[r:HAS_NVT]->(:NVT) RETURN count(r)")),
            Metric("refers_to_edges", scalar(session, "MATCH (:NVT)-[r:REFERS_TO]->(:Vulnerability) RETURN count(r)")),
            Metric("stix_entities", scalar(session, "MATCH (e:StixEntity) RETURN count(e)")),
            Metric("stix_is_edges", scalar(session, "MATCH (:StixEntity)-[r:IS]->(:Vulnerability) RETURN count(r)")),
        ]
        print("=== SNAPSHOT ===")
        for m in metrics:
            print(f"{m.name}: {m.value}")

        # --- A2: duplicity (mělo by být 0) ---
        dup_hosts = scalar(session, """
            MATCH (h:Host)
            WITH h.ip AS ip, count(*) AS c
            WHERE ip IS NOT NULL AND c > 1
            RETURN count(*)""")
        dup_nvts = scalar(session, """
            MATCH (n:NVT)
            WITH n.oid AS oid, count(*) AS c
            WHERE oid IS NOT NULL AND c > 1
            RETURN count(*)""")
        dup_cves = scalar(session, """
            MATCH (v:Vulnerability)
            WITH v.cve AS cve, count(*) AS c
            WHERE cve IS NOT NULL AND c > 1
            RETURN count(*)""")

        assert dup_hosts == 0, f"Dup Host.ip groups: {dup_hosts}"
        assert dup_nvts == 0, f"Dup NVT.oid groups: {dup_nvts}"
        assert dup_cves == 0, f"Dup Vulnerability.cve groups: {dup_cves}"

        # --- A3: dangling edges (mělo by být 0) ---
        dangling_vuln_to = scalar(session, """
            MATCH (h:Host)-[r:VULNERABLE_TO]->(v)
            WHERE h.ip IS NULL OR v.cve IS NULL
            RETURN count(r)""")
        assert dangling_vuln_to == 0, f"Dangling VULNERABLE_TO edges: {dangling_vuln_to}"

        # --- A4: CVE normalizace (mělo by být 0 nebo vědomě zdokumentované) ---
        bad_cve = session.run("MATCH (v:Vulnerability) RETURN v.cve AS cve").values()
        bad = [c[0] for c in bad_cve if isinstance(c[0], str) and not CVE_RE.match(c[0])]
        assert len(bad) == 0, f"Bad CVE format examples: {bad[:20]}"

        # --- A3: OpenCTI hrany vždy mezi StixEntity (mělo by být 0) ---
        dangling_stix = scalar(session, """
            MATCH (a)-[r]->(b)
            WHERE r.opencti_id IS NOT NULL
              AND (NOT a:StixEntity OR NOT b:StixEntity)
            RETURN count(r)""")
        assert dangling_stix == 0, f"Edges with opencti_id not between StixEntity: {dangling_stix}"

    driver.close()
    print("[OK] Neo4j consistency checks passed.")

if __name__ == "__main__":
    main()
