import os
from pathlib import Path
from typing import Dict
import logging

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse, Response
from fastapi.staticfiles import StaticFiles
from neo4j import GraphDatabase

load_dotenv()

NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASS = os.getenv("NEO4J_PASS", "CHANGE_ME")
NEO4J_DB = os.getenv("NEO4J_DB", "neo4j")
NEO4J_CONNECT_TIMEOUT = float(os.getenv("NEO4J_CONNECT_TIMEOUT", "5"))

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
INDEX_HTML = STATIC_DIR / "index.html"

app = FastAPI(title="CTI Graph UI")
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

logger = logging.getLogger(__name__)
driver = None


def get_driver():
    global driver
    if driver is None:
        driver = GraphDatabase.driver(
            NEO4J_URI,
            auth=(NEO4J_USER, NEO4J_PASS),
            connection_timeout=NEO4J_CONNECT_TIMEOUT,
        )
    return driver


def run(query: str, **params):
    try:
        with get_driver().session(database=NEO4J_DB) as session:
            return list(session.run(query, **params))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.on_event("startup")
def _startup():
    try:
        get_driver().verify_connectivity()
    except Exception as exc:
        logger.warning("Neo4j connectivity check failed on startup: %s", exc)


@app.on_event("shutdown")
def _shutdown():
    try:
        if driver is not None:
            driver.close()
    except Exception:
        pass


@app.get("/")
def index():
    return FileResponse(str(INDEX_HTML))


@app.get("/api/report.xml")
def report_xml():
    def safe_rows(query: str, **params):
        try:
            return [r.data() for r in run(query, **params)]
        except HTTPException:
            return []

    generated_at = safe_rows("RETURN datetime().epochMillis AS ts")
    generated_ts = generated_at[0]["ts"] if generated_at else None

    summary = safe_rows(
        """
        MATCH (n)
        WITH labels(n) AS labs
        UNWIND labs AS label
        RETURN label, count(*) AS total
        ORDER BY total DESC, label ASC
        """
    )

    top_hosts = safe_rows(
        """
        MATCH (h:Host)
        OPTIONAL MATCH (h)-[:VULNERABLE_TO]->(c)
        WITH h, count(DISTINCT c) AS cves
        RETURN coalesce(h.ip, h.name, elementId(h)) AS host, cves
        ORDER BY cves DESC, host ASC
        LIMIT 25
        """
    )

    top_cves = safe_rows(
        """
        MATCH (h:Host)-[:VULNERABLE_TO]->(c)
        WITH c, count(DISTINCT h) AS hosts
        RETURN coalesce(c.cve, c.name, elementId(c)) AS cve, hosts
        ORDER BY hosts DESC, cve ASC
        LIMIT 25
        """
    )

    top_threat_classes = safe_rows(
        """
        MATCH (t:ThreatClass)<-[:INDICATES_THREAT]-(:NVT)<-[:HAS_NVT]-(:Host)
        WITH t, count(*) AS hits
        RETURN coalesce(t.name, elementId(t)) AS threat_class, hits
        ORDER BY hits DESC, threat_class ASC
        LIMIT 20
        """
    )

    top_malware = safe_rows(
        """
        MATCH (:IntrusionSet)-[:USES]->(m:Malware)
        WITH m, count(*) AS used_by_groups
        RETURN coalesce(m.name, elementId(m)) AS malware, used_by_groups
        ORDER BY used_by_groups DESC, malware ASC
        LIMIT 20
        """
    )

    top_locations = safe_rows(
        """
        MATCH (:IntrusionSet)-[:TARGETS]->(l:Location)
        WITH l, count(*) AS targets
        RETURN coalesce(l.name, elementId(l)) AS location, targets
        ORDER BY targets DESC, location ASC
        LIMIT 20
        """
    )

    def esc(value):
        text = "" if value is None else str(value)
        return (
            text.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&apos;")
        )

    def xml_rows(tag: str, rows: list, fields: list[str]) -> str:
        parts = [f"  <{tag}>"]
        for row in rows:
            parts.append("    <row>")
            for field in fields:
                parts.append(f"      <{field}>{esc(row.get(field))}</{field}>")
            parts.append("    </row>")
        parts.append(f"  </{tag}>")
        return "\n".join(parts)

    xml = "\n".join(
        [
            '<?xml version="1.0" encoding="UTF-8"?>',
            '<?xml-stylesheet type="text/xsl" href="/static/report.xsl"?>',
            "<ctiReport>",
            f"  <generatedAtEpochMs>{esc(generated_ts)}</generatedAtEpochMs>",
            xml_rows("summaryByLabel", summary, ["label", "total"]),
            xml_rows("topHostsByCves", top_hosts, ["host", "cves"]),
            xml_rows("topCvesByHosts", top_cves, ["cve", "hosts"]),
            xml_rows("topThreatClasses", top_threat_classes, ["threat_class", "hits"]),
            xml_rows("topMalwareByGroupUsage", top_malware, ["malware", "used_by_groups"]),
            xml_rows("topLocationsTargeted", top_locations, ["location", "targets"]),
            "</ctiReport>",
        ]
    )
    return Response(content=xml, media_type="application/xml")


@app.get("/api/node")
def node_details(id: str, neigh_limit: int = 80):
    cypher = """
    MATCH (n)
    WHERE n.opencti_id = $id OR n.cve = $id OR n.ip = $id OR n.oid = $id OR n.name = $id OR elementId(n) = $id
    WITH n LIMIT 1

    OPTIONAL MATCH (n)-[r]-(m)
    WITH n, r, m
    ORDER BY type(r), coalesce(m.name, m.cve, m.ip, m.oid, elementId(m))
    WITH n,
         collect(DISTINCT {
           rel: type(r),
           dir: CASE WHEN startNode(r)=n THEN "OUT" ELSE "IN" END,
           other_id: coalesce(m.opencti_id, m.cve, m.ip, m.oid, elementId(m)),
           other_title: coalesce(m.name, m.cve, m.ip, m.oid, "unknown"),
           other_labels: labels(m)
         })[0..$neigh_limit] AS neighbors

    RETURN {
      id: coalesce(n.opencti_id, n.cve, n.ip, n.oid, elementId(n)),
      labels: labels(n),
      title: coalesce(n.name, n.cve, n.ip, n.oid, "unknown"),
      entity_type: n.entity_type,
      props: properties(n),
      neighbors: neighbors
    } AS node;
    """
    out = run(cypher, id=id, neigh_limit=neigh_limit)
    if not out:
        raise HTTPException(status_code=404, detail="node not found")
    return out[0].data()["node"]


@app.get("/api/search")
def search(q: str = Query(..., min_length=2), limit: int = 40):
    text = q.strip()

    idx_rows = run(
        """
        SHOW FULLTEXT INDEXES
        YIELD name, state
        WHERE state='ONLINE'
        RETURN collect(name) AS names
        """
    )
    online_indexes = set((idx_rows[0].data().get("names") or []) if idx_rows else [])

    wanted = [
        "stix_fulltext",
        "vuln_fulltext",
        "host_fulltext",
        "nvt_fulltext",
        "attackpattern_fulltext",
        "malware_fulltext",
        "location_fulltext",
        "mitre_intrusionset_fulltext",
        "intrusionset_fulltext",
    ]
    active = [x for x in wanted if x in online_indexes]

    merged: Dict[str, dict] = {}

    def merge_rows(rows):
        for r in rows:
            d = r.data()
            rid = d.get("id")
            if not rid:
                continue
            prev = merged.get(rid)
            if prev is None or float(d.get("score", 0)) > float(prev.get("score", 0)):
                merged[rid] = d

    variants = [text, f"{text}*"]

    for idx in active:
        for variant in variants:
            cypher = f"""
            CALL db.index.fulltext.queryNodes('{idx}', $q) YIELD node, score
            RETURN
              coalesce(node.opencti_id, node.cve, node.ip, node.oid, elementId(node)) AS id,
              labels(node) AS labels,
              coalesce(node.name, node.cve, node.ip, node.oid, 'unknown') AS title,
              node.entity_type AS entity_type,
              score
            ORDER BY score DESC
            LIMIT $limit
            """
            try:
                merge_rows(run(cypher, q=variant, limit=limit))
            except HTTPException:
                pass

    # fallback: pokryje i Location/Malware i bez fulltext indexů
    fallback = """
    MATCH (n)
    WHERE
      (n.cve IS NOT NULL AND toLower(n.cve) CONTAINS toLower($q)) OR
      (n.ip IS NOT NULL AND toLower(n.ip) CONTAINS toLower($q)) OR
      (n.oid IS NOT NULL AND toLower(n.oid) CONTAINS toLower($q)) OR
      (n.name IS NOT NULL AND toLower(n.name) CONTAINS toLower($q)) OR
      (n.entity_type IS NOT NULL AND toLower(n.entity_type) CONTAINS toLower($q))
    RETURN
      coalesce(n.opencti_id, n.cve, n.ip, n.oid, elementId(n)) AS id,
      labels(n) AS labels,
      coalesce(n.name, n.cve, n.ip, n.oid, 'unknown') AS title,
      n.entity_type AS entity_type,
      (
        CASE
          WHEN n.cve = $q THEN 500.0
          WHEN n.name = $q THEN 450.0
          WHEN n.cve STARTS WITH $q THEN 400.0
          WHEN toLower(n.name) STARTS WITH toLower($q) THEN 250.0
          ELSE 60.0
        END
        + CASE WHEN 'Location' IN labels(n) THEN 40.0 ELSE 0.0 END
        + CASE WHEN 'Malware' IN labels(n) THEN 30.0 ELSE 0.0 END
        + CASE WHEN 'Vulnerability' IN labels(n) THEN 20.0 ELSE 0.0 END
      ) AS score
    ORDER BY score DESC, title ASC
    LIMIT $limit
    """
    try:
        merge_rows(run(fallback, q=text, limit=limit * 3))
    except HTTPException:
        pass

    out = sorted(merged.values(), key=lambda x: float(x.get("score", 0)), reverse=True)[:limit]
    return {"results": out, "used_indexes": active}


@app.get("/api/graph")
def graph(
    node_id: str,
    hops: int = 2,
    max_nodes: int = 1200,
    max_edges: int = 0,
):
    if hops < 0 or hops > 8:
        raise HTTPException(status_code=400, detail="hops must be in range 0..8")
    if max_nodes < 50 or max_nodes > 6000:
        raise HTTPException(status_code=400, detail="max_nodes must be in range 50..6000")

    if max_edges <= 0:
        max_edges = min(max_nodes * 12, 25000)

    hops_int = int(hops)

    cypher = """
    MATCH (start)
    WHERE start.opencti_id = $node_id
       OR start.cve = $node_id
       OR start.ip = $node_id
       OR start.oid = $node_id
       OR start.name = $node_id
       OR elementId(start) = $node_id
    WITH start LIMIT 1

    CALL {
      WITH start
      MATCH p=(start)-[*0..__HOPS__]-(n)
      WITH n, min(length(p)) AS dist
      ORDER BY dist ASC
      RETURN collect(n)[0..$max_nodes] AS ns
    }

    CALL {
      WITH ns
      UNWIND ns AS n
      MATCH (n)-[r]-(m)
      WHERE m IN ns
      RETURN collect(DISTINCT r)[0..$max_edges] AS rs
    }

    RETURN
      [n IN ns | {
        id: coalesce(n.opencti_id, n.cve, n.ip, n.oid, elementId(n)),
        labels: labels(n),
        title: coalesce(n.name, n.cve, n.ip, n.oid, 'unknown'),
        entity_type: n.entity_type
      }] AS nodes,
      [r IN rs | {
        source: coalesce(startNode(r).opencti_id, startNode(r).cve, startNode(r).ip, startNode(r).oid, elementId(startNode(r))),
        target: coalesce(endNode(r).opencti_id, endNode(r).cve, endNode(r).ip, endNode(r).oid, elementId(endNode(r))),
        type: type(r)
      }] AS edges;
    """.replace("__HOPS__", str(hops_int))

    out = run(cypher, node_id=node_id, max_nodes=max_nodes, max_edges=max_edges)
    if not out:
        return {"nodes": [], "edges": []}
    return out[0].data()


@app.get("/api/list/hosts")
def list_hosts(limit: int = 500):
    q = """
    MATCH (h:Host)
    RETURN coalesce(h.ip, elementId(h)) AS id,
           coalesce(h.ip, h.name, elementId(h)) AS title,
           labels(h) AS labels
    ORDER BY title
    LIMIT $limit
    """
    rows = run(q, limit=limit)
    return {"results": [r.data() for r in rows]}


@app.get("/api/list/cves")
def list_cves(limit: int = 5000):
    q = """
    MATCH (n)
    WITH n,
         coalesce(
           n.cve,
           CASE
             WHEN n.name IS NOT NULL AND n.name =~ '(?i)^CVE-[0-9]{4}-[0-9].*' THEN n.name
             ELSE null
           END
         ) AS cve
    WHERE cve IS NOT NULL
    RETURN DISTINCT cve AS id,
           cve AS title,
           labels(n) AS labels
    ORDER BY title
    LIMIT $limit
    """
    rows = run(q, limit=limit)
    return {"results": [r.data() for r in rows]}


@app.get("/api/list/nvts")
def list_nvts(limit: int = 1200):
    q = """
    MATCH (n:NVT)
    RETURN coalesce(n.oid, elementId(n)) AS id,
           coalesce(n.name, elementId(n)) AS title,
           labels(n) AS labels
    ORDER BY title
    LIMIT $limit
    """
    rows = run(q, limit=limit)
    return {"results": [r.data() for r in rows]}


@app.get("/api/list/malware")
def list_malware(limit: int = 1200):
    q = """
    MATCH (m:Malware)
    RETURN coalesce(m.opencti_id, elementId(m)) AS id,
           coalesce(m.name, elementId(m)) AS title,
           labels(m) AS labels
    ORDER BY title
    LIMIT $limit
    """
    rows = run(q, limit=limit)
    return {"results": [r.data() for r in rows]}


@app.get("/api/list/intrusion-sets")
def list_intrusion_sets(limit: int = 1200):
    q = """
    MATCH (i:IntrusionSet)
    RETURN coalesce(i.opencti_id, elementId(i)) AS id,
           coalesce(i.name, elementId(i)) AS title,
           labels(i) AS labels
    ORDER BY title
    LIMIT $limit
    """
    rows = run(q, limit=limit)
    return {"results": [r.data() for r in rows]}


@app.get("/api/list/attack-patterns")
def list_attack_patterns(limit: int = 1200):
    q = """
    MATCH (a:AttackPattern)
    RETURN coalesce(a.opencti_id, elementId(a)) AS id,
           coalesce(a.name, elementId(a)) AS title,
           labels(a) AS labels
    ORDER BY title
    LIMIT $limit
    """
    rows = run(q, limit=limit)
    return {"results": [r.data() for r in rows]}


@app.get("/api/list/locations")
def list_locations(limit: int = 1200):
    q = """
    MATCH (l:Location)
    RETURN coalesce(l.opencti_id, elementId(l)) AS id,
           coalesce(l.name, elementId(l)) AS title,
           labels(l) AS labels
    ORDER BY title
    LIMIT $limit
    """
    rows = run(q, limit=limit)
    return {"results": [r.data() for r in rows]}


@app.get("/api/list/threat-classes")
def list_threat_classes(limit: int = 1200):
    q = """
    MATCH (t:ThreatClass)
    RETURN coalesce(t.name, elementId(t)) AS id,
           coalesce(t.name, elementId(t)) AS title,
           labels(t) AS labels
    ORDER BY title
    LIMIT $limit
    """
    rows = run(q, limit=limit)
    return {"results": [r.data() for r in rows]}
