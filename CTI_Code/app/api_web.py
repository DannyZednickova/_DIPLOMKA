# api_web.py  (OPRAVENO – bez route-dekorátorů uvnitř /api/graph, + lepší chyba místo tichého 500)

import os
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI, Query, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from neo4j import GraphDatabase

load_dotenv()

NEO4J_URI  = os.getenv("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASS = os.getenv("NEO4J_PASS", "CHANGE_ME")
NEO4J_DB   = os.getenv("NEO4J_DB", "neo4j")

BASE_DIR   = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
INDEX_HTML = STATIC_DIR / "index.html"

app = FastAPI(title="CTI Graph UI")
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASS))


@app.on_event("shutdown")
def _shutdown():
    try:
        driver.close()
    except Exception:
        pass


def run(query: str, **params):
    try:
        with driver.session(database=NEO4J_DB) as session:
            return list(session.run(query, **params))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/")
def index():
    return FileResponse(str(INDEX_HTML))


@app.get("/api/node")
def node_details(id: str, neigh_limit: int = 50):
    cypher = """
    MATCH (n)
    WHERE n.opencti_id = $id OR n.cve = $id OR n.ip = $id OR n.oid = $id OR elementId(n) = $id
    WITH n LIMIT 1

    OPTIONAL MATCH (n)-[r]-(m)
    WITH n, r, m
    ORDER BY type(r)
    WITH n,
         collect(DISTINCT {
           rel: type(r),
           dir: CASE WHEN startNode(r)=n THEN "OUT" ELSE "IN" END,
           other_id: coalesce(m.opencti_id, m.cve, m.ip, m.oid, elementId(m)),
           other_title: coalesce(m.name, m.cve, m.ip, m.oid, "unknown"),
           other_labels: labels(m)
         })[0..$neigh_limit] AS neighbors

    RETURN
      {
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
def search(q: str = Query(..., min_length=2), limit: int = 20):
    cypher = """
    CALL {
      CALL db.index.fulltext.queryNodes('stix_fulltext', $q) YIELD node, score
      RETURN node, score, labels(node) AS lbs
      UNION ALL
      CALL db.index.fulltext.queryNodes('vuln_fulltext', $q) YIELD node, score
      RETURN node, score, labels(node) AS lbs
      UNION ALL
      CALL db.index.fulltext.queryNodes('host_fulltext', $q) YIELD node, score
      RETURN node, score, labels(node) AS lbs
      UNION ALL
      CALL db.index.fulltext.queryNodes('nvt_fulltext', $q) YIELD node, score
      RETURN node, score, labels(node) AS lbs
    }
    RETURN
      coalesce(node.opencti_id, node.cve, node.ip, node.oid, elementId(node)) AS id,
      lbs AS labels,
      coalesce(node.name, node.cve, node.ip, node.oid, 'unknown') AS title,
      node.entity_type AS entity_type,
      score
    ORDER BY score DESC
    LIMIT $limit;
    """
    rows = run(cypher, q=q, limit=limit)
    return {"results": [r.data() for r in rows]}


@app.get("/api/graph")
def graph(node_id: str, radius: int = 2, max_nodes: int = 400):
    if radius not in (1, 2, 3, 4):
        raise HTTPException(status_code=400, detail="radius must be 1..4")

    cypher_by_radius = {
        1: """
        MATCH (start)
        WHERE start.opencti_id = $node_id OR start.cve = $node_id OR start.ip = $node_id OR start.oid = $node_id OR elementId(start) = $node_id
        WITH start LIMIT 1
        MATCH p=(start)-[*0..1]-(n)
        WITH collect(p) AS ps
        UNWIND ps AS p2
        UNWIND nodes(p2) AS nn
        WITH collect(DISTINCT nn)[0..$max_nodes] AS ns, ps
        UNWIND ps AS p3
        UNWIND relationships(p3) AS rr
        WITH ns, collect(DISTINCT rr) AS rs
        RETURN
          [n IN ns | {id: coalesce(n.opencti_id, n.cve, n.ip, n.oid, elementId(n)), labels: labels(n), title: coalesce(n.name, n.cve, n.ip, n.oid, 'unknown'), entity_type: n.entity_type}] AS nodes,
          [r IN rs | {source: coalesce(startNode(r).opencti_id, startNode(r).cve, startNode(r).ip, startNode(r).oid, elementId(startNode(r))),
                      target: coalesce(endNode(r).opencti_id, endNode(r).cve, endNode(r).ip, endNode(r).oid, elementId(endNode(r))),
                      type: type(r)}] AS edges;
        """,
        2: """
        MATCH (start)
        WHERE start.opencti_id = $node_id OR start.cve = $node_id OR start.ip = $node_id OR start.oid = $node_id OR elementId(start) = $node_id
        WITH start LIMIT 1
        MATCH p=(start)-[r*0..2]-(n)
        WHERE ALL(x IN r WHERE type(x) IN ["USES","TARGETS","IS","REFERS_TO","VULNERABLE_TO"])
        WITH collect(p) AS ps
        UNWIND ps AS p2
        UNWIND nodes(p2) AS nn
        WITH collect(DISTINCT nn)[0..$max_nodes] AS ns, ps
        UNWIND ps AS p3
        UNWIND relationships(p3) AS rr
        WITH ns, collect(DISTINCT rr) AS rs
        RETURN
          [n IN ns | {id: coalesce(n.opencti_id, n.cve, n.ip, n.oid, elementId(n)), labels: labels(n), title: coalesce(n.name, n.cve, n.ip, n.oid, 'unknown'), entity_type: n.entity_type}] AS nodes,
          [r IN rs | {source: coalesce(startNode(r).opencti_id, startNode(r).cve, startNode(r).ip, startNode(r).oid, elementId(startNode(r))),
                      target: coalesce(endNode(r).opencti_id, endNode(r).cve, endNode(r).ip, endNode(r).oid, elementId(endNode(r))),
                      type: type(r)}] AS edges;
        """,
        3: """
        MATCH (start)
        WHERE start.opencti_id = $node_id OR start.cve = $node_id OR start.ip = $node_id OR start.oid = $node_id OR elementId(start) = $node_id
        WITH start LIMIT 1
        MATCH p=(start)-[*0..3]-(n)
        WITH collect(p) AS ps
        UNWIND ps AS p2
        UNWIND nodes(p2) AS nn
        WITH collect(DISTINCT nn)[0..$max_nodes] AS ns, ps
        UNWIND ps AS p3
        UNWIND relationships(p3) AS rr
        WITH ns, collect(DISTINCT rr) AS rs
        RETURN
          [n IN ns | {id: coalesce(n.opencti_id, n.cve, n.ip, n.oid, elementId(n)), labels: labels(n), title: coalesce(n.name, n.cve, n.ip, n.oid, 'unknown'), entity_type: n.entity_type}] AS nodes,
          [r IN rs | {source: coalesce(startNode(r).opencti_id, startNode(r).cve, startNode(r).ip, startNode(r).oid, elementId(startNode(r))),
                      target: coalesce(endNode(r).opencti_id, endNode(r).cve, endNode(r).ip, endNode(r).oid, elementId(endNode(r))),
                      type: type(r)}] AS edges;
        """,
        4: """
        MATCH (start)
        WHERE start.opencti_id = $node_id OR start.cve = $node_id OR start.ip = $node_id OR start.oid = $node_id OR elementId(start) = $node_id
        WITH start LIMIT 1
        MATCH p=(start)-[*0..4]-(n)
        WITH collect(p) AS ps
        UNWIND ps AS p2
        UNWIND nodes(p2) AS nn
        WITH collect(DISTINCT nn)[0..$max_nodes] AS ns, ps
        UNWIND ps AS p3
        UNWIND relationships(p3) AS rr
        WITH ns, collect(DISTINCT rr) AS rs
        RETURN
          [n IN ns | {id: coalesce(n.opencti_id, n.cve, n.ip, n.oid, elementId(n)), labels: labels(n), title: coalesce(n.name, n.cve, n.ip, n.oid, 'unknown'), entity_type: n.entity_type}] AS nodes,
          [r IN rs | {source: coalesce(startNode(r).opencti_id, startNode(r).cve, startNode(r).ip, startNode(r).oid, elementId(startNode(r))),
                      target: coalesce(endNode(r).opencti_id, endNode(r).cve, endNode(r).ip, endNode(r).oid, elementId(endNode(r))),
                      type: type(r)}] AS edges;
        """,
    }

    out = run(cypher_by_radius[radius], node_id=node_id, max_nodes=max_nodes)
    if not out:
        return {"nodes": [], "edges": []}

    data = out[0].data()
    return {"nodes": data["nodes"], "edges": data["edges"]}


# LISTS – MUSÍ BÝT MIMO /api/graph (jinak 500/duplicitní route)
@app.get("/api/list/hosts")
def list_hosts(limit: int = 200):
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
def list_cves(limit: int = 300):
    q = """
    MATCH (v:Vulnerability)
    WHERE v.cve IS NOT NULL
    RETURN v.cve AS id,
           v.cve AS title,
           labels(v) AS labels
    ORDER BY title
    LIMIT $limit
    """
    rows = run(q, limit=limit)
    return {"results": [r.data() for r in rows]}


@app.get("/api/list/malware")
def list_malware(limit: int = 300):
    q = """
    MATCH (m:StixEntity:Malware)
    RETURN coalesce(m.opencti_id, elementId(m)) AS id,
           coalesce(m.name, elementId(m)) AS title,
           labels(m) AS labels
    ORDER BY title
    LIMIT $limit
    """
    rows = run(q, limit=limit)
    return {"results": [r.data() for r in rows]}


@app.get("/api/list/intrusion-sets")
def list_intrusion_sets(limit: int = 300):
    q = """
    MATCH (i:StixEntity:IntrusionSet)
    RETURN coalesce(i.opencti_id, elementId(i)) AS id,
           coalesce(i.name, elementId(i)) AS title,
           labels(i) AS labels
    ORDER BY title
    LIMIT $limit
    """
    rows = run(q, limit=limit)
    return {"results": [r.data() for r in rows]}


@app.get("/api/list/nvts")
def list_nvts(limit: int = 300):
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



