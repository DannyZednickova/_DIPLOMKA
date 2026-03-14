import os
from pathlib import Path
from typing import List, Dict, Set

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from neo4j import GraphDatabase
from neo4j.exceptions import Neo4jError

load_dotenv()

NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASS = os.getenv("NEO4J_PASS", "CHANGE_ME")
NEO4J_DB = os.getenv("NEO4J_DB", "neo4j")

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
INDEX_HTML = STATIC_DIR / "index.html"

app = FastAPI(title="CTI Graph UI")
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

# Kratší timeouty => API se nezasekne na desítky sekund při problému s DB
driver = GraphDatabase.driver(
    NEO4J_URI,
    auth=(NEO4J_USER, NEO4J_PASS),
    connection_timeout=5,
    max_connection_pool_size=30,
)


def run(query: str, **params):
    try:
        with driver.session(database=NEO4J_DB) as session:
            return list(session.run(query, **params))
    except Neo4jError as exc:
        raise HTTPException(status_code=500, detail=f"Neo4j error: {str(exc)}") from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.on_event("shutdown")
def _shutdown():
    try:
        driver.close()
    except Exception:
        pass


@app.get("/")
def index():
    # Hlavní stránka
    return FileResponse(str(INDEX_HTML))


@app.get("/api/health")
def health():
    return {"ok": True}


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


def _online_fulltext_indexes() -> Set[str]:
    q = """
    SHOW FULLTEXT INDEXES
    YIELD name, state
    WHERE state = 'ONLINE'
    RETURN collect(name) AS names
    """
    rows = run(q)
    if not rows:
        return set()
    return set(rows[0].data().get("names") or [])


def _query_fulltext(index_name: str, q: str, limit: int):
    cypher = f"""
    CALL db.index.fulltext.queryNodes('{index_name}', $q) YIELD node, score
    RETURN
      coalesce(node.opencti_id, node.cve, node.ip, node.oid, elementId(node)) AS id,
      labels(node) AS labels,
      coalesce(node.name, node.cve, node.ip, node.oid, 'unknown') AS title,
      node.entity_type AS entity_type,
      score
    ORDER BY score DESC
    LIMIT $limit
    """
    return run(cypher, q=q, limit=limit)


@app.get("/api/search")
def search(q: str = Query(..., min_length=2), limit: int = 40):
    # Podporované indexy (vezme jen ty ONLINE)
    preferred = [
        "stix_fulltext",
        "vuln_fulltext",
        "host_fulltext",
        "nvt_fulltext",
        "attackpattern_fulltext",
        "mitre_intrusionset_fulltext",
        "intrusionset_fulltext",
    ]

    try:
        online = _online_fulltext_indexes()
    except HTTPException:
        # Když DB/indexy zrovna nedostupné, neblokuj frontend
        return {"results": [], "used_indexes": []}

    active = [x for x in preferred if x in online]
    if not active:
        return {"results": [], "used_indexes": []}

    variants = [q.strip()]
    # Prefix varianta pro partial match
    if "*" not in q and '"' not in q:
        variants.append(f"{q.strip()}*")

    merged: Dict[str, dict] = {}
    for idx in active:
        for qv in variants:
            try:
                rows = _query_fulltext(idx, qv, limit)
            except HTTPException:
                continue
            for r in rows:
                d = r.data()
                rid = d["id"]
                prev = merged.get(rid)
                if (prev is None) or (float(d.get("score", 0)) > float(prev.get("score", 0))):
                    merged[rid] = d

    results = sorted(merged.values(), key=lambda x: float(x.get("score", 0)), reverse=True)[:limit]
    return {"results": results, "used_indexes": active}


@app.get("/api/graph")
def graph(
    node_id: str,
    hops: int = 1,          # nižší default => rychlejší start
    max_nodes: int = 350,   # nižší default => méně freeze
    max_edges: int = 1200,
):
    # tvrdé limity proti zaseknutí
    if hops < 0 or hops > 3:
        raise HTTPException(status_code=400, detail="hops must be in range 0..3")
    if max_nodes < 50 or max_nodes > 1200:
        raise HTTPException(status_code=400, detail="max_nodes must be in range 50..1200")
    if max_edges < 100 or max_edges > 5000:
        raise HTTPException(status_code=400, detail="max_edges must be in range 100..5000")

    hops_int = int(hops)

    # Pozn.: Neo4j neumí [*0..$hops], proto placeholder replace
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
      UNWIND nodes(p) AS nn
      RETURN collect(DISTINCT nn)[0..$max_nodes] AS ns
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
    try:
        rows = run(q, limit=limit)
        return {"results": [r.data() for r in rows]}
    except HTTPException:
        return {"results": []}


@app.get("/api/list/cves")
def list_cves(limit: int = 1000):
    q = """
    MATCH (v:Vulnerability)
    WHERE v.cve IS NOT NULL
    RETURN v.cve AS id,
           v.cve AS title,
           labels(v) AS labels
    ORDER BY title
    LIMIT $limit
    """
    try:
        rows = run(q, limit=limit)
        return {"results": [r.data() for r in rows]}
    except HTTPException:
        return {"results": []}


@app.get("/api/list/nvts")
def list_nvts(limit: int = 900):
    q = """
    MATCH (n:NVT)
    RETURN coalesce(n.oid, elementId(n)) AS id,
           coalesce(n.name, elementId(n)) AS title,
           labels(n) AS labels
    ORDER BY title
    LIMIT $limit
    """
    try:
        rows = run(q, limit=limit)
        return {"results": [r.data() for r in rows]}
    except HTTPException:
        return {"results": []}


@app.get("/api/list/malware")
def list_malware(limit: int = 900):
    q = """
    MATCH (m:Malware)
    RETURN coalesce(m.opencti_id, elementId(m)) AS id,
           coalesce(m.name, elementId(m)) AS title,
           labels(m) AS labels
    ORDER BY title
    LIMIT $limit
    """
    try:
        rows = run(q, limit=limit)
        return {"results": [r.data() for r in rows]}
    except HTTPException:
        return {"results": []}


@app.get("/api/list/intrusion-sets")
def list_intrusion_sets(limit: int = 900):
    q = """
    MATCH (i:IntrusionSet)
    RETURN coalesce(i.opencti_id, elementId(i)) AS id,
           coalesce(i.name, elementId(i)) AS title,
           labels(i) AS labels
    ORDER BY title
    LIMIT $limit
    """
    try:
        rows = run(q, limit=limit)
        return {"results": [r.data() for r in rows]}
    except HTTPException:
        return {"results": []}


@app.get("/api/list/attack-patterns")
def list_attack_patterns(limit: int = 900):
    q = """
    MATCH (a:AttackPattern)
    RETURN coalesce(a.opencti_id, elementId(a)) AS id,
           coalesce(a.name, elementId(a)) AS title,
           labels(a) AS labels
    ORDER BY title
    LIMIT $limit
    """
    try:
        rows = run(q, limit=limit)
        return {"results": [r.data() for r in rows]}
    except HTTPException:
        return {"results": []}


@app.get("/api/list/locations")
def list_locations(limit: int = 900):
    q = """
    MATCH (l:Location)
    RETURN coalesce(l.opencti_id, elementId(l)) AS id,
           coalesce(l.name, elementId(l)) AS title,
           labels(l) AS labels
    ORDER BY title
    LIMIT $limit
    """
    try:
        rows = run(q, limit=limit)
        return {"results": [r.data() for r in rows]}
    except HTTPException:
        return {"results": []}