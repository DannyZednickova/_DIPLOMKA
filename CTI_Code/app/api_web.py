# api_web.py  (OPRAVENO – bez route-dekorátorů uvnitř /api/graph, + lepší chyba místo tichého 500)

import os
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI, Query, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from neo4j import GraphDatabase
from collections import deque, defaultdict


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



REL_WHITELIST = [
    "USES","TARGETS","IS","REFERS_TO","VULNERABLE_TO",
    "HAS_NVT","AFFECTS","DETECTED_BY","RELATED_TO",
    "INDICATES","EXPLOITS","ATTRIBUTED_TO"
]

CYPHER_BY_RADIUS = {
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

    MATCH p=(start)-[r*0..2]-(x)
    WHERE ALL(rel IN r WHERE type(rel) IN ["USES","TARGETS","IS","REFERS_TO","VULNERABLE_TO","HAS_NVT"])
    WITH start, collect(p) AS ps

    // vypočti pro každý uzel minimální vzdálenost (dist) ze všech cest
    UNWIND ps AS p2
    UNWIND nodes(p2) AS n
    WITH start, ps, n, min(length(p2)) AS dist,
         CASE
           WHEN 'Host' IN labels(n) THEN 0
           WHEN 'Vulnerability' IN labels(n) THEN 1
           WHEN 'AttackPattern' IN labels(n) THEN 2
           WHEN 'Malware' IN labels(n) THEN 3
           WHEN 'IntrusionSet' IN labels(n) THEN 4
           WHEN 'NVT' IN labels(n) THEN 5
           ELSE 9
         END AS prio
    ORDER BY dist ASC, prio ASC

    WITH start, ps, collect(DISTINCT n)[0..$max_nodes] AS ns

    // hrany jen mezi vybranými uzly
    UNWIND ps AS p3
    UNWIND relationships(p3) AS rr
    WITH ns, collect(DISTINCT rr) AS rs

    RETURN
      [n IN ns | {
        id: coalesce(n.opencti_id, n.cve, n.ip, n.oid, elementId(n)),
        labels: labels(n),
        title: coalesce(n.name, n.cve, n.ip, n.oid, 'unknown'),
        entity_type: n.entity_type
      }] AS nodes,
      [r IN rs WHERE startNode(r) IN ns AND endNode(r) IN ns | {
        source: coalesce(startNode(r).opencti_id, startNode(r).cve, startNode(r).ip, startNode(r).oid, elementId(startNode(r))),
        target: coalesce(endNode(r).opencti_id, endNode(r).cve, endNode(r).ip, endNode(r).oid, elementId(endNode(r))),
        type: type(r)
      }] AS edges;
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


@app.on_event("shutdown")
def _shutdown():
    try:
        driver.close()
    except Exception:
        pass



def build_highlight_path(nodes, edges, start_id, max_hops=6):
    node_labels = {n["id"]: set(n.get("labels") or []) for n in nodes}
    hosts = {nid for nid, lbs in node_labels.items() if "Host" in lbs}
    if not hosts:
        return {"node_ids": [], "edge_keys": []}

    adj = defaultdict(list)
    for e in edges:
        s, t, typ = e["source"], e["target"], e["type"]
        adj[s].append((t, typ))
        adj[t].append((s, typ))  # nedirekční pro hledání

    q = deque([(start_id, 0)])
    prev = {start_id: None}  # node -> (prev_node, edge_type)
    found_host = None

    while q:
        cur, d = q.popleft()
        if cur in hosts and cur != start_id:
            found_host = cur
            break
        if d >= max_hops:
            continue
        for nxt, typ in adj.get(cur, []):
            if nxt not in prev:
                prev[nxt] = (cur, typ)
                q.append((nxt, d + 1))

    if not found_host:
        return {"node_ids": [], "edge_keys": []}

    # reconstruct path
    node_ids = []
    edge_keys = []
    x = found_host
    node_ids.append(x)
    while prev[x] is not None:
        p, typ = prev[x]
        node_ids.append(p)
        edge_keys.append(f"{p}|{typ}|{x}")
        x = p

    node_ids = list(reversed(node_ids))
    edge_keys = list(reversed(edge_keys))
    return {"node_ids": node_ids, "edge_keys": edge_keys}



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
def graph(
    node_id: str,
    radius: int = 2,
    max_nodes: int = 400,
    highlight_hosts: bool = True,
    path_max_hops: int = 6,
    max_hosts: int = 30,
):
    if radius not in (1, 2, 3, 4):
        raise HTTPException(status_code=400, detail="radius must be 1..4")

    # 1) tvůj radius subgraph
    out = run(CYPHER_BY_RADIUS[radius], node_id=node_id, max_nodes=max_nodes)
    if not out:
        return {"nodes": [], "edges": [], "highlight": {"node_ids": [], "edge_keys": []}}

    data = out[0].data()
    nodes = data["nodes"]
    edges = data["edges"]

    highlight = {"node_ids": [], "edge_keys": []}
    if highlight_hosts:
        highlight = build_highlight_path(nodes, edges, node_id, max_hops=path_max_hops)
    return {"nodes": nodes, "edges": edges, "highlight": highlight}


    #toto pujde smazat...
    HOPS = int(path_max_hops)
    if HOPS < 1 or HOPS > 12:
        raise HTTPException(status_code=400, detail="path_max_hops must be 1..12")


    # 2) shortest-ish cesty START -> Host přes whitelist relací
    highlight_cypher = f"""
    MATCH (start)
    WHERE start.opencti_id = $node_id OR start.cve = $node_id OR start.ip = $node_id OR start.oid = $node_id OR elementId(start) = $node_id
    WITH start LIMIT 1

    // kandidátní hosti do {HOPS} hopů (radši nedirekční, ať to najde cestu i když hrany nemáš všude stejným směrem)
    MATCH p=(start)-[rs*1..{HOPS}]-(h:Host)
    WHERE ALL(r IN rs WHERE type(r) IN $rel_whitelist)
    WITH h, min(length(p)) AS minLen, start
    ORDER BY minLen ASC
    LIMIT $max_hosts

    // všechny shortest cesty s tou minimální délkou
    MATCH p2=(start)-[rs2*1..{HOPS}]-(h)
    WHERE ALL(r IN rs2 WHERE type(r) IN $rel_whitelist)
      AND length(p2) = minLen

    WITH collect(p2) AS ps
    UNWIND ps AS p
    UNWIND nodes(p) AS n
    WITH collect(DISTINCT coalesce(n.opencti_id, n.cve, n.ip, n.oid, elementId(n))) AS node_ids, ps
    UNWIND ps AS p3
    UNWIND relationships(p3) AS r
    WITH node_ids,
         collect(DISTINCT (
           coalesce(startNode(r).opencti_id, startNode(r).cve, startNode(r).ip, startNode(r).oid, elementId(startNode(r)))
           + "|" + type(r) + "|" +
           coalesce(endNode(r).opencti_id, endNode(r).cve, endNode(r).ip, endNode(r).oid, elementId(endNode(r)))
         )) AS edge_keys
    RETURN {{ node_ids: node_ids, edge_keys: edge_keys }} AS highlight;
    """

    h = run(
        highlight_cypher,
        node_id=node_id,
        path_max_hops=path_max_hops,
        max_hosts=max_hosts,
        rel_whitelist=REL_WHITELIST,
    )
    if h:
        highlight = h[0].data().get("highlight") or highlight

    return {"nodes": nodes, "edges": edges, "highlight": highlight}


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



