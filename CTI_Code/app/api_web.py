from fastapi import FastAPI, Query
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from neo4j_db import run

# app/api_web.py
from pathlib import Path
from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

BASE_DIR = Path(__file__).resolve().parent          # .../app
STATIC_DIR = BASE_DIR / "static"                   # .../app/static
INDEX_HTML = STATIC_DIR / "index.html"

app = FastAPI(title="CTI Graph UI")

# statika (graph.js, index.html atd.)
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

@app.get("/")
def index():
    # FileResponse je nejspolehlivější (žádné open/read, správné hlavičky)
    return FileResponse(str(INDEX_HTML))

# 1) Fulltext search přes všechny indexy (sloučený výsledek)
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

# 2) Vrať subgraph kolem vybraného uzlu (radius = počet hopů)

@app.get("/api/graph")
def graph(node_id: str, radius: int = 2, max_nodes: int = 400):
    if radius not in (1, 2, 3, 4):
        raise HTTPException(status_code=400, detail="radius must be 1..4")

    # Každý dotaz má LITERÁL v délce cesty (Neo4j nepodporuje $radius v [*..])
    cypher_by_radius = {
        1: """
        MATCH (start)
        WHERE start.opencti_id = $node_id
           OR start.cve        = $node_id
           OR start.ip         = $node_id
           OR start.oid        = $node_id
           OR elementId(start) = $node_id
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
          [n IN ns |
            {
              id: coalesce(n.opencti_id, n.cve, n.ip, n.oid, elementId(n)),
              labels: labels(n),
              title: coalesce(n.name, n.cve, n.ip, n.oid, 'unknown'),
              entity_type: n.entity_type
            }
          ] AS nodes,
          [r IN rs |
            {
              source: coalesce(startNode(r).opencti_id, startNode(r).cve, startNode(r).ip, startNode(r).oid, elementId(startNode(r))),
              target: coalesce(endNode(r).opencti_id, endNode(r).cve, endNode(r).ip, endNode(r).oid, elementId(endNode(r))),
              type: type(r)
            }
          ] AS edges;
        """,
        2: """
        MATCH (start)
        WHERE start.opencti_id = $node_id
           OR start.cve        = $node_id
           OR start.ip         = $node_id
           OR start.oid        = $node_id
           OR elementId(start) = $node_id
        WITH start LIMIT 1
        MATCH p=(start)-[r*0..2]-(n)
WHERE ALL(x IN r WHERE type(x) IN [
  "USES",
  "TARGETS",
  "IS",
  "REFERS_TO",
  "VULNERABLE_TO"
])
        WITH collect(p) AS ps
        UNWIND ps AS p2
        UNWIND nodes(p2) AS nn
        WITH collect(DISTINCT nn)[0..$max_nodes] AS ns, ps
        UNWIND ps AS p3
        UNWIND relationships(p3) AS rr
        WITH ns, collect(DISTINCT rr) AS rs
        RETURN
          [n IN ns |
            {
              id: coalesce(n.opencti_id, n.cve, n.ip, n.oid, elementId(n)),
              labels: labels(n),
              title: coalesce(n.name, n.cve, n.ip, n.oid, 'unknown'),
              entity_type: n.entity_type
            }
          ] AS nodes,
          [r IN rs |
            {
              source: coalesce(startNode(r).opencti_id, startNode(r).cve, startNode(r).ip, startNode(r).oid, elementId(startNode(r))),
              target: coalesce(endNode(r).opencti_id, endNode(r).cve, endNode(r).ip, endNode(r).oid, elementId(endNode(r))),
              type: type(r)
            }
          ] AS edges;
        """,
        3: """
        MATCH (start)
        WHERE start.opencti_id = $node_id
           OR start.cve        = $node_id
           OR start.ip         = $node_id
           OR start.oid        = $node_id
           OR elementId(start) = $node_id
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
          [n IN ns |
            {
              id: coalesce(n.opencti_id, n.cve, n.ip, n.oid, elementId(n)),
              labels: labels(n),
              title: coalesce(n.name, n.cve, n.ip, n.oid, 'unknown'),
              entity_type: n.entity_type
            }
          ] AS nodes,
          [r IN rs |
            {
              source: coalesce(startNode(r).opencti_id, startNode(r).cve, startNode(r).ip, startNode(r).oid, elementId(startNode(r))),
              target: coalesce(endNode(r).opencti_id, endNode(r).cve, endNode(r).ip, endNode(r).oid, elementId(endNode(r))),
              type: type(r)
            }
          ] AS edges;
        """,
        4: """
        MATCH (start)
        WHERE start.opencti_id = $node_id
           OR start.cve        = $node_id
           OR start.ip         = $node_id
           OR start.oid        = $node_id
           OR elementId(start) = $node_id
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
          [n IN ns |
            {
              id: coalesce(n.opencti_id, n.cve, n.ip, n.oid, elementId(n)),
              labels: labels(n),
              title: coalesce(n.name, n.cve, n.ip, n.oid, 'unknown'),
              entity_type: n.entity_type
            }
          ] AS nodes,
          [r IN rs |
            {
              source: coalesce(startNode(r).opencti_id, startNode(r).cve, startNode(r).ip, startNode(r).oid, elementId(startNode(r))),
              target: coalesce(endNode(r).opencti_id, endNode(r).cve, endNode(r).ip, endNode(r).oid, elementId(endNode(r))),
              type: type(r)
            }
          ] AS edges;
        """,
    }

    cypher = cypher_by_radius[radius]
    out = run(cypher, node_id=node_id, max_nodes=max_nodes)

    if not out:
        return {"nodes": [], "edges": []}

    data = out[0].data()
    return {"nodes": data["nodes"], "edges": data["edges"]}