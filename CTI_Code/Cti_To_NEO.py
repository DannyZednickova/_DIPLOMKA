"""
Skript slouží k načtení dat z OpenCTI (přes GraphQL API)
a jejich uložení do grafové databáze Neo4j.

Funguje jako ETL pipeline:
- Extract: dotazy na OpenCTI GraphQL
- Transform: výběr a úprava polí (hlavně Indicator name)
- Load: ukládání uzlů a vztahů do Neo4j
"""

import requests
from fastapi import FastAPI, Query
from neo4j import GraphDatabase
from starlette.middleware.cors import CORSMiddleware


"""
Konfigurace OpenCTI GraphQL endpointu a autentizačního tokenu.
"""
OPENCTI_URL = "http://localhost:8080/graphql"
OPENCTI_TOKEN = "2cf990a2-5b35-4894-a214-da959ee51b31"


"""
Konfigurace připojení k Neo4j databázi.
Používá se přímé bolt:// připojení bez routingu.
"""
NEO4J_URI = "bolt://127.0.0.1:7687"
NEO4J_USER = "neo4j"
NEO4J_PASS = "82008200aA"
DB_NAME     = "neo4j"


"""
HTTP hlavičky pro GraphQL dotazy do OpenCTI.
Obsahují Bearer token pro autorizaci.
"""
HDR = {
    "Content-Type": "application/json",
    "Authorization": f"Bearer {OPENCTI_TOKEN}"
}


def gql(query, variables=None):
    """
    Obecný wrapper pro GraphQL dotazy na OpenCTI.

    - odešle POST request s GraphQL dotazem
    - vyhodí chybu při HTTP chybě nebo GraphQL erroru
    - vrací pouze část 'data' z odpovědi
    """
    r = requests.post(
        OPENCTI_URL,
        headers=HDR,
        json={"query": query, "variables": variables or {}}
    )
    r.raise_for_status()
    j = r.json()
    if "errors" in j:
        raise RuntimeError(j["errors"])
    return j["data"]


def paginate(query, root, page=300):
    """
    Generický stránkovací helper pro OpenCTI GraphQL dotazy.

    Postupně stahuje všechny stránky výsledků a vrací jednotlivé uzly.
    Používá GraphQL pageInfo (hasNextPage, endCursor).
    """
    after = None
    while True:
        data = gql(query, {"first": page, "after": after})
        conn = data[root]
        for e in conn.get("edges", []):
            yield e["node"]
        if not conn.get("pageInfo", {}).get("hasNextPage"):
            break
        after = conn["pageInfo"]["endCursor"]


"""
GraphQL dotazy pro jednotlivé typy uzlů (STIX entity).
Každý dotaz vrací edges->node a pageInfo pro stránkování.
"""

Q_INTRUSIONSETS = """
query($first:Int!,$after:ID){
  intrusionSets(first:$first, after:$after){
    edges{ node{ id name created modified created_at updated_at } }
    pageInfo{ hasNextPage endCursor }
  }
}"""

Q_THREATACTORS = """
query($first:Int!,$after:ID){
  threatActors(first:$first, after:$after){
    edges{ node{ id name created modified created_at updated_at } }
    pageInfo{ hasNextPage endCursor }
  }
}"""

Q_MALWARE = """
query($first:Int!,$after:ID){
  malwares(first:$first, after:$after){
    edges{ node{ id name malware_types created modified created_at updated_at } }
    pageInfo{ hasNextPage endCursor }
  }
}"""

Q_CAMPAIGNS = """
query($first:Int!,$after:ID){
  campaigns(first:$first, after:$after){
    edges{ node{ id name first_seen last_seen created_at updated_at } }
    pageInfo{ hasNextPage endCursor }
  }
}"""

Q_INDICATORS = """
query($first:Int!,$after:ID){
  indicators(first:$first, after:$after){
    edges{ node{
      id
      indicator_types
      valid_from
      created_at
      updated_at
      x_opencti_observable_values { type value }
    } }
    pageInfo{ hasNextPage endCursor }
  }
}"""


"""
GraphQL dotaz pro STIX vztahy (stixCoreRelationships).
Používá filtry na typ vztahu a typy zdrojových/cílových entit.
"""
Q_REL = """
query($first:Int!, $after:ID, $rtype:[String], $from:[String], $to:[String]) {
  stixCoreRelationships(first:$first, after:$after,
                        relationship_type:$rtype, fromTypes:$from, toTypes:$to) {
    edges {
      node {
        id
        from {
          __typename
          ... on StixObject    { id }
          ... on ThreatActor   { id name }
          ... on IntrusionSet  { id name }
          ... on Malware       { id name }
          ... on Campaign      { id name }
          ... on Indicator     { id x_opencti_observable_values { type value } }
        }
        to {
          __typename
          ... on StixObject    { id }
          ... on ThreatActor   { id name }
          ... on IntrusionSet  { id name }
          ... on Malware       { id name }
          ... on Campaign      { id name }
          ... on Indicator     { id x_opencti_observable_values { type value } }
        }
      }
    }
    pageInfo { hasNextPage endCursor }
  }
}
"""


"""
Mapování OpenCTI typů (__typename) na Neo4j labely.
Používá se při vytváření uzlů a vztahů.
"""
LABEL_MAP = {
    "IntrusionSet": "IntrusionSet",
    "ThreatActor":  "ThreatActor",
    "Malware":      "Malware",
    "Campaign":     "Campaign",
    "Indicator":    "Indicator",
}


def label_of(tname):
    """
    Vrátí Neo4j label pro daný OpenCTI typ.
    Pokud typ není podporovaný, vrací None.
    """
    return LABEL_MAP.get(tname)


def upsert_node(session, tname, node):
    """
    Zajistí existenci uzlu v Neo4j.

    - MERGE podle OpenCTI id
    - nastaví name (u Indicator z observable value)
    - používá se hlavně při ukládání vztahů
    """
    label = label_of(tname)
    if not label:
        return

    name = node.get("name")

    if not name and tname == "Indicator":
        vals = [
            ov.get("value")
            for ov in (node.get("x_opencti_observable_values") or [])
            if ov.get("value")
        ]
        name = vals[0] if vals else None

    session.run(
        f"MERGE (n:{label} {{id:$id}}) "
        f"SET n.name = COALESCE($name, n.name)",
        id=node["id"],
        name=name
    )


def upsert_rel(session, src, rel_type, dst):
    """
    Vytvoří vztah mezi dvěma existujícími uzly v Neo4j.

    - MATCH na zdrojový a cílový uzel podle id
    - MERGE vztahu daného typu
    """
    sl = label_of(src["__typename"])
    dl = label_of(dst["__typename"])

    if not sl or not dl:
        return

    session.run(
        f"MATCH (a:{sl} {{id:$sid}}) "
        f"MATCH (b:{dl} {{id:$tid}}) "
        f"MERGE (a)-[:{rel_type}]->(b)",
        sid=src["id"],
        tid=dst["id"]
    )


def load_nodes(session):
    """
    Načte všechny podporované OpenCTI entity a uloží je do Neo4j.

    - vytvoří unikátní constrainty na id
    - postupně nahraje IntrusionSet, ThreatActor, Malware, Campaign, Indicator
    """
    session.run("CREATE CONSTRAINT IF NOT EXISTS FOR (n:IntrusionSet) REQUIRE n.id IS UNIQUE")
    session.run("CREATE CONSTRAINT IF NOT EXISTS FOR (n:ThreatActor)  REQUIRE n.id IS UNIQUE")
    session.run("CREATE CONSTRAINT IF NOT EXISTS FOR (n:Malware)      REQUIRE n.id IS UNIQUE")
    session.run("CREATE CONSTRAINT IF NOT EXISTS FOR (n:Campaign)     REQUIRE n.id IS UNIQUE")
    session.run("CREATE CONSTRAINT IF NOT EXISTS FOR (n:Indicator)    REQUIRE n.id IS UNIQUE")

    for n in paginate(Q_INTRUSIONSETS, "intrusionSets"):
        session.run(
            """MERGE (x:IntrusionSet {id:$id})
               SET x.name=$name, x.created=$created, x.modified=$modified,
                   x.created_at=$created_at, x.updated_at=$updated_at""",
            id=n["id"],
            name=n.get("name"),
            created=n.get("created"),
            modified=n.get("modified"),
            created_at=n.get("created_at"),
            updated_at=n.get("updated_at")
        )

    for n in paginate(Q_THREATACTORS, "threatActors"):
        session.run(
            """MERGE (x:ThreatActor {id:$id})
               SET x.name=$name, x.created=$created, x.modified=$modified,
                   x.created_at=$created_at, x.updated_at=$updated_at""",
            id=n["id"],
            name=n.get("name"),
            created=n.get("created"),
            modified=n.get("modified"),
            created_at=n.get("created_at"),
            updated_at=n.get("updated_at")
        )

    for n in paginate(Q_MALWARE, "malwares"):
        session.run(
            """MERGE (x:Malware {id:$id})
               SET x.name=$name, x.malware_types=$types,
                   x.created=$created, x.modified=$modified,
                   x.created_at=$created_at, x.updated_at=$updated_at""",
            id=n["id"],
            name=n.get("name"),
            types=n.get("malware_types"),
            created=n.get("created"),
            modified=n.get("modified"),
            created_at=n.get("created_at"),
            updated_at=n.get("updated_at")
        )

    for n in paginate(Q_CAMPAIGNS, "campaigns"):
        session.run(
            """MERGE (x:Campaign {id:$id})
               SET x.name=$name, x.first_seen=$first_seen, x.last_seen=$last_seen,
                   x.created_at=$created_at, x.updated_at=$updated_at""",
            id=n["id"],
            name=n.get("name"),
            first_seen=n.get("first_seen"),
            last_seen=n.get("last_seen"),
            created_at=n.get("created_at"),
            updated_at=n.get("updated_at")
        )

    for n in paginate(Q_INDICATORS, "indicators"):
        vals = [
            ov.get("value")
            for ov in (n.get("x_opencti_observable_values") or [])
            if ov.get("value")
        ]
        name = vals[0] if vals else None

        session.run(
            """MERGE (x:Indicator {id:$id})
               SET x.name=$name, x.indicator_types=$types,
                   x.valid_from=$valid_from,
                   x.created_at=$created_at, x.updated_at=$updated_at""",
            id=n["id"],
            name=name,
            types=n.get("indicator_types"),
            valid_from=n.get("valid_from"),
            created_at=n.get("created_at"),
            updated_at=n.get("updated_at")
        )


def paginate_relationships(rtype_list, from_types, to_types, page=300):
    """
    Stránkovací helper pro STIX vztahy.
    Vrací jednotlivé relationship node objekty.
    """
    after = None
    while True:
        data = gql(
            Q_REL,
            {
                "first": page,
                "after": after,
                "rtype": rtype_list,
                "from": from_types,
                "to": to_types
            }
        )
        conn = data["stixCoreRelationships"]
        for e in conn.get("edges", []):
            yield e["node"]
        if not conn["pageInfo"]["hasNextPage"]:
            break
        after = conn["pageInfo"]["endCursor"]


def load_relationships(session):
    """
    Načte vybrané typy vztahů z OpenCTI a uloží je do Neo4j.

    USES:
      IntrusionSet / ThreatActor -> Malware

    ATTRIBUTED_TO:
      Campaign -> IntrusionSet / ThreatActor

    INDICATES:
      Malware -> Indicator
    """

    for rel in paginate_relationships(
        ["uses"],
        ["Intrusion-Set", "Threat-Actor"],
        ["Malware"]
    ):
        upsert_node(session, rel["from"]["__typename"], rel["from"])
        upsert_node(session, rel["to"]["__typename"], rel["to"])
        upsert_rel(session, rel["from"], "USES", rel["to"])

    for rel in paginate_relationships(
        ["attributed-to"],
        ["Campaign"],
        ["Intrusion-Set", "Threat-Actor"]
    ):
        upsert_node(session, rel["from"]["__typename"], rel["from"])
        upsert_node(session, rel["to"]["__typename"], rel["to"])
        upsert_rel(session, rel["from"], "ATTRIBUTED_TO", rel["to"])

    for rel in paginate_relationships(
        ["indicates"],
        ["Malware"],
        ["Indicator"]
    ):
        upsert_node(session, rel["from"]["__typename"], rel["from"])
        upsert_node(session, rel["to"]["__typename"], rel["to"])
        upsert_rel(session, rel["from"], "INDICATES", rel["to"])


def main():
    """
    Hlavní entry point skriptu.

    - připojí se k Neo4j
    - nahraje uzly
    - nahraje vztahy
    """
    auth = (NEO4J_USER, NEO4J_PASS) if NEO4J_PASS else None
    driver = GraphDatabase.driver(NEO4J_URI, auth=auth)

    with driver.session(database=DB_NAME) as s:
        print("→ Nahrávám uzly…")
        load_nodes(s)

        print("→ Nahrávám vztahy…")
        load_relationships(s)

    driver.close()

    print("✓ Hotovo. Ověř v Browseru:")
    print("MATCH ()-[r]->() RETURN type(r), count(*) ORDER BY count(*) DESC;")
    print("MATCH (a:IntrusionSet)-[:USES]->(m:Malware) RETURN a,m LIMIT 25;")


if __name__ == "__main__":
    main()
