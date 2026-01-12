from neo4j import GraphDatabase
from settigs import settings

driver = GraphDatabase.driver(
    settings.NEO4J_URI,
    auth=(settings.NEO4J_USER, settings.NEO4J_PASS)
)

def run(query: str, **params):
    with driver.session(database=settings.NEO4J_DB) as session:
        return list(session.run(query, **params))