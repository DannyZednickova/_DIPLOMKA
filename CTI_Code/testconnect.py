from neo4j import GraphDatabase

NEO4J_URI = "bolt://127.0.0.1:7687"
NEO4J_USER = "neo4j"
NEO4J_PASS = "82008200aA"
DB_NAME = "test"

driver = GraphDatabase.driver(
    NEO4J_URI,
    auth=(NEO4J_USER, NEO4J_PASS)
)

with driver.session(database=DB_NAME) as session:
    result = session.run("RETURN 1 AS ok")
    print("Connected, result:", result.single()["ok"])

driver.close()