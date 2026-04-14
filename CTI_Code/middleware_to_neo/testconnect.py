#!/usr/bin/env python3
"""Print exact relationship triplets in Neo4j as:
(LabelA)-[:REL]->(LabelB) [count]

Usage:
  python CTI_Code/middleware_to_neo/inspect_relationships.py
"""

import os
from neo4j import GraphDatabase
from dotenv import load_dotenv

load_dotenv()

NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASS = os.getenv("NEO4J_PASS", "CHANGE_ME")
NEO4J_DB = os.getenv("NEO4J_DB", "neo4j")

Q_TRIPLETS = """
MATCH (a)-[r]->(b)
UNWIND labels(a) AS from_label
UNWIND labels(b) AS to_label
RETURN from_label, type(r) AS rel, to_label, count(*) AS cnt
ORDER BY rel, cnt DESC, from_label, to_label
"""

Q_TOTALS = """
MATCH ()-[r]->()
RETURN type(r) AS rel, count(*) AS cnt
ORDER BY cnt DESC, rel
"""


def main() -> None:
    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASS))
    try:
        with driver.session(database=NEO4J_DB) as session:
            totals = session.run(Q_TOTALS).data()
            print("=== Relationship totals ===")
            for row in totals:
                print(f"{row['rel']}: {row['cnt']}")

            print("\n=== Exact label-to-label relationships ===")
            rows = session.run(Q_TRIPLETS).data()
            for row in rows:
                print(f"({row['from_label']})-[:{row['rel']}]->({row['to_label']}) [{row['cnt']}]")
    finally:
        driver.close()


if __name__ == "__main__":
    main()
