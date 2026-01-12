import os
from dataclasses import dataclass
from dotenv import load_dotenv

load_dotenv()

@dataclass(frozen=True)
class Settings:
    NEO4J_URI: str = os.getenv("NEO4J_URI", "bolt://localhost:7687")
    NEO4J_USER: str = os.getenv("NEO4J_USER", "neo4j")
    NEO4J_PASS: str = os.getenv("NEO4J_PASS", "CHANGE_ME")
    NEO4J_DB: str = os.getenv("NEO4J_DB", "neo4j")

settings = Settings()