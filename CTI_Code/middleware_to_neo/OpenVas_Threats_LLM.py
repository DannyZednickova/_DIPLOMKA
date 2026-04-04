from __future__ import annotations

import json
import os
import re
import time
from typing import Dict, List, Tuple

import requests
from neo4j import GraphDatabase

NEO4J_URI = os.getenv("NEO4J_URI")
NEO4J_USER = os.getenv("NEO4J_USER")
NEO4J_PASS = os.getenv("NEO4J_PASS")
NEO4J_DB = os.getenv("NEO4J_DB")

LLM_PROVIDER = os.getenv("THREAT_LLM_PROVIDER")
LLM_MODEL = os.getenv("THREAT_LLM_MODEL")
OLLAMA_URL = os.getenv("OLLAMA_URL")
OLLAMA_TIMEOUT = int(os.getenv("OLLAMA_TIMEOUT"))

OLLAMA_TAGS_URL = os.getenv("OLLAMA_TAGS_URL", "http://127.0.0.1:11434/api/tags")
OLLAMA_DEBUG = os.getenv("THREAT_LLM_DEBUG", "1") == "1"

MAX_TEXT_CHARS = int(os.getenv("THREAT_MAX_TEXT_CHARS", "2500"))
MAX_RESULTS = int(os.getenv("THREAT_MAX_RESULTS", "400"))
MIN_SEVERITY = float(os.getenv("THREAT_MIN_SEVERITY", "7.0"))
MIN_QOD = int(os.getenv("THREAT_MIN_QOD", "70"))
FORCE_RULES_ONLY = os.getenv("THREAT_RULES_ONLY", "0") == "1"


THREAT_CLASSES = [
    "Initial Access",
    "Remote Code Execution",
    "Privilege Escalation",
    "Credential Access",
    "Lateral Movement",
    "Data Exfiltration",
    "Ransomware Risk",
    "Malware Delivery",
    "Denial of Service",
    "Configuration Weakness",
    "Exposure / Information Disclosure",
    "Persistence",
    "Command and Control",
]

KEYWORD_RULES: List[Tuple[str, List[str]]] = [
    ("Remote Code Execution", ["rce", "execute arbitrary", "remote shell", "backdoor", "command execution"]),
    ("Initial Access", ["gain a shell remotely", "unauthenticated", "exposed service", "remote access"]),
    ("Exposure / Information Disclosure", ["read file", "information disclosure", "lfi", "directory traversal"]),
    ("Ransomware Risk", ["smb", "eternalblue", "critical windows", "wormable"]),
    ("Credential Access", ["default credentials", "password", "bruteforce", "credential"]),
    ("Denial of Service", ["denial of service", "dos", "resource exhaustion"]),
    ("Configuration Weakness", ["misconfiguration", "debug enabled", "insecure configuration"]),
    ("Malware Delivery", ["trojan", "malware", "dropper", "payload"]),
    ("Persistence", ["web shell", "persistence", "startup"]),
    ("Command and Control", ["c2", "command and control", "beacon"]),
]


def _normalize(text: str) -> str:
    return re.sub(r"\s+", " ", (text or "").lower()).strip()


def _fallback_rule_classify(text: str) -> List[str]:
    n = _normalize(text)
    out: List[str] = []
    for label, kws in KEYWORD_RULES:
        if any(kw in n for kw in kws):
            out.append(label)
    if not out:
        out.append("Configuration Weakness")
    return out


def _call_ollama(prompt: str) -> Dict:
    payload = {
        "model": LLM_MODEL,
        "prompt": prompt,
        "stream": False,
        "format": "json",
        "options": {"temperature": 0.1},
    }
    r = requests.post(OLLAMA_URL, json=payload, timeout=OLLAMA_TIMEOUT)
    r.raise_for_status()
    body = r.json()
    raw = body.get("response", "{}")
    return json.loads(raw)


def _build_prompt(item: Dict) -> str:
    allowed = ", ".join(THREAT_CLASSES)
    return f"""
Jsi analytik kybernetickych hrozeb.
Mas OpenVAS nalez. Zarad ho do 1-3 trid hrozeb.

Allowed classes: [{allowed}]

Vstup:
name: {item.get('name')}
family: {item.get('family')}
summary: {item.get('summary')}
description: {item.get('description')}
port: {item.get('port')}
cvss: {item.get('cvss')}
threat: {item.get('threat')}

Vrat POUZE JSON bez dalsiho textu:
{{
  "classes": ["..."],
  "confidence": 0.0,
  "reason": "kratke oduvodneni"
}}
""".strip()


def classify_one(item: Dict) -> Dict:
    combined = " ".join([
        item.get("name") or "",
        item.get("family") or "",
        item.get("summary") or "",
        item.get("description") or "",
    ])

    if len(combined) > MAX_TEXT_CHARS:
        item = dict(item)
        item["description"] = (item.get("description") or "")[:MAX_TEXT_CHARS]

    if LLM_PROVIDER == "ollama":
        try:
            result = _call_ollama(_build_prompt(item))
            classes = [c for c in result.get("classes", []) if c in THREAT_CLASSES]
            if not classes:
                classes = _fallback_rule_classify(combined)
            return {
                "classes": classes[:3],
                "confidence": float(result.get("confidence", 0.55)),
                "reason": result.get("reason", "LLM classification"),
                "method": "llm",
            }
        except Exception as exc:
            classes = _fallback_rule_classify(combined)
            return {
                "classes": classes[:3],
                "confidence": 0.45,
                "reason": f"Fallback rules because LLM call failed: {exc}",
                "method": "rules",
            }

    classes = _fallback_rule_classify(combined)
    return {
        "classes": classes[:3],
        "confidence": 0.4,
        "reason": "Rule-only classification",
        "method": "rules",
    }


def load_candidates(session) -> List[Dict]:
    query = """
    MATCH (h:Host)-[rel:HAS_NVT]->(n:NVT)
    RETURN h.ip AS host_ip,
           rel.port AS port,
           rel.threat AS threat,
           rel.severity AS severity,
           n.oid AS oid,
           n.name AS name,
           n.family AS family,
           n.summary AS summary,
           n.last_description AS description,
           n.cvss_base AS cvss
    LIMIT $limit
    """
    records = session.run(query, limit=MAX_RESULTS)
    return [dict(r) for r in records]


def ensure_schema(session) -> None:
    session.run("CREATE CONSTRAINT IF NOT EXISTS FOR (t:ThreatClass) REQUIRE t.name IS UNIQUE")


def persist_classification(session, item: Dict, classified: Dict) -> None:
    base_params = {
        "host_ip": item.get("host_ip"),
        "oid": item.get("oid"),
        "confidence": classified["confidence"],
        "reason": classified["reason"],
        "method": classified["method"],
    }

    for label in classified["classes"]:
        params = dict(base_params)
        params["label"] = label
        session.run(
            """
            MERGE (t:ThreatClass {name:$label})
            WITH t
            MATCH (h:Host {ip:$host_ip})-[:HAS_NVT]->(n:NVT {oid:$oid})
            MERGE (n)-[r:INDICATES_THREAT]->(t)
            SET r.confidence = $confidence,
                r.reason = $reason,
                r.method = $method
            MERGE (h)-[:EXPOSED_TO_THREAT]->(t)
            """,
            **params,
        )


def print_summary(session) -> None:
    query = """
    MATCH (t:ThreatClass)
    OPTIONAL MATCH (h:Host)-[:EXPOSED_TO_THREAT]->(t)
    WITH t, count(DISTINCT h) AS hosts
    OPTIONAL MATCH (n:NVT)-[:INDICATES_THREAT]->(t)
    RETURN t.name AS threat_class, hosts, count(DISTINCT n) AS findings
    ORDER BY findings DESC, hosts DESC
    """
    rows = [dict(r) for r in session.run(query)]
    print("[THREAT] Summary for graph widgets:")
    print(json.dumps(rows, ensure_ascii=False, indent=2))


def main() -> None:
    if not all([NEO4J_URI, NEO4J_USER, NEO4J_PASS]):
        raise SystemExit("Missing Neo4j env: NEO4J_URI/NEO4J_USER/NEO4J_PASS")

    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASS))
    try:
        with driver.session(database=NEO4J_DB) as session:
            ensure_schema(session)
            items = load_candidates(session)
            print(f"[THREAT] candidates={len(items)}")

            for item in items:
                classified = classify_one(item)
                persist_classification(session, item, classified)

            print_summary(session)
            print("[THREAT] done")
    finally:
        driver.close()


if __name__ == "__main__":
    main()
