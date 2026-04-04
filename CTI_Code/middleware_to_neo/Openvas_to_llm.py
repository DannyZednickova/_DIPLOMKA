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

LLM_PROVIDER = os.getenv("THREAT_LLM_PROVIDER", "ollama")
LLM_MODEL = os.getenv("THREAT_LLM_MODEL", "qwen2.5:7b-instruct")
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://127.0.0.1:11434/api/generate")
OLLAMA_TIMEOUT = int(os.getenv("OLLAMA_TIMEOUT", "35"))
OLLAMA_TAGS_URL = os.getenv("OLLAMA_TAGS_URL", "http://127.0.0.1:11434/api/tags")
OLLAMA_DEBUG = os.getenv("THREAT_LLM_DEBUG", "1") == "1"

MAX_TEXT_CHARS = int(os.getenv("THREAT_MAX_TEXT_CHARS", "2500"))
MAX_RESULTS = int(os.getenv("THREAT_MAX_RESULTS", "400"))
MIN_SEVERITY = float(os.getenv("THREAT_MIN_SEVERITY", "7.0"))
MIN_QOD = int(os.getenv("THREAT_MIN_QOD", "70"))
FORCE_RULES_ONLY = os.getenv("THREAT_RULES_ONLY", "0") == "1"

REQUEST_COUNTER = 0


def _next_request_counter() -> int:
    globals()["REQUEST_COUNTER"] = int(globals().get("REQUEST_COUNTER", 0)) + 1
    return int(globals()["REQUEST_COUNTER"])


def _current_request_counter() -> int:
    return int(globals().get("REQUEST_COUNTER", 0))


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
    "Unclassified / Needs Review",
]

KEYWORD_RULES: List[Tuple[str, List[str]]] = [
    ("Remote Code Execution", [
        "rce", "remote code execution", "execute arbitrary", "command injection", "remote shell", "backdoor",
        "arbitrary command", "shell remotely", "gain a shell"
    ]),
    ("Initial Access", [
        "unauthenticated", "exposed service", "remote access", "publicly accessible", "internet exposed",
        "open port", "default install", "external attacker"
    ]),
    ("Exposure / Information Disclosure", [
        "read file", "information disclosure", "lfi", "directory traversal", "sensitive information",
        "source code disclosure", "path traversal", "file inclusion"
    ]),
    ("Credential Access", [
        "default credentials", "weak password", "bruteforce", "credential", "password", "login bypass",
        "auth bypass", "account takeover"
    ]),
    ("Privilege Escalation", [
        "privilege escalation", "elevation of privilege", "local privilege", "sudo", "setuid"
    ]),
    ("Lateral Movement", [
        "lateral movement", "pivot", "remote administration", "smb", "winrm", "rdp"
    ]),
    ("Ransomware Risk", [
        "wormable", "eternalblue", "smbv1", "known exploited", "kev", "mass exploitation"
    ]),
    ("Malware Delivery", [
        "trojan", "malware", "dropper", "payload", "malicious file", "implant"
    ]),
    ("Denial of Service", [
        "denial of service", "dos", "ddos", "resource exhaustion", "crash"
    ]),
    ("Persistence", [
        "web shell", "persistence", "startup", "autorun", "scheduled task"
    ]),
    ("Command and Control", [
        "c2", "command and control", "beacon", "callback", "reverse shell"
    ]),
    ("Configuration Weakness", [
        "misconfiguration", "insecure configuration", "hardening", "tls", "ssl", "deprecated", "outdated",
        "missing patch", "vulnerable version", "weak cipher", "tls1.0", "tls1.1", "self-signed",
        "expired certificate", "cbc", "rc4", "3des", "ssh weak",  "insufficient strength" , " certificate has already expired", ""
    ]),
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
        out.append("Unclassified / Needs Review")
    return out


def _ollama_healthcheck() -> None:
    if LLM_PROVIDER != "ollama" or FORCE_RULES_ONLY:
        return

    try:
        start = time.perf_counter()
        r = requests.get(OLLAMA_TAGS_URL, timeout=min(OLLAMA_TIMEOUT, 10))
        took_ms = (time.perf_counter() - start) * 1000
        r.raise_for_status()
        payload = r.json()
        names = [m.get("name", "") for m in payload.get("models", [])]
        model_present = any(name.startswith(LLM_MODEL) for name in names)
        print(
            f"[THREAT][OLLAMA] healthcheck ok status={r.status_code} "
            f"models={len(names)} model_present={model_present} elapsed_ms={took_ms:.0f}"
        )
        if OLLAMA_DEBUG and names:
            preview = ", ".join(names[:8])
            print(f"[THREAT][OLLAMA] model list (first): {preview}")
    except Exception as exc:
        print(f"[THREAT][OLLAMA] healthcheck failed: {exc}")


def _call_ollama(prompt: str, oid: str | None = None) -> Dict:
    request_no = _next_request_counter()
    payload = {
        "model": LLM_MODEL,
        "prompt": prompt,
        "stream": False,
        "format": "json",
        "options": {"temperature": 0.1},
    }

    print(
        f"[THREAT][OLLAMA] request#{request_no} oid={oid or '-'} model={LLM_MODEL} "
        f"prompt_chars={len(prompt)} url={OLLAMA_URL}"
    )

    start = time.perf_counter()
    r = requests.post(OLLAMA_URL, json=payload, timeout=OLLAMA_TIMEOUT)
    took_ms = (time.perf_counter() - start) * 1000

    print(f"[THREAT][OLLAMA] response#{request_no} oid={oid or '-'} status={r.status_code} elapsed_ms={took_ms:.0f}")

    r.raise_for_status()
    body = r.json()
    raw = body.get("response", "{}")

    if OLLAMA_DEBUG:
        print(f"[THREAT][OLLAMA] response#{request_no} oid={oid or '-'} payload_chars={len(raw)}")

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
last_description: {item.get('last_description')}
port_samples: {item.get('ports')}
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
        item.get("last_description") or "",
    ])

    if len(combined) > MAX_TEXT_CHARS:
        item = dict(item)
        item["description"] = (item.get("description") or "")[:MAX_TEXT_CHARS]
        item["last_description"] = (item.get("last_description") or "")[:MAX_TEXT_CHARS]

    if LLM_PROVIDER == "ollama" and not FORCE_RULES_ONLY:
        try:
            # DETAILNI VYPIS VSTUPU DO LLM
            llm_input_debug = {
                "name": item.get("name"),
                "family": item.get("family"),
                "summary": item.get("summary"),
                "description": item.get("description"),
                "last_description": item.get("last_description"),
                "port_samples": item.get("ports"),
                "cvss": item.get("cvss"),
                "threat": item.get("threat"),
                "oid": item.get("oid"),

            }
            print("[THREAT][OLLAMA][INPUT] " + json.dumps(llm_input_debug, ensure_ascii=False)[:4000])

            oid = item.get("oid")
            result = _call_ollama(_build_prompt(item), oid=oid)
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
    # Klasifikace po unikatnich NVT (OID), ne po kazdem host->nvt nalezu.
    query = """
    MATCH (h:Host)-[rel:HAS_NVT]->(n:NVT)
    WITH n,
         collect(DISTINCT h.ip)[0..200] AS host_ips,
         collect(DISTINCT rel.port)[0..25] AS ports,
         max(toFloat(coalesce(rel.severity, n.cvss_base, '0'))) AS max_severity,
         max(toInteger(coalesce(rel.qod, '0'))) AS max_qod,
         collect(DISTINCT coalesce(rel.threat, 'unknown'))[0] AS threat_sample
    WHERE max_severity >= $min_severity AND max_qod >= $min_qod
    RETURN n.oid AS oid,
           n.name AS name,
           n.family AS family,
           n.summary AS summary,
           n.last_description AS last_description,
           substring(coalesce(n.last_description, ''), 0, $max_text_chars) AS description,
           n.cvss_base AS cvss,
           threat_sample AS threat,
           host_ips,
           ports,
           size(host_ips) AS host_count
    ORDER BY max_severity DESC, host_count DESC
    LIMIT $limit
    """
    records = session.run(
        query,
        limit=MAX_RESULTS,
        min_severity=MIN_SEVERITY,
        min_qod=MIN_QOD,
        max_text_chars=MAX_TEXT_CHARS,
    )
    return [dict(r) for r in records]


def ensure_schema(session) -> None:
    session.run("CREATE CONSTRAINT IF NOT EXISTS FOR (t:ThreatClass) REQUIRE t.name IS UNIQUE")


def persist_classification(session, item: Dict, classified: Dict) -> None:
    base_params = {
        "oid": item.get("oid"),
        "host_ips": item.get("host_ips") or [],
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
            MATCH (n:NVT {oid:$oid})
            MERGE (n)-[r:INDICATES_THREAT]->(t)
            SET r.confidence = $confidence,
                r.reason = $reason,
                r.method = $method
            WITH t
            UNWIND $host_ips AS host_ip
            MATCH (h:Host {ip:host_ip})
            MERGE (h)-[:EXPOSED_TO_THREAT]->(t)
            """,
            **params,
        )


def ensure_every_nvt_has_threat_class(session) -> int:
    query = """
    MERGE (t:ThreatClass {name:'Unclassified / Needs Review'})
    WITH t
    MATCH (n:NVT)
    WHERE NOT (n)-[:INDICATES_THREAT]->(:ThreatClass)
    MERGE (n)-[r:INDICATES_THREAT]->(t)
    SET r.confidence = coalesce(r.confidence, 0.15),
        r.reason = coalesce(r.reason, 'No confident LLM/rule match yet'),
        r.method = coalesce(r.method, 'auto-backfill')
    RETURN count(n) AS added
    """
    rec = session.run(query).single()
    return int(rec["added"] if rec and rec["added"] is not None else 0)


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

    print(
        f"[THREAT] mode provider={LLM_PROVIDER} model={LLM_MODEL} "
        f"rules_only={FORCE_RULES_ONLY} min_sev={MIN_SEVERITY} min_qod={MIN_QOD} limit={MAX_RESULTS}"
    )

    _ollama_healthcheck()

    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASS))
    try:
        with driver.session(database=NEO4J_DB) as session:
            ensure_schema(session)
            items = load_candidates(session)
            print(f"[THREAT] unique_nvt_candidates={len(items)}")

            for idx, item in enumerate(items, start=1):
                if OLLAMA_DEBUG and idx % 10 == 0:
                    print(f"[THREAT] progress {idx}/{len(items)}")
                classified = classify_one(item)
                persist_classification(session, item, classified)

            backfilled = ensure_every_nvt_has_threat_class(session)
            print(f"[THREAT] backfilled_unclassified_nvt={backfilled}")
            print_summary(session)
            print(f"[THREAT][OLLAMA] total_requests={_current_request_counter()}")
            print("[THREAT] done")
    finally:
        driver.close()


if __name__ == "__main__":
    main()