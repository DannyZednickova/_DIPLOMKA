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

FORCE_RULES_ONLY = os.getenv("THREAT_RULES_ONLY", "0") == "1"

REQUEST_COUNTER = 0

# LLM vybírá jen jednu třídu. "Unclassified / Needs Review" není povolená LLM,
# používá se jen interně jako fallback.
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

LLM_THREAT_CLASSES = [
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
    ("Remote Code Execution", [
        "rce", "remote code execution", "execute arbitrary", "command injection", "remote shell", "backdoor",
        "arbitrary command", "shell remotely", "gain a shell", "code execution", "execute code"
    ]),
    ("Initial Access", [
        "unauthenticated", "exposed service", "remote access", "publicly accessible", "internet exposed",
        "open port", "external attacker"
    ]),
    ("Exposure / Information Disclosure", [
        "read file", "information disclosure", "lfi", "directory traversal", "sensitive information",
        "source code disclosure", "path traversal", "file inclusion", "disclosure"
    ]),
    ("Credential Access", [
        "default credentials", "weak password", "bruteforce", "credential", "password", "login bypass",
        "auth bypass", "account takeover", "default password"
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
        "weak cipher", "tls1.0", "tls1.1", "self-signed", "expired certificate", "certificate has already expired",
        "cbc", "rc4", "3des", "ssh weak", "insufficient strength", "weak key",
        "rsa keys less than 2048", "less than 2048 bits", "certificate chain"
    ]),
]


def _next_request_counter() -> int:
    globals()["REQUEST_COUNTER"] = int(globals().get("REQUEST_COUNTER", 0)) + 1
    return int(globals()["REQUEST_COUNTER"])


def _current_request_counter() -> int:
    return int(globals().get("REQUEST_COUNTER", 0))


def _normalize(text: str) -> str:
    return re.sub(r"\s+", " ", (text or "").lower()).strip()


def _combined_text(item: Dict) -> str:
    return " ".join([
        item.get("name") or "",
        item.get("family") or "",
        item.get("summary") or "",
        item.get("tags_raw") or "",
        item.get("description") or "",
        item.get("last_description") or "",
        item.get("solution") or "",
    ])


def _is_ssl_tls_configuration_weakness(item: Dict) -> bool:
    text = _normalize(_combined_text(item))
    ssl_tls_markers = [
        "ssl", "tls", "certificate", "certificate chain",
        "weak key", "weak cipher", "deprecated protocol",
        "self-signed", "expired certificate",
        "tls1.0", "tls1.1", "rc4", "3des",
        "rsa keys less than 2048", "less than 2048 bits",
        "replace the certificate with a stronger key",
        "reissue the certificates"
    ]
    return any(marker in text for marker in ssl_tls_markers)


def _fallback_rule_classify(text: str) -> str:
    n = _normalize(text)
    for label, kws in KEYWORD_RULES:
        if any(kw and kw in n for kw in kws):
            return label
    return "Unclassified / Needs Review"


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
        "options": {"temperature": 0.0},
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
    allowed = ", ".join(LLM_THREAT_CLASSES)
    return f"""
Jsi analytik kybernetickych hrozeb.

Mas OpenVAS/OpenCTI nalez.
Vyber presne 1 nejlepsi tridu z povolenych trid.

Pevna pravidla:
- SSL/TLS, certifikaty, weak key, weak cipher, deprecated protocol, expired certificate, self-signed, certificate chain issue => Configuration Weakness
- command injection, remote shell, arbitrary command, code execution => Remote Code Execution
- auth bypass, default credentials, weak password => Credential Access
- information disclosure, file read, directory traversal => Exposure / Information Disclosure
- Do "Configuration Weakness" nedavej RCE jen proto, ze se tyka SSL/TLS komponenty.
- Vrat presne jednu tridu.

Allowed classes: [{allowed}]

Vstup:
name: {item.get('name')}
family: {item.get('family')}
summary: {item.get('summary')}
description: {item.get('description')}
tags_raw: {item.get('tags_raw')}
last_description: {item.get('last_description')}
solution: {item.get('solution')}
port_samples: {item.get('ports')}
cvss: {item.get('cvss')}
threat: {item.get('threat')}

Vrat POUZE JSON bez dalsiho textu:
{{
  "class": "...",
  "confidence": 0.0,
  "reason": "kratke oduvodneni"
}}
""".strip()


def classify_one(item: Dict) -> Dict:
    combined = _combined_text(item)

    if len(combined) > MAX_TEXT_CHARS:
        item = dict(item)
        item["description"] = (item.get("description") or "")[:MAX_TEXT_CHARS]
        item["tags_raw"] = (item.get("tags_raw") or "")[:MAX_TEXT_CHARS]
        item["last_description"] = (item.get("last_description") or "")[:MAX_TEXT_CHARS]
        item["solution"] = (item.get("solution") or "")[:MAX_TEXT_CHARS]

    # Tvrdé pravidlo jen pro SSL/TLS findings
    if _is_ssl_tls_configuration_weakness(item):
        return {
            "classes": ["Configuration Weakness"],
            "confidence": 0.99,
            "reason": "Deterministic SSL/TLS weakness mapping",
            "method": "rules",
        }

    if LLM_PROVIDER == "ollama" and not FORCE_RULES_ONLY:
        try:
            llm_input_debug = {
                "name": item.get("name"),
                "family": item.get("family"),
                "summary": item.get("summary"),
                "description": item.get("description"),
                "last_description": item.get("last_description"),
                "solution": item.get("solution"),
                "tags_raw": item.get("tags_raw"),
                "port_samples": item.get("ports"),
                "cvss": item.get("cvss"),
                "threat": item.get("threat"),
                "oid": item.get("oid"),
            }
            print("[THREAT][OLLAMA][INPUT] " + json.dumps(llm_input_debug, ensure_ascii=False)[:4000])

            oid = item.get("oid")
            result = _call_ollama(_build_prompt(item), oid=oid)

            label = result.get("class")
            if label not in LLM_THREAT_CLASSES:
                label = _fallback_rule_classify(combined)

            return {
                "classes": [label],
                "confidence": float(result.get("confidence", 0.55)),
                "reason": result.get("reason", "LLM classification"),
                "method": "llm",
            }
        except Exception as exc:
            label = _fallback_rule_classify(combined)
            return {
                "classes": [label],
                "confidence": 0.45,
                "reason": f"Fallback rules because LLM call failed: {exc}",
                "method": "rules",
            }

    label = _fallback_rule_classify(combined)
    return {
        "classes": [label],
        "confidence": 0.4,
        "reason": "Rule-only classification",
        "method": "rules",
    }


def load_candidates(session) -> List[Dict]:
    query = """
    MATCH (h:Host)-[rel:HAS_NVT]->(n:NVT)
    WITH n,
         collect(DISTINCT h.ip)[0..200] AS host_ips,
         collect(DISTINCT rel.port)[0..25] AS ports,
         collect(DISTINCT coalesce(rel.threat, 'unknown'))[0] AS threat_sample
    RETURN n.oid AS oid,
           n.name AS name,
           n.family AS family,
           n.summary AS summary,
           n.tags_raw AS tags_raw,
           n.last_description AS last_description,
           substring(coalesce(n.last_description, ''), 0, $max_text_chars) AS description,
           n.solution AS solution,
           n.cvss_base AS cvss,
           threat_sample AS threat,
           host_ips,
           ports,
           size(host_ips) AS host_count
    ORDER BY host_count DESC
    LIMIT $limit
    """
    records = session.run(
        query,
        limit=MAX_RESULTS,
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
        f"rules_only={FORCE_RULES_ONLY} limit={MAX_RESULTS}"
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