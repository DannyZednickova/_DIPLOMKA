from __future__ import annotations

import os
import re
import sys
import subprocess
import logging
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Set

from dotenv import load_dotenv
from neo4j import GraphDatabase


# ----------------------------
# Logging
# ----------------------------
logging.getLogger("neo4j").setLevel(logging.WARNING)

# ----------------------------
# CONFIG
# ----------------------------
load_dotenv()

NEO4J_URI = os.getenv("NEO4J_URI")
NEO4J_USER = os.getenv("NEO4J_USER")
NEO4J_PASS = os.getenv("NEO4J_PASS")
NEO4J_DB = os.getenv("NEO4J_DB")  # např. "newcve" (OpenVAS/exposure DB)

OPENVAS_XML_PATH = Path(os.getenv("OPENVAS_XML_PATH", ""))

# --- CTI trigger config ---
CTI_ENABLE = os.getenv("CTI_ENABLE", "1") == "1"
CTI_SCRIPT_PATH = Path(os.getenv("CTI_SCRIPT_PATH", "CVE_To_Neo.py"))  # cesta k CVE_To_Neo.py
CTI_MAX_CVES = int(os.getenv("CTI_MAX_CVES", "900"))

# --- Threat-class trigger config (OpenVAS -> LLM) ---
THREAT_LLM_ENABLE = os.getenv("THREAT_LLM_ENABLE", "1") == "1"
THREAT_LLM_SCRIPT_PATH = Path(os.getenv("THREAT_LLM_SCRIPT_PATH", "Openvas_to_llm.py"))



# předáš CTI skriptu i tyhle parametry, pokud je používá
CTI_HOPS = os.getenv("HOPS", "1")
CTI_PAGE_SIZE = os.getenv("PAGE_SIZE", "500")
MODE = os.getenv("MODE", "full")

# regex na CVE
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)


# ----------------------------
# Data model
# ----------------------------
@dataclass
class Row:
    host_ip: str
    host_name: Optional[str]
    port_raw: Optional[str]
    threat: Optional[str]
    severity: Optional[str]
    qod: Optional[str]

    nvt_oid: Optional[str]
    nvt_name: Optional[str]
    nvt_family: Optional[str]
    nvt_tags_raw: Optional[str]
    nvt_summary: Optional[str]
    nvt_solution: Optional[str]
    nvt_cvss_base: Optional[str]

    cves: List[str]


# ----------------------------
# XML helpers
# ----------------------------
def _text(elem: Optional[ET.Element], path: str) -> Optional[str]:
    if elem is None:
        return None
    v = elem.findtext(path)
    if v is None:
        return None
    v = v.strip()
    return v if v else None


def _attr(elem: Optional[ET.Element], key: str) -> Optional[str]:
    if elem is None:
        return None
    v = elem.attrib.get(key)
    if v is None:
        return None
    v = v.strip()
    return v if v else None

def trigger_openvas_to_llm() -> None:
    if not THREAT_LLM_ENABLE:
        print("[THREAT] Disabled (THREAT_LLM_ENABLE=0).")
        return

    if not THREAT_LLM_SCRIPT_PATH.is_file():
        raise FileNotFoundError(f"Missing THREAT_LLM_SCRIPT_PATH: {THREAT_LLM_SCRIPT_PATH}")

    env = os.environ.copy()
    env["NEO4J_URI"] = NEO4J_URI
    env["NEO4J_USER"] = NEO4J_USER
    env["NEO4J_PASS"] = NEO4J_PASS
    env["NEO4J_DB"] = NEO4J_DB

    py = sys.executable
    print(f"[THREAT] Running: {py} {THREAT_LLM_SCRIPT_PATH}")

    completed = subprocess.run(
        [py, str(THREAT_LLM_SCRIPT_PATH)],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )

    print("[THREAT] STDOUT:\n" + (completed.stdout or ""))
    if completed.stderr:
        print("[THREAT] STDERR:\n" + completed.stderr)

    if completed.returncode != 0:
        raise RuntimeError(f"[THREAT] Openvas_to_llm failed with exit code {completed.returncode}")


def _first_text(elem: ET.Element, paths: List[str]) -> Optional[str]:
    for p in paths:
        v = _text(elem, p)
        if v:
            return v
    return None


def parse_tags_kv(tags: Optional[str]) -> Dict[str, str]:
    if not tags:
        return {}
    parts = [p.strip() for p in tags.split("|") if p.strip()]
    out: Dict[str, str] = {}
    for p in parts:
        if "=" not in p:
            continue
        k, v = p.split("=", 1)
        k = k.strip()
        v = v.strip()
        if k and v and k not in out:
            out[k] = v
    return out


def extract_cves(result_elem: ET.Element) -> List[str]:
    found: List[str] = []

    for ref in result_elem.findall(".//ref"):
        if (ref.attrib.get("type", "") or "").lower() != "cve":
            continue
        cid = (ref.attrib.get("id") or "").strip() or (ref.text or "").strip()
        if cid:
            found.extend([x.upper() for x in CVE_RE.findall(cid)])

    cve_tag = _first_text(result_elem, ["nvt/cve", "cve"])
    if cve_tag:
        found.extend([x.upper() for x in CVE_RE.findall(cve_tag)])

    # dedup preserve order
    out: List[str] = []
    seen: Set[str] = set()
    for c in found:
        c = c.strip().upper()
        if c and c not in seen:
            seen.add(c)
            out.append(c)
    return out


def parse_openvas(xml_path: Path) -> List[Row]:
    tree = ET.parse(xml_path)
    root = tree.getroot()

    results = root.findall(".//result")
    if not results:
        results = [e for e in root.iter() if str(e.tag).endswith("result")]

    rows: List[Row] = []
    for r in results:
        host_ip = _first_text(r, ["host/ip", "host", "host/host"])
        if not host_ip:
            continue
        host_ip = host_ip.strip()

        host_name = _first_text(r, ["host/hostname", "host/name", "hostname"])
        port_raw = _text(r, "port")
        threat = _text(r, "threat")
        severity = _text(r, "severity")
        qod = _text(r, "qod/value")

        nvt = r.find("nvt")
        nvt_oid = _attr(nvt, "oid") or _attr(nvt, "id") or _text(nvt, "oid")
        nvt_name = _first_text(r, ["nvt/name", "name"])
        nvt_family = _text(r, "nvt/family")
        nvt_tags_raw = _text(r, "nvt/tags")
        nvt_cvss_base = _first_text(r, ["nvt/cvss_base", "nvt/cvss_base_score", "cvss_base", "cvss_base_score"])

        tags_kv = parse_tags_kv(nvt_tags_raw)
        nvt_summary = tags_kv.get("summary") or _text(r, "nvt/summary") or _text(r, "nvt/description")
        nvt_solution = _text(r, "nvt/solution") or tags_kv.get("solution") or _text(r, "solution")

        cves = extract_cves(r)

        rows.append(Row(
            host_ip=host_ip,
            host_name=host_name,
            port_raw=port_raw,
            threat=threat,
            severity=severity,
            qod=qod,
            nvt_oid=nvt_oid,
            nvt_name=nvt_name,
            nvt_family=nvt_family,
            nvt_tags_raw=nvt_tags_raw,
            nvt_summary=nvt_summary,
            nvt_solution=nvt_solution,
            nvt_cvss_base=nvt_cvss_base,
            cves=cves,
        ))

    return rows


# ----------------------------
# Neo4j schema (bez konfliktů index/constraint)
# ----------------------------
def ensure_schema(session) -> None:
    """
    Bez názvů + bezpečné: Host.ip, NVT.oid, Vulnerability.name
    (Žádné CTI constrainty tady! To ať řeší CVE_To_Neo.py v jeho DB.)
    """
    session.run("CREATE CONSTRAINT IF NOT EXISTS FOR (h:Host) REQUIRE h.ip IS UNIQUE")
    session.run("CREATE CONSTRAINT IF NOT EXISTS FOR (n:NVT) REQUIRE n.oid IS UNIQUE")
    session.run("CREATE CONSTRAINT IF NOT EXISTS FOR (v:Vulnerability) REQUIRE v.name IS UNIQUE")


# ----------------------------
# Neo4j writes (OpenVAS layer)
# ----------------------------
def import_openvas_to_neo4j(rows: List[Row]) -> List[str]:
    """
    Zapíše Host/NVT/Vulnerability + vazby:
      (Host)-[:HAS_NVT]->(NVT)
      (NVT)-[:REFERS_TO]->(Vulnerability)
      (Host)-[:VULNERABLE_TO]->(Vulnerability)  (čistá hrana, bez props)
    Vrací seznam unikátních CVE pro CTI skript.
    """
    cves_for_cti: List[str] = []
    seen: Set[str] = set()

    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASS))
    try:
        with driver.session(database=NEO4J_DB) as session:
            ensure_schema(session)

            for r in rows:
                session.run(
                    "MERGE (h:Host {ip:$ip}) SET h.hostname = coalesce($hn, h.hostname)",
                    ip=r.host_ip, hn=r.host_name
                )

                if r.nvt_oid:
                    # NVT uzel (metadata patří sem)
                    session.run(
                        """
                        MERGE (n:NVT {oid:$oid})
                        SET n.name      = coalesce($name, n.name),
                            n.family    = coalesce($family, n.family),
                            n.tags_raw  = coalesce($tags_raw, n.tags_raw),
                            n.summary   = coalesce($summary, n.summary),
                            n.solution  = coalesce($solution, n.solution),
                            n.cvss_base = coalesce($cvss_base, n.cvss_base)
                        """,
                        oid=r.nvt_oid,
                        name=r.nvt_name,
                        family=r.nvt_family,
                        tags_raw=r.nvt_tags_raw,
                        summary=r.nvt_summary,
                        solution=r.nvt_solution,
                        cvss_base=r.nvt_cvss_base,
                    )

                    # Host -> NVT (můžeš dát prázdné props, ale tady dávám jen kontext výsledku)
                    session.run(
                        """
                        MATCH (h:Host {ip:$ip})
                        MATCH (n:NVT {oid:$oid})
                        MERGE (h)-[rel:HAS_NVT]->(n)
                        SET rel.port = coalesce($port, rel.port),
                            rel.threat = coalesce($threat, rel.threat),
                            rel.severity = coalesce($severity, rel.severity),
                            rel.qod = coalesce($qod, rel.qod)
                        """,
                        ip=r.host_ip,
                        oid=r.nvt_oid,
                        port=r.port_raw,
                        threat=r.threat,
                        severity=r.severity,
                        qod=r.qod,
                    )

                for cve in r.cves:
                    cve_u = cve.strip().upper()

                    session.run("MERGE (v:Vulnerability {name:$name})", name=cve_u)

                    # NVT -> CVE (NVT může patřit více CVE)
                    if r.nvt_oid:
                        session.run(
                            """
                            MATCH (n:NVT {oid:$oid})
                            MATCH (v:Vulnerability {name:$cve})
                            MERGE (n)-[:REFERS_TO]->(v)
                            """,
                            oid=r.nvt_oid,
                            cve=cve_u,
                        )

                    # Host -> CVE (čistě, bez props)
                    session.run(
                        """
                        MATCH (h:Host {ip:$ip})
                        MATCH (v:Vulnerability {name:$cve})
                        MERGE (h)-[:VULNERABLE_TO]->(v)
                        """,
                        ip=r.host_ip,
                        cve=cve_u,
                    )

                    if cve_u not in seen:
                        seen.add(cve_u)
                        cves_for_cti.append(cve_u)

        return cves_for_cti
    finally:
        driver.close()


# ----------------------------
# CTI trigger: zavolá CVE_To_Neo.py
# ----------------------------
def trigger_new_cti_to_neo(cves: List[str]) -> None:
    if not CTI_ENABLE:
        print("[CTI] Disabled (CTI_ENABLE=0).")
        return

    if not CTI_SCRIPT_PATH.is_file():
        raise FileNotFoundError(f"Missing CTI_SCRIPT_PATH: {CTI_SCRIPT_PATH}")

    uniq = cves[:CTI_MAX_CVES]
    if not uniq:
        print("[CTI] No CVEs to pass.")
        return

    env = os.environ.copy()
    env["CVE_LIST"] = ",".join(uniq)
    env["HOPS"] = CTI_HOPS
    env["PAGE_SIZE"] = CTI_PAGE_SIZE
    env["MODE"] = MODE

    # sjednotí neo4j připojení – CTI skript zapisuje kam chce (typicky do NEO4J_DB=newcti)
    env["NEO4J_URI"] = NEO4J_URI
    env["NEO4J_USER"] = NEO4J_USER
    env["NEO4J_PASS"] = NEO4J_PASS
    env["NEO4J_DB"] = NEO4J_DB  # pokud CTI píše do jiné DB, nastav to v env před spuštěním!

    py = sys.executable
    print(f"[CTI] Running: {py} {CTI_SCRIPT_PATH}")
    print(f"[CTI] CVEs: {len(uniq)}")

    completed = subprocess.run(
        [py, str(CTI_SCRIPT_PATH)],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )

    print("[CTI] STDOUT:\n" + (completed.stdout or ""))
    if completed.stderr:
        print("[CTI] STDERR:\n" + completed.stderr)

    if completed.returncode != 0:
        raise RuntimeError(f"[CTI] NEW_CTI_TO_NEO failed with exit code {completed.returncode}")


def main() -> None:
    if not OPENVAS_XML_PATH.is_file():
        raise SystemExit(f"Missing OPENVAS_XML_PATH: {OPENVAS_XML_PATH}")

    if not all([NEO4J_URI, NEO4J_USER, NEO4J_PASS]):
        raise SystemExit("Missing Neo4j env: NEO4J_URI/NEO4J_USER/NEO4J_PASS")

    print(f"[OPENVAS] XML={OPENVAS_XML_PATH}")
    print(f"[NEO4J]   uri={NEO4J_URI} user={NEO4J_USER} db={NEO4J_DB or '(default)'}")

    rows = parse_openvas(OPENVAS_XML_PATH)
    print(f"[OPENVAS] results parsed={len(rows)}")

    cves = import_openvas_to_neo4j(rows)
    print(f"[OPENVAS->NEO4J] unique CVEs={len(cves)}")

    #  po importu OpenVAS spusť klasifikaci do ThreatClass (Openvas_to_llm.py)
    trigger_openvas_to_llm()

    #  tady se volá CVE_To_Neo.py (a NIC jiného CTI se tu nedělá)
    trigger_new_cti_to_neo(cves)

    print("[OK] done.")


if __name__ == "__main__":
    main()
