
import re
import subprocess
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
import sys
from typing import Optional, Dict, Any, List, Set
from neo4j import GraphDatabase
from dotenv import load_dotenv
import os

load_dotenv()
# OpenCTI connection
OPENCTI_URL = os.getenv("OPENCTI_URL")
OPENCTI_TOKEN = os.getenv("OPENCTI_TOKEN")
NEO4J_URI = os.getenv("NEO4J_URI")
NEO4J_USER = os.getenv("NEO4J_USER")
NEO4J_PASS = os.getenv("NEO4J_PASS")
NEO4J_DB   = os.getenv("NEO4J_DB")

# ---- input
OPENVAS_XML_PATH = Path(os.getenv("OPENVAS_XML_PATH"))


# ---- enrichment controls
ENRICH_ENABLE = os.getenv("ENRICH_ENABLE", "1") == "1"
ENRICH_MAX_CVES = int(os.getenv("ENRICH_MAX_CVES", "100"))  # bezpečnostní limit
ENRICH_ONLY_HIGHER_THAN = float(os.getenv("ENRICH_ONLY_HIGHER_THAN", "0"))  # třeba 7.0
HOPS = int(os.getenv("HOPS", "1"))
PAGE_SIZE = int(os.getenv("PAGE_SIZE", "200"))



# =========================
# CTI TRIGGER CONFIG
# =========================
CTI_ENABLE = os.getenv("CTI_ENABLE", "1") == "1"
CTI_SCRIPT_PATH = Path(os.getenv("CTI_SCRIPT_PATH"))
CTI_MAX_CVES = int(os.getenv("CTI_MAX_CVES", "200"))

# předáš CTI skriptu (pokud to podporuje; když ne, nevadí)
CTI_HOPS = os.getenv("HOPS", "1")
CTI_PAGE_SIZE = os.getenv("PAGE_SIZE", "200")

# optional: filtruj CVE jen pokud cvss_base >= threshold
ENRICH_ONLY_CVSS_GE = float(os.getenv("ENRICH_ONLY_CVSS_GE", "0"))

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)

##========================
#Check config
#========================
if not OPENVAS_XML_PATH.is_file():
    sys.exit(f"Missing OPENVAS_XML_PATH: {OPENVAS_XML_PATH}")

if not CTI_SCRIPT_PATH.is_file():
    sys.exit(f"Missing CTI_SCRIPT_PATH: {CTI_SCRIPT_PATH}")


# =========================
# XML HELPERS
# =========================
def text(elem: Optional[ET.Element], path: str) -> Optional[str]:
    if elem is None:
        return None
    v = elem.findtext(path)
    if v is None:
        return None
    v = v.strip()
    return v if v else None


def attr(elem: Optional[ET.Element], key: str) -> Optional[str]:
    if elem is None:
        return None
    v = elem.attrib.get(key)
    if v is None:
        return None
    v = v.strip()
    return v if v else None


def first_text(elem: ET.Element, paths: List[str]) -> Optional[str]:
    for p in paths:
        v = text(elem, p)
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
    cves: List[str] = []

    # <ref type="cve" id="CVE-..."/>
    for ref in result_elem.findall(".//ref"):
        if (ref.attrib.get("type", "") or "").lower() != "cve":
            continue
        cid = (ref.attrib.get("id") or "").strip()
        if not cid:
            cid = (ref.text or "").strip()
        if cid:
            found = CVE_RE.findall(cid)
            if found:
                cves.extend([f.upper() for f in found])
            else:
                cves.append(cid.upper())

    # fallback: někdy <nvt/cve>
    cve_tag = first_text(result_elem, ["nvt/cve", "cve"])
    if cve_tag:
        cves.extend([f.upper() for f in CVE_RE.findall(cve_tag)])

    # dedup preserve order
    out: List[str] = []
    seen: Set[str] = set()
    for c in cves:
        c = c.strip().upper()
        if c and c not in seen:
            out.append(c)
            seen.add(c)
    return out


# =========================
# DATA MODEL
# =========================
@dataclass
class Row:
    host_ip: str
    port: Optional[str]
    proto: Optional[str]
    threat: Optional[str]
    severity: Optional[str]
    cvss_base: Optional[str]
    nvt_oid: Optional[str]
    nvt_name: Optional[str]
    nvt_family: Optional[str]
    tags_raw: Optional[str]
    summary: Optional[str]
    solution: Optional[str]
    cves: List[str]


def parse_openvas(xml_path: Path) -> List[Row]:
    tree = ET.parse(xml_path)
    root = tree.getroot()

    results = root.findall(".//result")
    print(f"[+] Found <result> entries: {len(results)}")

    rows: List[Row] = []
    for r in results:
        host_ip = first_text(r, ["host", "host/ip", "host/host"])
        if not host_ip:
            continue
        host_ip = host_ip.strip()

        port_raw = text(r, "port")
        port = None
        proto = None
        if port_raw:
            port_raw = port_raw.strip()
            if "/" in port_raw:
                p, pr = port_raw.split("/", 1)
                port = p.strip() if p.strip() else None
                proto = pr.strip() if pr.strip() else None
            else:
                port = port_raw

        threat = text(r, "threat")
        severity = text(r, "severity")
        cvss_base = first_text(r, ["nvt/cvss_base", "nvt/cvss_base_score", "cvss_base", "cvss_base_score"])

        nvt = r.find("nvt")
        nvt_oid = attr(nvt, "oid") or attr(nvt, "id") or text(nvt, "oid")
        nvt_name = first_text(r, ["nvt/name", "name"])
        nvt_family = text(r, "nvt/family")
        tags_raw = text(r, "nvt/tags")

        tags_kv = parse_tags_kv(tags_raw)
        summary = tags_kv.get("summary") or text(r, "nvt/summary") or text(r, "description")
        solution = text(r, "nvt/solution") or tags_kv.get("solution") or text(r, "solution")

        cves = extract_cves(r)

        rows.append(Row(
            host_ip=host_ip,
            port=port,
            proto=proto,
            threat=threat,
            severity=severity,
            cvss_base=cvss_base,
            nvt_oid=nvt_oid,
            nvt_name=nvt_name,
            nvt_family=nvt_family,
            tags_raw=tags_raw,
            summary=summary,
            solution=solution,
            cves=cves
        ))
    return rows


# =========================
# NEO4J SCHEMA
# =========================
def ensure_schema(session):
    session.run("""
        CREATE CONSTRAINT host_ip_unique IF NOT EXISTS
        FOR (h:Host) REQUIRE h.ip IS UNIQUE
        """)
    session.run("""
        CREATE CONSTRAINT nvt_oid_unique IF NOT EXISTS
        FOR (n:NVT) REQUIRE n.oid IS UNIQUE
        """)
    session.run("""
        CREATE CONSTRAINT vuln_cve_unique IF NOT EXISTS
        FOR (v:Vulnerability) REQUIRE v.cve IS UNIQUE
        """)


# =========================
# CTI TRIGGER
# =========================
def trigger_cti_to_neo(cves: List[str]) -> None:
    if not CTI_ENABLE:
        print("[CTI] Disabled (CTI_ENABLE=0).")
        return

    # dedup preserve order
    uniq: List[str] = []
    seen: Set[str] = set()
    for c in cves:
        c = (c or "").strip().upper()
        if c and c not in seen:
            uniq.append(c)
            seen.add(c)

    if not uniq:
        print("[CTI] No CVEs to pass to CTI_To_NEO.py")
        return

    uniq = uniq[:CTI_MAX_CVES]
    cve_csv = ",".join(uniq)

    if not os.path.exists(CTI_SCRIPT_PATH):
        raise FileNotFoundError(f"CTI script not found: {CTI_SCRIPT_PATH}")

    env = os.environ.copy()
    env["CVE_LIST"] = cve_csv

    # pokud CTI_To_NEO.py čte tyhle proměnné, pošli je
    env["HOPS"] = CTI_HOPS
    env["PAGE_SIZE"] = CTI_PAGE_SIZE

    # sjednotíme zápis do stejné Neo4j DB
    env["NEO4J_URI"] = NEO4J_URI
    env["NEO4J_USER"] = NEO4J_USER
    env["NEO4J_PASS"] = NEO4J_PASS
    env["NEO4J_DB"] = NEO4J_DB

    # KLÍČ: spustit to stejným pythonem jako běží OpenVAS skript
    py = sys.executable
    print(f"[CTI] Running: {py} {CTI_SCRIPT_PATH}")
    print(f"[CTI] CVEs: {len(uniq)}")

    completed = subprocess.run(
        [py, CTI_SCRIPT_PATH],
        env=env,
        capture_output=True,
        text=True,
        check=False
    )

    print("[CTI] STDOUT:\n" + (completed.stdout or ""))
    if completed.stderr:
        print("[CTI] STDERR:\n" + completed.stderr)

    if completed.returncode != 0:
        raise RuntimeError(f"CTI_To_NEO.py failed with exit code {completed.returncode}")

# =========================
# IMPORTER
# =========================
def import_openvas(xml_path: Path):
    rows = parse_openvas(xml_path)
    print(f"[+] Parsed rows: {len(rows)}")
    print(f"[+] Total CVE refs: {sum(len(r.cves) for r in rows)}")

    # sesbírej CVE pro trigger (můžeš filtrovat cvss_base)
    cves_for_cti: List[str] = []
    seen: Set[str] = set()

    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASS))
    try:
        with driver.session(database=NEO4J_DB) as session:
            ensure_schema(session)

            for r in rows:
                # Host
                session.run("MERGE (h:Host {ip: $ip})", ip=r.host_ip)

                # NVT
                if r.nvt_oid:
                    session.run("""
                        MERGE (n:NVT {oid: $oid})
                        SET n.name = coalesce($name, n.name),
                            n.family = coalesce($family, n.family),
                            n.summary = coalesce($summary, n.summary),
                            n.solution = coalesce($solution, n.solution),
                            n.tags_raw = coalesce($tags_raw, n.tags_raw)
                        """, oid=r.nvt_oid, name=r.nvt_name, family=r.nvt_family,
                                summary=r.summary, solution=r.solution, tags_raw=r.tags_raw)

                    # Host -> NVT
                    session.run("""
                        MATCH (h:Host {ip: $ip})
                        MATCH (n:NVT {oid: $oid})
                        MERGE (h)-[rel:HAS_NVT]->(n)
                        SET rel.threat = coalesce($threat, rel.threat),
                            rel.severity = coalesce($severity, rel.severity),
                            rel.cvss_base = coalesce($cvss_base, rel.cvss_base),
                            rel.port = coalesce($port, rel.port),
                            rel.proto = coalesce($proto, rel.proto)
                        """, ip=r.host_ip, oid=r.nvt_oid, threat=r.threat, severity=r.severity,
                                cvss_base=r.cvss_base, port=r.port, proto=r.proto)

                # CVE nodes + vztahy
                for cve in r.cves:
                    cve_u = cve.strip().upper()

                    session.run("""
                        MERGE (v:Vulnerability {cve: $cve})
                        SET v.sources = coalesce(v.sources, [])
                        WITH v
                        SET v.sources = CASE WHEN NOT $src IN v.sources THEN v.sources + $src ELSE v.sources END
                        """, cve=cve_u, src="OpenVAS")

                    session.run("""
                        MATCH (h:Host {ip: $ip})
                        MATCH (v:Vulnerability {cve: $cve})
                        MERGE (h)-[rel:VULNERABLE_TO]->(v)
                        SET rel.threat = coalesce($threat, rel.threat),
                            rel.severity = coalesce($severity, rel.severity),
                            rel.cvss_base = coalesce($cvss_base, rel.cvss_base),
                            rel.port = coalesce($port, rel.port),
                            rel.proto = coalesce($proto, rel.proto),
                            rel.nvt_oid = coalesce($nvt_oid, rel.nvt_oid),
                            rel.nvt_name = coalesce($nvt_name, rel.nvt_name)
                        """, ip=r.host_ip, cve=cve_u, threat=r.threat, severity=r.severity,
                                cvss_base=r.cvss_base, port=r.port, proto=r.proto,
                                nvt_oid=r.nvt_oid, nvt_name=r.nvt_name)

                    if r.nvt_oid:
                        session.run("""
                            MATCH (n:NVT {oid: $oid})
                            MATCH (v:Vulnerability {cve: $cve})
                            MERGE (n)-[:REFERS_TO]->(v)
                            """, oid=r.nvt_oid, cve=cve_u)

                    # připrav CVE pro CTI trigger (volitelně filtr CVSS)
                    try:
                        cvss = float(r.cvss_base) if r.cvss_base else 0.0
                    except ValueError:
                        cvss = 0.0

                    if cvss >= ENRICH_ONLY_CVSS_GE and cve_u not in seen:
                        seen.add(cve_u)
                        cves_for_cti.append(cve_u)

        print(f"[=] Done. Imported OpenVAS into Neo4j DB '{NEO4J_DB}'")

    finally:
        driver.close()

    # TRIGGER CTI (po importu)
    trigger_cti_to_neo(cves_for_cti)


if __name__ == "__main__":
    if not OPENVAS_XML_PATH.exists():
        raise FileNotFoundError(f"Missing XML file: {OPENVAS_XML_PATH.resolve()}")
    import_openvas(OPENVAS_XML_PATH)