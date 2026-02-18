from __future__ import annotations

import os
import json
import hashlib
import logging
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from dotenv import load_dotenv
from neo4j import GraphDatabase
from neo4j.exceptions import ClientError
from pycti import OpenCTIApiClient

# ---------------------------------------------------------------------
# Logging (utlum OpenCTI/pycti spam)
# ---------------------------------------------------------------------
logging.getLogger("api").setLevel(logging.WARNING)
logging.getLogger("opencti").setLevel(logging.WARNING)
logging.getLogger("pycti").setLevel(logging.WARNING)

# ---------------------------------------------------------------------
# ENV / CONFIG
# ---------------------------------------------------------------------
load_dotenv()

# OpenVAS
OPENVAS_XML_PATH = os.getenv("OPENVAS_XML_PATH")  # např. /path/to/report.xml

# OpenCTI
OPENCTI_URL = os.getenv("OPENCTI_URL")
OPENCTI_TOKEN = os.getenv("OPENCTI_TOKEN")
OPENCTI_MODE = os.getenv("OPENCTI_MODE", "full")  # full/simple

# Neo4j
NEO4J_URI = os.getenv("NEO4J_URI")
NEO4J_USER = os.getenv("NEO4J_USER")
NEO4J_PASS = os.getenv("NEO4J_PASS")
NEO4J_DB = os.getenv("NEO4J_DB")  # např. "newcti" (nebo prázdné => default)

# CTI relace, které chceme z bundlu tahat
CTI_REL_TYPES = {"targets", "exploits", "uses"}
CTI_SOURCE_TYPES = {"attack-pattern", "malware", "intrusion-set"}  # STIX lower-case

# ---------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------
@dataclass(frozen=True)
class Finding:
    host_ip: str
    host_name: Optional[str]
    port: Optional[str]
    nvt_oid: Optional[str]
    nvt_name: Optional[str]
    severity: Optional[float]
    threat: Optional[str]
    description: Optional[str]
    solution: Optional[str]
    cves: List[str]  # ["CVE-2024-1234", ...]


# ---------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------
def sha1_hex(s: str) -> str:
    return hashlib.sha1(s.encode("utf-8", errors="ignore")).hexdigest()

def safe_float(x: Optional[str]) -> Optional[float]:
    if x is None:
        return None
    try:
        return float(x)
    except Exception:
        return None

def text_of(elem: Optional[ET.Element]) -> Optional[str]:
    if elem is None:
        return None
    t = elem.text
    if t is None:
        return None
    t = t.strip()
    return t if t else None


# ---------------------------------------------------------------------
# OpenVAS XML parsing
# ---------------------------------------------------------------------
def parse_openvas_xml(xml_path: str) -> Tuple[List[Finding], Set[str]]:
    """
    Vytáhne z OpenVAS reportu:
      - list Finding (host + port + nvt + metadata + CVE list)
      - set všech CVE (buffer pro enrichment)
    """
    tree = ET.parse(xml_path)
    root = tree.getroot()

    findings: List[Finding] = []
    cve_buffer: Set[str] = set()

    # OpenVAS reporty typicky obsahují <results><result>...</result></results>
    # nebo někdy <report><results>...
    result_elems = root.findall(".//result")
    if not result_elems:
        # fallback: někdy je "results/result" v namespace - zkusíme bez ohledu na namespace
        # (ElementTree namespace řeší tak, že tag je "{ns}result".)
        result_elems = [e for e in root.iter() if e.tag.endswith("result")]

    for res in result_elems:
        finding = parse_result_element(res)
        if finding is None:
            continue
        if finding.cves:
            for c in finding.cves:
                cve_buffer.add(c)
        findings.append(finding)

    return findings, cve_buffer


def parse_result_element(res: ET.Element) -> Optional[Finding]:
    """
    Robustní parser jednoho <result>.
    V různých OpenVAS XML může být host/port/nvt/severity jinde.
    """
    # Host info
    host_ip = text_of(res.find("host")) or text_of(res.find("./host/ip"))  # někdy bývá <host>1.2.3.4</host>
    host_name = None

    # Některé reporty mají detail hostu ve <host> s child prvky
    host_elem = res.find("host")
    if host_elem is not None and list(host_elem):
        host_ip = text_of(host_elem.find("ip")) or host_ip
        host_name = text_of(host_elem.find("hostname")) or text_of(host_elem.find("name")) or host_name

    # Port
    port = text_of(res.find("port"))

    # Severity / threat
    severity = safe_float(text_of(res.find("severity")))
    threat = text_of(res.find("threat"))

    # NVT (Network Vulnerability Test) část
    nvt_elem = res.find("nvt")
    nvt_oid = None
    nvt_name = None
    description = None
    solution = None
    cves: List[str] = []

    if nvt_elem is not None:
        nvt_oid = nvt_elem.get("oid") or text_of(nvt_elem.find("oid"))
        nvt_name = text_of(nvt_elem.find("name")) or text_of(nvt_elem.find("title"))

        description = text_of(nvt_elem.find("description"))
        solution = text_of(nvt_elem.find("solution")) or text_of(nvt_elem.find("solution/text"))

        # CVE mohou být:
        # - <cve>CVE-....</cve>
        # - <cve>CVE-1, CVE-2</cve>
        # - v refs: <refs><ref type="cve" id="CVE-..."/></refs>
        # - nebo <xref> ...
        cves = extract_cves_from_result(res, nvt_elem)

    # Pokud nemáme host, ten result není použitelný pro host->HAS_VULNERABILITY
    if not host_ip:
        return None

    return Finding(
        host_ip=host_ip,
        host_name=host_name,
        port=port,
        nvt_oid=nvt_oid,
        nvt_name=nvt_name,
        severity=severity,
        threat=threat,
        description=description,
        solution=solution,
        cves=cves,
    )


def extract_cves_from_result(res: ET.Element, nvt_elem: ET.Element) -> List[str]:
    """
    CVE extraction - co nejrobustnější.
    Pokud se u tebe CVE nachází v jiné části XML, uprav jen tuhle funkci.
    """
    out: Set[str] = set()

    # 1) přímé <cve> v nvt
    for cve_elem in nvt_elem.findall(".//cve"):
        val = text_of(cve_elem)
        if val:
            for token in split_cve_tokens(val):
                out.add(token)

    # 2) refs: <refs><ref type="cve" id="CVE-...."/></refs>
    refs_elem = nvt_elem.find("refs")
    if refs_elem is not None:
        for ref in refs_elem.findall(".//ref"):
            ref_type = (ref.get("type") or "").lower()
            ref_id = ref.get("id") or text_of(ref)
            if ref_type == "cve" and ref_id:
                for token in split_cve_tokens(ref_id):
                    out.add(token)

    # 3) někdy je CVE v resultu (ne v nvt)
    for cve_elem in res.findall(".//cve"):
        val = text_of(cve_elem)
        if val:
            for token in split_cve_tokens(val):
                out.add(token)

    # Normalizace
    normalized = sorted({c.strip().upper() for c in out if c.strip().upper().startswith("CVE-")})
    return normalized


def split_cve_tokens(s: str) -> List[str]:
    """
    Rozdělí string typu "CVE-2024-1234, CVE-2024-9999" na jednotlivé CVE.
    """
    # typické oddělovače: čárka, mezera, newline
    raw = s.replace("\n", " ").replace("\t", " ").replace(";", ",")
    parts = [p.strip() for p in raw.split(",")]
    tokens: List[str] = []
    for p in parts:
        if not p:
            continue
        # ještě rozbij podle mezer
        for t in p.split():
            t = t.strip().upper()
            if t.startswith("CVE-"):
                tokens.append(t)
    return tokens












# ---------------------------------------------------------------------
# Neo4j schema + upsert
# ---------------------------------------------------------------------
def neo4j_init_constraints(driver) -> None:
    """
    Idempotentní schema init pro Neo4j 5+ bez kolizí názvů.
    Nepoužívá explicitní názvy constraintů => nepadá na IndexWithNameAlreadyExists.
    """
    statements = [
        # Host
        "CREATE CONSTRAINT IF NOT EXISTS FOR (h:Host) REQUIRE h.ip IS UNIQUE",

        # Jedna Vulnerability per CVE name
        "CREATE CONSTRAINT IF NOT EXISTS FOR (v:Vulnerability) REQUIRE v.name IS UNIQUE",
    ]

    # CTI uzly (unique stix_id)
    for lbl in [
        "Malware", "AttackPattern", "IntrusionSet", "ThreatActor",
        "Campaign", "Indicator", "Tool", "Identity", "Report"
    ]:
        statements.append(
            f"CREATE CONSTRAINT IF NOT EXISTS FOR (n:{lbl}) REQUIRE n.stix_id IS UNIQUE"
        )

    # Spusť
    with driver.session(database=NEO4J_DB) as session:
        for cypher in statements:
            try:
                session.run(cypher)
            except ClientError as e:
                # Kdybys narazil na starší DB s legacy schématem, radši vypiš a pokračuj
                # (typicky by už teď nemělo nastat)
                print(f"[SCHEMA] warning: {e.code}: {e.message}\n  cypher={cypher}")

def upsert_host(tx, ip: str, hostname: Optional[str]) -> None:
    tx.run(
        """
        MERGE (h:Host {ip: $ip})
        SET h.hostname = coalesce($hostname, h.hostname)
        """,
        ip=ip,
        hostname=hostname,
    )


def upsert_vulnerability_by_name(tx, cve_name: str, props: Dict[str, Any]) -> None:
    """
    Jedna Vulnerability per CVE (name). OpenCTI později doplní stix_id/opencti_id/metadata.
    """
    tx.run(
        """
        MERGE (v:Vulnerability {name: $name})
        SET v += $props
        """,
        name=cve_name,
        props=props,
    )


def merge_has_vuln_relationship(
    tx,
    host_ip: str,
    cve_name: str,
    rel_props: Dict[str, Any],
) -> None:
    """
    Idempotentní HRANA Host-[:HAS_VULNERABILITY {finding_id}]->Vulnerability
    finding_id = hash(host_ip|cve|nvt_oid|port)
    """
    tx.run(
        """
        MATCH (h:Host {ip: $ip})
        MATCH (v:Vulnerability {name: $cve})
        MERGE (h)-[r:HAS_VULNERABILITY {finding_id: $finding_id}]->(v)
        SET r += $props
        """,
        ip=host_ip,
        cve=cve_name,
        finding_id=rel_props["finding_id"],
        props=rel_props,
    )


def stix_type_to_label(stix_type: str) -> str:
    mapping = {
        "malware": "Malware",
        "attack-pattern": "AttackPattern",
        "intrusion-set": "IntrusionSet",
        "vulnerability": "Vulnerability",
        "threat-actor": "ThreatActor",
        "campaign": "Campaign",
        "indicator": "Indicator",
        "tool": "Tool",
        "identity": "Identity",
        "report": "Report",
    }
    return mapping.get(stix_type, "".join(p.capitalize() for p in stix_type.split("-")))


def rel_type_to_neo4j(rel_type: str) -> str:
    return rel_type.upper().replace("-", "_")


def upsert_cti_node(tx, label: str, stix_id: str, props: Dict[str, Any]) -> None:
    """
    CTI uzly (Malware/AttackPattern/IntrusionSet...) MERGE podle stix_id.
    """
    tx.run(
        f"""
        MERGE (n:{label} {{stix_id: $stix_id}})
        SET n += $props
        """,
        stix_id=stix_id,
        props=props,
    )


def upsert_cti_relationship(tx, src_label: str, src_stix_id: str, rel_type: str, tgt_label: str, tgt_stix_id: str, rel_props: Dict[str, Any]) -> None:
    """
    Idempotentní CTI hrana MERGE podle rel.stix_id (relationship--...).
    """
    tx.run(
        f"""
        MATCH (a:{src_label} {{stix_id: $src}})
        MATCH (b:{tgt_label} {{stix_id: $tgt}})
        MERGE (a)-[r:{rel_type} {{stix_id: $rel_stix_id}}]->(b)
        SET r += $props
        """,
        src=src_stix_id,
        tgt=tgt_stix_id,
        rel_stix_id=rel_props["stix_id"],
        props=rel_props,
    )


def link_cti_to_vulnerability_by_name(tx, src_label: str, src_stix_id: str, rel_type: str, cve_name: str, rel_props: Dict[str, Any]) -> None:
    """
    Z CTI uzlu (malware/attack-pattern/...) udělá vztah na naši jednotnou Vulnerability {name:CVE-...}.
    To je klíč proti duplikaci: target není nová Vulnerability podle stix_id, ale existující podle name.
    """
    tx.run(
        f"""
        MATCH (a:{src_label} {{stix_id: $src}})
        MATCH (v:Vulnerability {{name: $cve}})
        MERGE (a)-[r:{rel_type} {{stix_id: $rel_stix_id}}]->(v)
        SET r += $props
        """,
        src=src_stix_id,
        cve=cve_name,
        rel_stix_id=rel_props["stix_id"],
        props=rel_props,
    )


# ---------------------------------------------------------------------
# OpenCTI enrichment (CVE by name -> STIX bundle -> Neo4j)
# ---------------------------------------------------------------------
def index_bundle_objects(bundle: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    idx: Dict[str, Dict[str, Any]] = {}
    for obj in bundle.get("objects", []):
        oid = obj.get("id")
        if oid:
            idx[oid] = obj
    return idx


def find_vulnerability_obj_in_bundle(bundle: Dict[str, Any], cve_name: str) -> Optional[Dict[str, Any]]:
    for obj in bundle.get("objects", []):
        if obj.get("type") == "vulnerability" and obj.get("name") == cve_name:
            return obj
    return None


def stix_props_as_neo4j_props(stix_obj: Dict[str, Any]) -> Dict[str, Any]:
    """
    Všechny metadata uložíme do Neo4j properties.
    list/dict -> JSON string (aby se nic neztratilo).
    """
    props: Dict[str, Any] = {}
    for k, v in stix_obj.items():
        if v is None:
            continue
        if isinstance(v, (str, int, float, bool)):
            props[k] = v
        elif isinstance(v, (list, dict)):
            props[k] = json.dumps(v, ensure_ascii=False)
        else:
            props[k] = str(v)

    # sjednocení
    if "id" in stix_obj:
        props["stix_id"] = stix_obj["id"]
    if "x_opencti_id" in stix_obj:
        props["opencti_id"] = stix_obj.get("x_opencti_id")
    if "type" in stix_obj:
        props["stix_type"] = stix_obj.get("type")
    return props


def enrich_one_cve_from_opencti_to_neo4j(
    neo4j_session,
    opencti_client: OpenCTIApiClient,
    cve_name: str,
    mode: str = "full",
) -> None:
    """
    1) najdi OpenCTI Vulnerability podle name
    2) export STIX bundle
    3) doplň metadata na naši jednotnou Neo4j :Vulnerability {name}
    4) vlož CTI source uzly (malware/attack-pattern/intrusion-set) + jejich vztahy na CVE
    """
    cve_entity = opencti_client.vulnerability.read(
        filters={
            "mode": "and",
            "filters": [{"key": "name", "values": [cve_name]}],
            "filterGroups": [],
        }
    )
    if not cve_entity:
        # CVE není v OpenCTI -> enrichment přeskoč
        return

    bundle = opencti_client.stix2.get_stix_bundle_or_object_from_entity_id(
        entity_type="Vulnerability",
        entity_id=cve_entity["id"],  # OpenCTI interní UUID
        mode=mode,
    )

    objects_idx = index_bundle_objects(bundle)
    vuln_obj = find_vulnerability_obj_in_bundle(bundle, cve_name)
    if vuln_obj:
        # Doplň metadata na jednotnou Vulnerability (MERGE podle name)
        vuln_props = stix_props_as_neo4j_props(vuln_obj)
        neo4j_session.execute_write(upsert_vulnerability_by_name, cve_name, vuln_props)

    # Vztahy v bundlu: relationship with source_ref/target_ref
    # Chceme jen ty, kde target je ta vulnerability a source je malware/attack-pattern/intrusion-set
    vuln_stix_id = vuln_obj["id"] if vuln_obj else None

    for obj in bundle.get("objects", []):
        if obj.get("type") != "relationship":
            continue

        rtype = obj.get("relationship_type")
        if rtype not in CTI_REL_TYPES:
            continue

        if vuln_stix_id and obj.get("target_ref") != vuln_stix_id:
            continue

        src_ref = obj.get("source_ref")
        tgt_ref = obj.get("target_ref")
        if not src_ref or not tgt_ref:
            continue

        src_obj = objects_idx.get(src_ref)
        if not src_obj:
            continue

        if src_obj.get("type") not in CTI_SOURCE_TYPES:
            continue

        # 1) upsert CTI source node
        src_label = stix_type_to_label(src_obj["type"])
        src_props = stix_props_as_neo4j_props(src_obj)
        src_stix_id = src_obj["id"]
        neo4j_session.execute_write(upsert_cti_node, src_label, src_stix_id, src_props)

        # 2) upsert relationship properties
        rel_props = stix_props_as_neo4j_props(obj)  # zahrne i stix_id vztahu + opencti_id
        neo_rel_type = rel_type_to_neo4j(rtype)

        # 3) link source -> (jednotná) Vulnerability by name
        #    (tím zabráníme vytvoření druhé Vulnerability uzlované podle stix_id)
        neo4j_session.execute_write(
            link_cti_to_vulnerability_by_name,
            src_label,
            src_stix_id,
            neo_rel_type,
            cve_name,
            rel_props,
        )


# ---------------------------------------------------------------------
# Pipeline: OpenVAS -> Neo4j + buffer -> OpenCTI enrichment -> Neo4j
# ---------------------------------------------------------------------
def openvas_to_neo4j_and_enrich():
    if not OPENVAS_XML_PATH or not os.path.isfile(OPENVAS_XML_PATH):
        raise SystemExit("Chybí nebo neexistuje OPENVAS_XML_PATH")

    if not all([NEO4J_URI, NEO4J_USER, NEO4J_PASS]):
        raise SystemExit("Chybí Neo4j env: NEO4J_URI / NEO4J_USER / NEO4J_PASS")

    if not all([OPENCTI_URL, OPENCTI_TOKEN]):
        raise SystemExit("Chybí OpenCTI env: OPENCTI_URL / OPENCTI_TOKEN")

    print(f"[OPENVAS] XML: {OPENVAS_XML_PATH}")
    print(f"[NEO4J]   uri={NEO4J_URI} user={NEO4J_USER} db={NEO4J_DB or '(default)'}")
    print(f"[OPENCTI] url={OPENCTI_URL} mode={OPENCTI_MODE}")

    findings, cve_buffer = parse_openvas_xml(OPENVAS_XML_PATH)
    print(f"[OPENVAS] findings: {len(findings)}, unique CVEs: {len(cve_buffer)}")

    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASS))
    neo4j_init_constraints(driver)

    opencti_client = OpenCTIApiClient(OPENCTI_URL, OPENCTI_TOKEN)

    with driver.session(database=NEO4J_DB) as session:
        # -----------------------------------------------------------------
        # 1) OpenVAS -> Neo4j (Host + Vulnerability(by name) + HAS_VULNERABILITY)
        # -----------------------------------------------------------------
        written_rels = 0
        written_hosts = 0
        written_vulns = 0

        for f in findings:
            # host
            session.execute_write(upsert_host, f.host_ip, f.host_name)
            written_hosts += 1

            # pro každé CVE vytvoř jednotnou Vulnerability uzel (MERGE podle name)
            for cve in f.cves:
                vuln_props = {
                    # minimální společná metadata z OpenVAS
                    "name": cve,
                    "source": "openvas",
                }
                session.execute_write(upsert_vulnerability_by_name, cve, vuln_props)
                written_vulns += 1

                # hrana Host -> HAS_VULNERABILITY -> Vulnerability
                finding_key = f"{f.host_ip}|{cve}|{f.nvt_oid or ''}|{f.port or ''}"
                finding_id = sha1_hex(finding_key)

                rel_props = {
                    "finding_id": finding_id,
                    "source": "openvas",
                    "port": f.port,
                    "nvt_oid": f.nvt_oid,
                    "nvt_name": f.nvt_name,
                    "severity": f.severity,
                    "threat": f.threat,
                    "description": f.description,
                    "solution": f.solution,
                }
                # odstraň None, ať Neo4j nedostane nully
                rel_props = {k: v for k, v in rel_props.items() if v is not None}

                session.execute_write(merge_has_vuln_relationship, f.host_ip, cve, rel_props)
                written_rels += 1

        print(f"[OPENVAS->NEO4J] hosts upserts={written_hosts}, vulns upserts={written_vulns}, HAS_VULNERABILITY edges={written_rels}")

        # -----------------------------------------------------------------
        # 2) Enrichment: buffer CVE -> OpenCTI -> Neo4j (CTI nodes/edges + vuln metadata)
        # -----------------------------------------------------------------
        enriched = 0
        for cve in sorted(cve_buffer):
            enrich_one_cve_from_opencti_to_neo4j(
                neo4j_session=session,
                opencti_client=opencti_client,
                cve_name=cve,
                mode=OPENCTI_MODE,
            )
            enriched += 1

        print(f"[CTI->NEO4J] enrichment attempts={enriched}")

        # -----------------------------------------------------------------
        # 3) Sanity check counts
        # -----------------------------------------------------------------
        cnt_nodes = session.run("MATCH (n) RETURN count(n) AS c").single()["c"]
        cnt_rels = session.run("MATCH ()-[r]->() RETURN count(r) AS c").single()["c"]
        cnt_hosts = session.run("MATCH (h:Host) RETURN count(h) AS c").single()["c"]
        cnt_vuln = session.run("MATCH (v:Vulnerability) RETURN count(v) AS c").single()["c"]
        print(f"[CHECK] nodes={cnt_nodes}, rels={cnt_rels}, hosts={cnt_hosts}, vulnerabilities={cnt_vuln}")

    driver.close()


if __name__ == "__main__":
    openvas_to_neo4j_and_enrich()
