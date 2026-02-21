from __future__ import annotations

import os
import json
import re
import logging
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import Dict, Any, List, Optional, Set, Tuple

from dotenv import load_dotenv
from pycti import OpenCTIApiClient
from neo4j import GraphDatabase

# ----------------------------
# Logging (utlum spam)
# ----------------------------
logging.getLogger("api").setLevel(logging.WARNING)
logging.getLogger("opencti").setLevel(logging.WARNING)
logging.getLogger("pycti").setLevel(logging.WARNING)

# ----------------------------
# CONFIG
# ----------------------------
load_dotenv()

# OpenVAS
OPENVAS_XML_PATH = os.getenv("OPENVAS_XML_PATH")  # path k report.xml

# OpenCTI
OPENCTI_URL = os.getenv("OPENCTI_URL")
OPENCTI_TOKEN = os.getenv("OPENCTI_TOKEN")
MODE = os.getenv("MODE", "full")  # full/simple

# Neo4j
NEO4J_URI = os.getenv("NEO4J_URI")
NEO4J_USER = os.getenv("NEO4J_USER")
NEO4J_PASS = os.getenv("NEO4J_PASS")
NEO4J_DB = os.getenv("NEO4J_DB")  # např. "newcti" (nebo prázdné => default)

# CTI filtering v bundlu
REL_TYPES = {"targets", "exploits", "uses"}
SOURCE_TYPES = {"attack-pattern", "malware", "intrusion-set"}

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)

# ----------------------------
# OpenVAS parsing model
# ----------------------------
@dataclass
class Row:
    host_ip: str
    host_name: Optional[str]
    port_raw: Optional[str]            # "general/tcp", "80/tcp", "general/icmp", ...
    threat: Optional[str]
    severity: Optional[str]            # často string v reportu
    qod: Optional[str]                 # Quality of detection
    result_description: Optional[str]  # <result><description>...</description>

    nvt_oid: Optional[str]
    nvt_name: Optional[str]
    nvt_family: Optional[str]
    nvt_tags_raw: Optional[str]
    nvt_summary: Optional[str]
    nvt_solution: Optional[str]
    nvt_cvss_base: Optional[str]

    cves: List[str]


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

    # fallback: někdy <nvt/cve> nebo <cve>
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


def parse_openvas(xml_path: str) -> List[Row]:
    tree = ET.parse(xml_path)
    root = tree.getroot()

    results = root.findall(".//result")
    if not results:
        results = [e for e in root.iter() if str(e.tag).endswith("result")]

    rows: List[Row] = []
    for r in results:
        # host
        host_ip = _first_text(r, ["host/ip", "host", "host/host"])
        if not host_ip:
            continue
        host_ip = host_ip.strip()

        host_name = _first_text(r, ["host/hostname", "host/name", "hostname"])

        port_raw = _text(r, "port")
        threat = _text(r, "threat")
        severity = _text(r, "severity")
        qod = _text(r, "qod/value")
        result_description = _text(r, "description")

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
            result_description=result_description,
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
# OpenCTI STIX helpers
# ----------------------------
def index_bundle_objects(bundle: dict) -> dict:
    idx = {}
    for obj in bundle.get("objects", []):
        oid = obj.get("id")
        if oid:
            idx[oid] = obj
    return idx


def find_vuln_obj_in_bundle(bundle: dict, cve_name: str) -> Optional[dict]:
    for obj in bundle.get("objects", []):
        if obj.get("type") == "vulnerability" and obj.get("name") == cve_name:
            return obj
    return None


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
    return mapping.get(stix_type, "".join(part.capitalize() for part in stix_type.split("-")))


def rel_type_to_neo4j(rel_type: str) -> str:
    return rel_type.upper().replace("-", "_")


def to_neo4j_props(stix_obj: Dict[str, Any]) -> Dict[str, Any]:
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

    props["stix_id"] = stix_obj.get("id")
    if "x_opencti_id" in stix_obj:
        props["opencti_id"] = stix_obj.get("x_opencti_id")
    if "type" in stix_obj and isinstance(stix_obj["type"], str):
        props["stix_type"] = stix_obj["type"]

    return props


def extract_edges_for_cve(bundle: dict, cve_name: str) -> List[Dict[str, Any]]:
    objects_idx = index_bundle_objects(bundle)
    vuln_obj = find_vuln_obj_in_bundle(bundle, cve_name)
    if not vuln_obj:
        return []

    vuln_stix_id = vuln_obj["id"]
    edges: List[Dict[str, Any]] = []

    for obj in bundle.get("objects", []):
        if obj.get("type") != "relationship":
            continue

        rtype = obj.get("relationship_type")
        if rtype not in REL_TYPES:
            continue

        if obj.get("target_ref") != vuln_stix_id:
            continue

        src_ref = obj.get("source_ref")
        if not src_ref:
            continue

        src_obj = objects_idx.get(src_ref)
        if not src_obj or src_obj.get("type") not in SOURCE_TYPES:
            continue

        edges.append({"relationship": obj, "source": src_obj, "target": vuln_obj})

    return edges


# ----------------------------
# Neo4j schema + writes
# ----------------------------
def neo4j_init_constraints(driver) -> None:
    """
    Bez názvů => žádné kolize se starým schématem.
    """
    with driver.session(database=NEO4J_DB) as session:
        session.run("CREATE CONSTRAINT IF NOT EXISTS FOR (h:Host) REQUIRE h.ip IS UNIQUE")
        session.run("CREATE CONSTRAINT IF NOT EXISTS FOR (n:NVT) REQUIRE n.oid IS UNIQUE")
        session.run("CREATE CONSTRAINT IF NOT EXISTS FOR (v:Vulnerability) REQUIRE v.name IS UNIQUE")

        for lbl in ["Malware", "AttackPattern", "IntrusionSet", "ThreatActor", "Campaign", "Indicator", "Tool", "Identity", "Report"]:
            session.run(f"CREATE CONSTRAINT IF NOT EXISTS FOR (x:{lbl}) REQUIRE x.stix_id IS UNIQUE")


def upsert_host(tx, ip: str, hostname: Optional[str]) -> None:
    tx.run(
        """
        MERGE (h:Host {ip: $ip})
        SET h.hostname = coalesce($hostname, h.hostname)
        """,
        ip=ip,
        hostname=hostname,
    )


def upsert_nvt(tx, oid: str, props: Dict[str, Any]) -> None:
    tx.run(
        """
        MERGE (n:NVT {oid: $oid})
        SET n += $props
        """,
        oid=oid,
        props=props,
    )


def link_host_has_nvt(tx, host_ip: str, nvt_oid: str, rel_props: Dict[str, Any]) -> None:
    """
    Pokud chceš hranu úplně "čistou", dej rel_props={} a nech to tak.
    Já dávám jen 'kde to bylo' (port/threat/severity/qod) – žádný nvt_name atd. (to patří do NVT uzlu).
    """
    tx.run(
        """
        MATCH (h:Host {ip: $ip})
        MATCH (n:NVT {oid: $oid})
        MERGE (h)-[r:HAS_NVT]->(n)
        SET r += $props
        """,
        ip=host_ip,
        oid=nvt_oid,
        props=rel_props,
    )


def upsert_vulnerability_by_name(tx, cve_name: str, props: Dict[str, Any]) -> None:
    tx.run(
        """
        MERGE (v:Vulnerability {name: $name})
        SET v += $props
        """,
        name=cve_name,
        props=props,
    )


def link_nvt_refers_to_cve(tx, nvt_oid: str, cve_name: str) -> None:
    tx.run(
        """
        MATCH (n:NVT {oid: $oid})
        MATCH (v:Vulnerability {name: $cve})
        MERGE (n)-[:REFERS_TO]->(v)
        """,
        oid=nvt_oid,
        cve=cve_name,
    )


def link_host_vulnerable_to(tx, host_ip: str, cve_name: str) -> None:
    """
    Čistá hrana bez vlastností – jen pro přímé dotazy.
    Pokud ji nechceš vůbec, prostě ten call v pipeline vypni.
    """
    tx.run(
        """
        MATCH (h:Host {ip: $ip})
        MATCH (v:Vulnerability {name: $cve})
        MERGE (h)-[:VULNERABLE_TO]->(v)
        """,
        ip=host_ip,
        cve=cve_name,
    )


def upsert_cti_node(tx, label: str, stix_id: str, props: Dict[str, Any]) -> None:
    tx.run(
        f"""
        MERGE (n:{label} {{stix_id: $stix_id}})
        SET n += $props
        """,
        stix_id=stix_id,
        props=props,
    )


def link_cti_to_cve_by_name(tx, src_label: str, src_stix_id: str, rel_type: str, cve_name: str, rel_props: Dict[str, Any]) -> None:
    """
    CTI uzel -> naše jednotná Vulnerability(name=CVE-...)
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


def rel_props_from_relationship(rel: Dict[str, Any]) -> Dict[str, Any]:
    props: Dict[str, Any] = {}
    for k, v in rel.items():
        if v is None:
            continue
        if isinstance(v, (str, int, float, bool)):
            props[k] = v
        elif isinstance(v, (list, dict)):
            props[k] = json.dumps(v, ensure_ascii=False)
        else:
            props[k] = str(v)

    props["stix_id"] = rel.get("id")
    if "x_opencti_id" in rel:
        props["opencti_id"] = rel.get("x_opencti_id")
    props["relationship_type_norm"] = rel.get("relationship_type")
    return props


# ----------------------------
# MAIN PIPELINE
# ----------------------------
def main() -> None:
    if not OPENVAS_XML_PATH or not os.path.isfile(OPENVAS_XML_PATH):
        raise SystemExit("Chybí/neexistuje OPENVAS_XML_PATH")

    if not all([NEO4J_URI, NEO4J_USER, NEO4J_PASS]):
        raise SystemExit("Chybí Neo4j env: NEO4J_URI/NEO4J_USER/NEO4J_PASS")

    if not all([OPENCTI_URL, OPENCTI_TOKEN]):
        raise SystemExit("Chybí OpenCTI env: OPENCTI_URL/OPENCTI_TOKEN")

    print(f"[OPENVAS] XML={OPENVAS_XML_PATH}")
    print(f"[NEO4J]   uri={NEO4J_URI} user={NEO4J_USER} db={NEO4J_DB or '(default)'}")
    print(f"[OPENCTI] url={OPENCTI_URL} mode={MODE}")

    rows = parse_openvas(OPENVAS_XML_PATH)
    print(f"[OPENVAS] parsed results={len(rows)}")

    # CVE buffer pro enrichment (unikátně)
    cve_buffer: Set[str] = set()
    for r in rows:
        for c in r.cves:
            cve_buffer.add(c)

    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASS))
    neo4j_init_constraints(driver)

    client = OpenCTIApiClient(OPENCTI_URL, OPENCTI_TOKEN)

    with driver.session(database=NEO4J_DB) as session:
        # 1) OpenVAS -> Neo4j: Host, NVT, CVE, linky
        for r in rows:
            session.execute_write(upsert_host, r.host_ip, r.host_name)

            if r.nvt_oid:
                nvt_props = {
                    "oid": r.nvt_oid,
                    "name": r.nvt_name,
                    "family": r.nvt_family,
                    "tags_raw": r.nvt_tags_raw,
                    "summary": r.nvt_summary,
                    "solution": r.nvt_solution,
                    "cvss_base": r.nvt_cvss_base,
                }
                nvt_props = {k: v for k, v in nvt_props.items() if v is not None}
                session.execute_write(upsert_nvt, r.nvt_oid, nvt_props)

                # hrana Host->NVT (minimální kontext, žádné NVT metadata)
                rel_props = {
                    "port": r.port_raw,
                    "threat": r.threat,
                    "severity": r.severity,
                    "qod": r.qod,
                    "result_description": r.result_description,
                }
                rel_props = {k: v for k, v in rel_props.items() if v is not None}
                session.execute_write(link_host_has_nvt, r.host_ip, r.nvt_oid, rel_props)

            # CVE uzly + linky
            for cve in r.cves:
                # jednotná Vulnerability node (name=CVE-...)
                session.execute_write(upsert_vulnerability_by_name, cve, {"name": cve, "source": "openvas"})

                # NVT -> CVE (jeden NVT může referovat víc CVE => tohle to přesně řeší)
                if r.nvt_oid:
                    session.execute_write(link_nvt_refers_to_cve, r.nvt_oid, cve)

                # volitelně Host -> CVE (čistá hrana bez props)
                session.execute_write(link_host_vulnerable_to, r.host_ip, cve)

        print(f"[OPENVAS->NEO4J] unique CVEs={len(cve_buffer)}")

        # 2) OpenCTI enrichment: pro každé CVE doplníme CTI uzly a vztahy na CVE
        for cve_name in sorted(cve_buffer):
            cve_entity = client.vulnerability.read(
                filters={
                    "mode": "and",
                    "filters": [{"key": "name", "values": [cve_name]}],
                    "filterGroups": [],
                }
            )
            if not cve_entity:
                continue

            bundle = client.stix2.get_stix_bundle_or_object_from_entity_id(
                entity_type="Vulnerability",
                entity_id=cve_entity["id"],  # OpenCTI interní UUID
                mode=MODE,
            )

            # doplň vulnerability metadata do našeho uzlu (MERGE podle name)
            vuln_obj = find_vuln_obj_in_bundle(bundle, cve_name)
            if vuln_obj:
                session.execute_write(upsert_vulnerability_by_name, cve_name, to_neo4j_props(vuln_obj))

            # CTI edges (malware/attack-pattern/intrusion-set) -> CVE
            edges = extract_edges_for_cve(bundle, cve_name)
            for e in edges:
                src = e["source"]
                rel = e["relationship"]

                src_label = stix_type_to_label(src.get("type", "unknown"))
                src_props = to_neo4j_props(src)
                if not src_props.get("stix_id"):
                    continue

                # 1) upsert CTI source node
                session.execute_write(upsert_cti_node, src_label, src_props["stix_id"], src_props)

                # 2) relationship -> link na CVE node (by name)
                neo_rel_type = rel_type_to_neo4j(rel.get("relationship_type", "RELATED_TO"))
                rel_props = rel_props_from_relationship(rel)
                if not rel_props.get("stix_id"):
                    continue

                session.execute_write(
                    link_cti_to_cve_by_name,
                    src_label,
                    src_props["stix_id"],
                    neo_rel_type,
                    cve_name,
                    rel_props,
                )

        # sanity check
        cnt_nodes = session.run("MATCH (n) RETURN count(n) AS c").single()["c"]
        cnt_rels = session.run("MATCH ()-[r]->() RETURN count(r) AS c").single()["c"]
        cnt_hosts = session.run("MATCH (:Host) RETURN count(*) AS c").single()["c"]
        cnt_nvts = session.run("MATCH (:NVT) RETURN count(*) AS c").single()["c"]
        cnt_vulns = session.run("MATCH (:Vulnerability) RETURN count(*) AS c").single()["c"]
        print(f"[CHECK] nodes={cnt_nodes}, rels={cnt_rels}, hosts={cnt_hosts}, nvts={cnt_nvts}, vulns={cnt_vulns}")

    driver.close()
    print("[OK] Done.")


if __name__ == "__main__":
    main()
