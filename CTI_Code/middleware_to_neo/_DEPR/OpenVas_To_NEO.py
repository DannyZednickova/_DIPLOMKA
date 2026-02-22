
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
# =========================
NEO4J_URI = os.getenv("NEO4J_URI")
NEO4J_USER = os.getenv("NEO4J_USER")
NEO4J_PASS = os.getenv("NEO4J_PASS")
NEO4J_DB   = os.getenv("NEO4J_DB")

# ---- input
OPENVAS_XML_PATH = Path(os.getenv("OPENVAS_XML_PATH"))


# ============================================================
# CTI TRIGGER CONFIG
# spusti se, kdyz chceme do Neo4J nacpat OpenCTI data o CVE atp.,
# ============================================================
# CTI_ENABLE: umožní/zakáže volání dalšího skriptu CTI_To_NEO.py
CTI_To_Nei_ENABLE = os.getenv("CTI_ENABLE", "1") == "1"
# Cesta k externímu CTI skriptu (ten má dělat OpenCTI -> Neo4j enrichment)
CTI_SCRIPT_PATH = Path(os.getenv("CTI_SCRIPT_PATH"))
# Limit pro počet CVE, které se předají CTI skriptu
CTI_MAX_CVES = int(os.getenv("CTI_MAX_CVES", "900"))
# Parametry se předávají CTI skriptu přes env proměnné
CTI_HOPS = os.getenv("HOPS", "1")
CTI_PAGE_SIZE = os.getenv("PAGE_SIZE", "500")
# Filtr: do CTI enrichmentu posílej jen CVE u kterých je cvss_base v OpenVAS >= threshold
ENRICH_ONLY_CVSS_GE = float(os.getenv("ENRICH_ONLY_CVSS_GE", "0"))

# Regulární výraz pro nalezení CVE identifikátorů kdekoliv v textu.
# - \b ... hranice slova
# - CVE-YYYY-NNNN(....)
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)


# ============================================================
# VALIDACE KONFIGURACE
# ============================================================
# Ověříš, že input XML existuje – jinak skript nemá smysl spouštět.
if not OPENVAS_XML_PATH.is_file():
    sys.exit(f"Missing OPENVAS_XML_PATH: {OPENVAS_XML_PATH}")

# Ověříš, že existuje externí CTI skript – protože se má volat po importu.
if not CTI_SCRIPT_PATH.is_file():
    sys.exit(f"Missing CTI_SCRIPT_PATH: {CTI_SCRIPT_PATH}")





# =========================
# XML HELPERS
# =========================
def text(elem: Optional[ET.Element], path: str) -> Optional[str]:
    """
      Vrátí text z elementu podle XPath-like cesty (elem.findtext(path)).
      - Pokud elem neexistuje / text je prázdný, vrací None.
      - Jinak ořeže whitespace (strip).
      Užitek: zjednoduší parsování XML, nemusí se opakovat None-checky.
      """

    if elem is None:
        return None
    v = elem.findtext(path)
    if v is None:
        return None
    v = v.strip()
    return v if v else None


def attr(elem: Optional[ET.Element], key: str) -> Optional[str]:
    """
    Vrátí hodnotu atributu elementu (elem.attrib.get(key)).
    - Pokud elem neexistuje / atribut není / je prázdný, vrací None.
    Užitek: např. NVT oid je často atribut (<nvt oid="...">).
    """
    if elem is None:
        return None
    v = elem.attrib.get(key)
    if v is None:
        return None
    v = v.strip()
    return v if v else None


def first_text(elem: ET.Element, paths: List[str]) -> Optional[str]:
    """
     Zkusí více cest a vrátí první nalezený neprázdný text.
     Užitek: OpenVAS XML někdy mění/variantně ukládá stejné pole
             (např. cvss_base může být v nvt/cvss_base nebo cvss_base_score).
     """
    for p in paths:
        v = text(elem, p)
        if v:
            return v
    return None


def parse_tags_kv(tags: Optional[str]) -> Dict[str, str]:
    """
    OpenVAS NVT tags bývají ve formátu "k=v|k2=v2|...".
    Tato funkce:
    - rozdělí string podle "|"
    - vezme jen páry s "="
    - vrátí dict {k: v}
    - první výskyt klíče vyhraje (nepřepisuje se)
    Užitek: summary/solution často právě z tags.
    """
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
    """
    Z jedné <result> položky vytáhne CVE reference.
    Postup:
    1) Projde všechny <ref> uzly a vezme ty s type="cve".
       - CVE může být v atributu id="CVE-...." nebo jako text uvnitř <ref>.
       - použije regex CVE_RE, aby odfiltroval a našel validní CVE.
    2) Fallback: někdy je CVE uvedené v <nvt><cve>...</cve>
    3) Dedup: odstraní duplicity při zachování pořadí (seen set).
    Výstup: seznam unikátních CVE (uppercase) pro daný result.
    """
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
    """
    Row = normalizovaná reprezentace jednoho OpenVAS <result>.
    Proč: parsování a Neo4j import chceme dělat nad čistými Python objekty,
          ne nad ET.Element.
    """
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
    """
    Načte OpenVAS XML report a vytvoří list Row objektů.
    Klíčový princip:
    - iteruje přes všechny <result> elementy (atomické detekce)
    - pro každý result:
      - vytáhne host/port/proto
      - vytáhne NVT metadata (oid, name, family, tags)
      - z tags a dalších polí vyrobí summary + solution
      - vytáhne CVE reference
    Výstup: rows = seznam výsledků vhodný pro Neo4j import.
    """
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


# ============================================================
# NEO4J SCHEMA
# ============================================================

def ensure_schema(session):
    """
    V Neo4j vytvoří unikátní constrainty (idempotentně).
    Proč:
    - MERGE je bezpečný jen pokud má uzel jednoznačný klíč (jinak může dělat duplicity).
    - Constrainty zajišťují datovou integritu i výkon.
    """
    # Host: unikátní podle IP
    session.run("""
        CREATE CONSTRAINT host_ip_unique IF NOT EXISTS
        FOR (h:Host) REQUIRE h.ip IS UNIQUE
        """)
    # NVT: unikátní podle oid
    session.run("""
        CREATE CONSTRAINT nvt_oid_unique IF NOT EXISTS
        FOR (n:NVT) REQUIRE n.oid IS UNIQUE
        """)
    # Vulnerability: unikátní podle CVE stringu
    session.run("""
        CREATE CONSTRAINT vuln_cve_unique IF NOT EXISTS
        FOR (v:Vulnerability) REQUIRE v.cve IS UNIQUE
        """)


# ============================================================
# CTI TRIGGER (spuštění externího skriptu)
# ============================================================

def trigger_cti_to_neo(cves: List[str]) -> None:
    """
    Spustí externí skript CTI_To_NEO.py a předá mu seznam CVE přes env proměnnou CVE_LIST.
    Cíl:
    - import OpenVAS -> Neo4j je "asset exposure" vrstva (Host/NVT/CVE)
    - CTI skript přidá "threat context" z OpenCTI (ThreatActor, Malware, Campaign, ...)

    Kroky:
    1) pokud CTI_ENABLE=0 -> nedělá nic
    2) deduplikuje CVE (uppercase) při zachování pořadí
    3) omezí seznam na CTI_MAX_CVES
    4) nastaví env proměnné (CVE_LIST, HOPS, PAGE_SIZE, Neo4j creds)
    5) spustí CTI skript stejným Pythonem (sys.executable)
    6) vypíše stdout/stderr a při chybě vyhodí výjimku
    """
    if not CTI_To_Nei_ENABLE:
        print("[CTI] Disabled (CTI_ENABLE=0).")
        return

    # dedup preserve order (přes Set)
    uniq: List[str] = []
    seen: Set[str] = set()
    for c in cves:
        c = (c or "").strip().upper()
        if c and c not in seen:
            uniq.append(c)
            seen.add(c)

    # pokud nemš co enrichovat, končí
    if not uniq:
        print("[CTI] No CVEs to pass to CTI_To_NEO.py")
        return

    # limituje počet CVE pro bezpečnost / výkon / délku běhu
    uniq = uniq[:CTI_MAX_CVES]
    cve_csv = ",".join(uniq)

    # pojistka: skript musí existovat
    if not os.path.exists(CTI_SCRIPT_PATH):
        raise FileNotFoundError(f"CTI script not found: {CTI_SCRIPT_PATH}")

    # připraví env pro subprocess
    env = os.environ.copy()
    env["CVE_LIST"] = cve_csv

    # předání parametrů do CTI skriptu (pokud je podporuje)
    env["HOPS"] = CTI_HOPS
    env["PAGE_SIZE"] = CTI_PAGE_SIZE

    # sjednocení Neo4j připojení -> CTI skript zapisuje do stejné DB jako OpenVAS import
    env["NEO4J_URI"] = NEO4J_URI
    env["NEO4J_USER"] = NEO4J_USER
    env["NEO4J_PASS"] = NEO4J_PASS
    env["NEO4J_DB"] = NEO4J_DB

    # sys.executable = cesta k pythonu, který spustil aktuální skript
    # tím zajistíš, že CTI skript poběží ve stejném virtualenvu (stejné knihovny)
    py = sys.executable
    print(f"[CTI] Running: {py} {CTI_SCRIPT_PATH}")
    print(f"[CTI] CVEs: {len(uniq)}")

    # subprocess.run spustí proces a počká na dokončení
    completed = subprocess.run(
        [py, CTI_SCRIPT_PATH],
        env=env,
        capture_output=True,   # zachytí stdout/stderr do completed.stdout/stderr
        text=True,             # dekóduje jako text (str), ne bytes
        check=False            # nevyhodí automaticky výjimku; řešíš ručně níže
    )

    # debug log: co CTI skript vypsal
    print("[CTI] STDOUT:\n" + (completed.stdout or ""))
    if completed.stderr:
        print("[CTI] STDERR:\n" + completed.stderr)

    # návratový kód != 0 znamená chyba -> vyhodíš výjimku, aby pipeline failnula
    if completed.returncode != 0:
        raise RuntimeError(f"CTI_To_NEO.py failed with exit code {completed.returncode}")


# =========================
# IMPORTER
# =========================
# ============================================================
# IMPORTER (OpenVAS XML -> Neo4j)
# ============================================================

def import_openvas(xml_path: Path):
    """
    Hlavní pipeline:
    1) parse_openvas: XML -> list Row
    2) připojí se do Neo4j
    3) ensure_schema: constrainty
    4) pro každý Row:
       - MERGE Host
       - MERGE NVT (+ metadata)
       - MERGE vztah Host-[:HAS_NVT]->NVT (s properties)
       - pro každé CVE:
         - MERGE Vulnerability (CVE)
         - MERGE Host-[:VULNERABLE_TO]->Vulnerability (s properties)
         - MERGE NVT-[:REFERS_TO]->Vulnerability
       - sbírá unikátní CVE pro CTI trigger (filtrované podle cvss_base)
    5) po importu zavolá trigger_cti_to_neo(cves_for_cti)
    """
    rows = parse_openvas(xml_path)
    print(f"[+] Parsed rows: {len(rows)}")
    print(f"[+] Total CVE refs: {sum(len(r.cves) for r in rows)}")

    # CVE pro CTI trigger (unikátní, filtrované)
    cves_for_cti: List[str] = []
    seen: Set[str] = set()

    # vytvoří Neo4j driver (pool připojení)
    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASS))
    try:
        # otevře session na konkrétní databázi (Neo4j může mít více DB)
        with driver.session(database=NEO4J_DB) as session:
            # constrainty (idempotentně)
            ensure_schema(session)

            # pro každý OpenVAS result (Row)
            for r in rows:
                # ------------------------------------------------------------
                # (1) Host node
                # ------------------------------------------------------------
                # MERGE: pokud Host s ip existuje, použije ho; jinak vytvoří nový.
                session.run("MERGE (h:Host {ip: $ip})", ip=r.host_ip)

                # ------------------------------------------------------------
                # (2) NVT node + Host->NVT relationship
                # ------------------------------------------------------------
                if r.nvt_oid:
                    # NVT uzel: identita je oid.
                    # SET přes coalesce: pokud přijde nová hodnota, nastaví; pokud None, nechá původní.
                    session.run("""
                        MERGE (n:NVT {oid: $oid})
                        SET n.name = coalesce($name, n.name),
                            n.family = coalesce($family, n.family),
                            n.summary = coalesce($summary, n.summary),
                            n.solution = coalesce($solution, n.solution),
                            n.tags_raw = coalesce($tags_raw, n.tags_raw)
                        """, oid=r.nvt_oid, name=r.nvt_name, family=r.nvt_family,
                                summary=r.summary, solution=r.solution, tags_raw=r.tags_raw)

                    # Vztah Host -> NVT představuje, že daný host byl tímto NVT "zasažen/detekován".
                    # Properties na hraně ukládají kontext: threat, severity, cvss, port, proto.
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

                # ------------------------------------------------------------
                # (3) CVE nodes + vztahy Host->CVE + NVT->CVE
                # ------------------------------------------------------------
                for cve in r.cves:
                    cve_u = cve.strip().upper()

                    # Uzel Vulnerability identifikovaný podle CVE.
                    # v.sources je pole zdrojů, aby bylo vidět odkud CVE pochází (OpenVAS, OpenCTI, ...).
                    # Logika:
                    # - inicializuj sources pokud neexistuje
                    # - pokud "OpenVAS" není v sources, přidej ho
                    session.run("""
                        MERGE (v:Vulnerability {cve: $cve})
                        SET v.sources = coalesce(v.sources, [])
                        WITH v
                        SET v.sources = CASE WHEN NOT $src IN v.sources THEN v.sources + $src ELSE v.sources END
                        """, cve=cve_u, src="OpenVAS")

                    # Vztah Host -> Vulnerability: host je zranitelný na CVE.
                    # Properties ukládají kontext detekce (port, proto, severity, NVT info).
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

                    # Vztah NVT -> Vulnerability: daný plugin referuje na dané CVE.
                    # To ti umožní dotazy typu "jaké CVE spadá pod tento NVT".
                    if r.nvt_oid:
                        session.run("""
                            MATCH (n:NVT {oid: $oid})
                            MATCH (v:Vulnerability {cve: $cve})
                            MERGE (n)-[:REFERS_TO]->(v)
                            """, oid=r.nvt_oid, cve=cve_u)

                    # --------------------------------------------------------
                    # (4) Příprava CVE pro CTI trigger (filtrování podle cvss_base)
                    # --------------------------------------------------------
                    # cvss_base v OpenVAS je string -> převedeme na float s ošetřením chyb
                    try:
                        cvss = float(r.cvss_base) if r.cvss_base else 0.0
                    except ValueError:
                        cvss = 0.0

                    # pokud cvss >= threshold a CVE ještě není v seznamu, přidej
                    if cvss >= ENRICH_ONLY_CVSS_GE and cve_u not in seen:
                        seen.add(cve_u)
                        cves_for_cti.append(cve_u)

        print(f"[=] Done. Imported OpenVAS into Neo4j DB '{NEO4J_DB}'")

    finally:
        # driver zavři vždy (uvolnění zdrojů)
        driver.close()

    # ------------------------------------------------------------
    # (5) CTI TRIGGER až po importu OpenVAS
    # ------------------------------------------------------------
    # Důvod: nejdřív vytvoří graf expozice (Host/CVE/NVT),
    # a pak ho CTI skript obohatí o threat context (TA/Malware/IntrusionSet/...).
    trigger_cti_to_neo(cves_for_cti)


if __name__ == "__main__":
    if not OPENVAS_XML_PATH.exists():
        raise FileNotFoundError(f"Missing XML file: {OPENVAS_XML_PATH.resolve()}")
    import_openvas(OPENVAS_XML_PATH)