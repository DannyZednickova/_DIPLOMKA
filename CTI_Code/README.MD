
Spuštění po vzgenerování uvicorn app.api_web:app --reload

Nezapomeň na FullText indexy v Neo4j pro rychlé hledání!

Zapnout Docker OpenCTI

Spustit OpenVasToNeo, ktery si vola samostante CTI To Neo na zpracovani
CVEcek z OpenCTI do Neo4j.

## Nově: LLM klasifikace kybernetických hrozeb z OpenVAS

Pipeline nyní umí po importu OpenVAS automaticky zavolat lokální LLM klasifikaci
(`OpenVas_Threats_LLM.py`), která převádí findings do grafových tříd hrozeb.

### Co se ukládá do Neo4j

- `(:Host)-[:HAS_NVT]->(:NVT)` z OpenVAS importu.
- `(:NVT)-[:INDICATES_THREAT]->(:ThreatClass)` s `confidence`, `reason`, `method`.
- `(:Host)-[:EXPOSED_TO_THREAT]->(:ThreatClass)` pro agregaci dashboardu.

### Jak to funguje

1. `OpenVas_To_NEO.py` načte XML `<result>` a uloží host/NVT/CVE.
2. Spustí se `CVE_To_Neo.py` (existující CTI enrichment).
3. Spustí se `OpenVas_Threats_LLM.py` (Qwen přes Ollama), která:
   - bere texty z `n.name`, `n.family`, `n.summary`, `n.last_description`,
   - vrací 1–3 třídy hrozeb,
   - při chybě LLM používá fallback pravidla (keyword klasifikace).

### Konfigurace (.env)

- `THREAT_ENABLE=1`
- `THREAT_SCRIPT_PATH=OpenVas_Threats_LLM.py`
- `THREAT_LLM_PROVIDER=ollama`
- `THREAT_LLM_MODEL=qwen2.5:7b-instruct`
- `OLLAMA_URL=http://127.0.0.1:11434/api/generate`
- `THREAT_MAX_RESULTS=1000`
- `THREAT_LLM_DEBUG=1` (vypis request/response komunikace s Ollama API)

### Výstup pro grafy (dashboard)

`OpenVas_Threats_LLM.py` na konci vypíše JSON agregaci:
- `threat_class`
- `hosts`
- `findings`

Tohle je připravené pro pie/bar grafy bez dalšího textového reportu.


### Performance tuning (LLM)

Pro rychlé běhy nastav:
- `THREAT_MAX_RESULTS=200`
- `THREAT_MIN_SEVERITY=7.0`
- `THREAT_MIN_QOD=70`
- `THREAT_RULES_ONLY=1` (volitelné, bez volání Ollama)

Skript nyní klasifikuje unikátní NVT (`oid`) místo každého host->finding záznamu, což výrazně zrychlí běh na velkých datech.


### Debug komunikace s Ollama

Při `THREAT_LLM_DEBUG=1` uvidíš v logu řádky:
- `[THREAT][OLLAMA] healthcheck ok ...`
- `[THREAT][OLLAMA] request oid=...`
- `[THREAT][OLLAMA] response oid=... status=200 elapsed_ms=...`

Tím je ověřeno, že skript opravdu volá Ollama HTTP API.
