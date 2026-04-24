

Spuštění po vzgenerování uvicorn app.api_web:app --reload

Když se Uvicorn v terminálu "zasekne" bez výpisu:
- spouštěj z kořene `CTI_Code` přes `python -m uvicorn app.api_web:app --reload`
- ověř, že máš aktivní správné `.venv` (stejný interpreter jako v IDE)
- pokud Neo4j neběží, app teď jen zapíše warning a nezablokuje start (timeout lze změnit přes `NEO4J_CONNECT_TIMEOUT`, default 5s)

DATABAZE V NEO4J 22/04/2026

FINALDB - obsahuje jen spusteni All_Station_Unauthorized
bugtestafterllm - OBSAHUJE VSECHY HOSTY A AUTHORIZED TEST 



Nezapomeň na FullText indexy v Neo4j pro rychlé hledání!

Zapnout Docker OpenCTI

Spustit OpenVasToNeo, ktery si vola samostante CTI To Neo na zpracovani
CVEcek z OpenCTI do Neo4j.
