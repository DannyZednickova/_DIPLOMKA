Ten skript je v principu ETL pipeline: Extract (tahá data z OpenCTI přes GraphQL), Transform (vybere a mírně upraví pole, hlavně u Indicator), Load (ukládá uzly a vztahy do Neo4j).

Celkový průběh programu (od startu po konec)

Nastaví si konstanty pro OpenCTI (GraphQL endpoint + token) a pro Neo4j (URI, user, heslo, DB).

Připraví HTTP hlavičky HDR s Bearer tokenem pro OpenCTI.

Definuje pomocné funkce pro volání GraphQL (gql) a pro stránkování výsledků (paginate, paginate_relationships).

Definuje GraphQL dotazy pro jednotlivé typy entit (IntrusionSet, ThreatActor, Malware, Campaign, Indicator) a pro vztahy (stixCoreRelationships).

Definuje mapování LABEL_MAP, aby z OpenCTI typů šlo udělat Neo4j labely.

Definuje funkce, které:

vytvoří v Neo4j unikátní constrainty,

nahrají uzly (MERGE/SET),

nahrají vztahy mezi uzly (MATCH/MERGE na relace).

main() se připojí do Neo4j databáze a spustí:

load_nodes(session) – vytvoří constrainty a nahraje uzly,

load_relationships(session) – nahraje vybrané vztahy (USES, ATTRIBUTED_TO, INDICATES).

Na konci vypíše příkazy, kterými si to ověříš v Neo4j Browseru.

Důležitá vlastnost: používá se MERGE, takže opakované spuštění skriptu má být “idempotentní” v tom smyslu, že ti to nebude tvořit duplicity uzlů (kvůli unikátnímu constraintu a MERGE na id) a relace taky MERGE.