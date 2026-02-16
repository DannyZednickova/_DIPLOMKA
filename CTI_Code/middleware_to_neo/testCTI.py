import json
from pycti import OpenCTIApiClient, OpenCTIStix2
from pycti.utils.opencti_stix2 import OpenCTIStix2  # <-- DŮLEŽITÉ
import os
import json
import uuid
from datetime import datetime, timezone


OPENCTI_URL = os.getenv("OPENCTI_URL", "http://localhost:8080/graphql")
OPENCTI_TOKEN = os.getenv("OPENCTI_TOKEN", "3c6f2d8e-9c6e-4f4a-9f7a-5a8c9a8b1e22")


#ENTITY_ID = os.getenv("ENTITY_ID", "058688fb-642d-48ff-ad11-14e3e4902995") #attack pattern MITRE AND ATTACK
#ENTITY_ID = os.getenv("ENTITY_ID", "52984ef0-3299-4bf8-88a6-096cad6a3da5")  # MALWARE
#ENTITY_ID = os.getenv("ENTITY_ID", "b53ddb38-7465-4dd5-b469-84a3e8d1b5a1")  # CVE
#ENTITY_ID = os.getenv("ENTITY_ID", "429bccca-754e-4aea-a65f-4950976ee700")  # Intrusion set

#identifikator test
ENTITY_ID = os.getenv("ENTITY_ID", "malware--c944c24b-110d-5bec-8a0c-3a71e4fc82f7")


MODE = os.getenv("MODE", "full")  # full / simple

client = OpenCTIApiClient(OPENCTI_URL, OPENCTI_TOKEN)

# zjisti entity_type (Attack-Pattern / Report / Incident / ...)
entity = client.stix_core_object.read(id=ENTITY_ID)
if not entity:
    raise SystemExit(f"Objekt nenalezen: {ENTITY_ID}")


entity_type = entity.get("entity_type") or entity.get("type")
if not entity_type:
    raise SystemExit(f"Neznám entity_type pro: {ENTITY_ID}")


bundle = client.stix2.get_stix_bundle_or_object_from_entity_id(
    entity_type=entity_type,
    entity_id=ENTITY_ID,
    mode=MODE,
)



print(json.dumps(bundle, ensure_ascii=False, indent=2))
