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
ENTITY_ID = os.getenv("ENTITY_ID", "2aa66f81-862d-40b9-ad66-5f6b246b2614")  # Intrusion set

#identifikator test
#ENTITY_ID = os.getenv("ENTITY_ID", "vulnerability--0dda0210-8681-5f3a-b881-890bba5e92b7")


MODE = os.getenv("MODE", "full")  # full / simple

client = OpenCTIApiClient(OPENCTI_URL, OPENCTI_TOKEN)

# zjisti entity_type (Attack-Pattern / Report / Incident / ...)
entity = client.stix_core_object.read(id=ENTITY_ID)
print(entity)
if not entity:
    raise SystemExit(f"Objekt nenalezen: {ENTITY_ID}")


entity_type = entity.get("entity_type") or entity.get("type")
print(entity_type)
if not entity_type:
    raise SystemExit(f"Neznám entity_type pro: {ENTITY_ID}")


bundle = client.stix2.get_stix_bundle_or_object_from_entity_id(
    entity_type=entity_type,
    entity_id=ENTITY_ID,
    mode=MODE,

)



print(json.dumps(bundle, ensure_ascii=False, indent=2))
