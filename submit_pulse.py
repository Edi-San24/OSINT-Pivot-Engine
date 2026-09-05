# Posts a pulse file to OTX exactly as built. The file is already in the shape
# OTX wants, so nothing here reshapes it: attack_ids stay plain strings and
# public stays a boolean. Wrapping an id as {"id": "T1566.001"} is what OTX
# rejects with "Must be a list of strings".
import json
import sys
import requests

from config import OTX_API_KEY

path = sys.argv[1]
pulse = json.load(open(path))

# The audit keys are local bookkeeping and are not part of the OTX payload.
payload = {k: v for k, v in pulse.items() if not k.startswith("_")}

print(f"  submitting {len(payload['indicators'])} indicators from {path}")
print(f"  description {len(payload['description'])} chars, public={payload['public']!r}, "
      f"{len(payload.get('attack_ids') or [])} attack_ids")

r = requests.post(
    "https://otx.alienvault.com/api/v1/pulses/create",
    headers={"X-OTX-API-KEY": OTX_API_KEY, "Content-Type": "application/json"},
    json=payload,
    timeout=60,
)
print(f"  HTTP {r.status_code}")
if r.status_code >= 400:
    print(f"  {r.text[:600]}")
else:
    data = r.json()
    print(f"  https://otx.alienvault.com/pulse/{data.get('id','')}")
