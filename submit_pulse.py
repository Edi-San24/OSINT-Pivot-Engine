# submit_pulse.py
# Posts a pulse file to OTX unmodified.

"""
Submits a pulse built by core.stix_exporter.

The file is already in the shape OTX expects, so nothing here reshapes it:
attack_ids stay plain strings and public stays a boolean. Keys prefixed with an
underscore are the local audit trail and are not part of the payload.

    PYTHONPATH=. python submit_pulse.py pulse.json
"""

import json
import sys

import requests

from config import OTX_API_KEY

CREATE_URL = "https://otx.alienvault.com/api/v1/pulses/create"


def submit(path: str) -> int:
    pulse = json.load(open(path, encoding="utf-8"))
    payload = {k: v for k, v in pulse.items() if not k.startswith("_")}

    print(f"  submitting {len(payload['indicators'])} indicators from {path}")
    print(f"  description {len(payload['description'])} chars, "
          f"public={payload['public']!r}, "
          f"{len(payload.get('attack_ids') or [])} attack_ids")

    response = requests.post(
        CREATE_URL,
        headers={"X-OTX-API-KEY": OTX_API_KEY, "Content-Type": "application/json"},
        json=payload,
        timeout=60,
    )
    print(f"  HTTP {response.status_code}")

    if response.status_code >= 400:
        # The body names every failing field at once, so print it whole.
        print(f"  {response.text[:600]}")
        return 1

    print(f"  https://otx.alienvault.com/pulse/{response.json().get('id', '')}")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(2)
    sys.exit(submit(sys.argv[1]))
