#!/usr/bin/env bash
# Run the responder loop for an incident through the incident desk.
#
#   scripts/respond.sh INC-xxxx            # full loop: evidence -> agent -> policy -> act -> verify
#   scripts/respond.sh INC-xxxx --dry-run  # decide only; print the command policy would run
#   scripts/respond.sh INC-xxxx --proposal p.json
set -euo pipefail

DESK="${DESK_URL:-http://127.0.0.1:8099}"
INCIDENT="${1:?usage: respond.sh INCIDENT_ID [--dry-run] [--proposal file.json]}"
shift || true

BODY="{}"
if [ "${1:-}" = "--dry-run" ]; then
  BODY='{"dry_run": true}'
fi
if [ "${1:-}" = "--proposal" ]; then
  if [ -z "${2:-}" ]; then echo "missing proposal path" >&2; exit 2; fi
  BODY=$(python3 -c 'import json,sys;print(json.dumps({"proposal":json.load(open(sys.argv[1]))}))' "${2}")
fi

echo "==> Responding to ${INCIDENT}"
curl -sS -X POST "${DESK}/incidents/${INCIDENT}/respond" \
  -H 'content-type: application/json' -d "${BODY}" | python3 -m json.tool
