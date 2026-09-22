#!/usr/bin/env bash
# Run the whole loop end to end and print the reconstruction.
#
#   1. Break the app and deploy the bad release (scripts/break-app.sh)
#   2. Wait for the alert to fire and the desk to open an incident
#   3. Show the incident
#   4. Run the responder (evidence -> headless agent -> policy -> act -> verify)
#   5. Print the report
#
# Requires the observability stack (docker compose up) and the kind cluster.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DESK="${DESK_URL:-http://127.0.0.1:8099}"
WAIT_SECONDS="${WAIT_SECONDS:-180}"

"${ROOT}/scripts/break-app.sh"

echo "==> Waiting up to ${WAIT_SECONDS}s for an incident"
incident=""
for _ in $(seq 1 "${WAIT_SECONDS}"); do
  incident=$(curl -sS "${DESK}/incidents" | python3 -c '
import json,sys
items=json.load(sys.stdin)["items"]
open_=[i for i in items if i["status"] in {"open","investigating"}]
print(open_[0]["id"] if open_ else "")
' 2>/dev/null || true)
  [ -n "${incident}" ] && break
  sleep 1
done
if [ -z "${incident}" ]; then
  echo "no incident opened; check the alert and the traffic generator" >&2
  exit 1
fi
echo "    incident ${incident}"

echo "==> Incident before response"
curl -sS "${DESK}/incidents/${incident}" | python3 -c '
import json,sys
i=json.load(sys.stdin)
print(json.dumps({k:i[k] for k in ("id","status","release","route","summary","impact")}, indent=2))
'

"${ROOT}/scripts/respond.sh" "${incident}"

echo "==> Reconstruction"
curl -sS "${DESK}/incidents/${incident}/report"
