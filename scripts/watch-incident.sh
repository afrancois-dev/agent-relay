#!/usr/bin/env bash
# Show the alert firing and the incident it opens, then stop for a decision.
set -euo pipefail

DESK="${DESK_URL:-http://127.0.0.1:8099}"
PROM="${PROMETHEUS_URL:-http://127.0.0.1:9090}"

echo "==> Firing alerts in Prometheus"
curl -sS "${PROM}/api/v1/alerts" | python3 -c '
import json,sys
alerts = json.load(sys.stdin)["data"]["alerts"]
if not alerts:
    print("  (none yet - give the ratio a minute to accumulate)")
for a in alerts:
    labels=a["labels"]
    print(f"  {labels.get(\"alertname\")} severity={labels.get(\"severity\")} route={labels.get(\"route\")} release={labels.get(\"release\")}")
    print(f"    impact: {a[\"annotations\"].get(\"impact\")}")
'

echo
echo "==> Incidents at the desk"
curl -sS "${DESK}/incidents" | python3 -c '
import json,sys
items = json.load(sys.stdin)["items"]
if not items:
    print("  (no incident yet)")
for i in items:
    print(f"  {i[\"id\"]} status={i[\"status\"]} release={i[\"release\"]} route={i[\"route\"]}")
    print(f"    {i[\"summary\"]}")
'
