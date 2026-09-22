#!/usr/bin/env bash
# Generate realistic user traffic against the relay in kind.
#
# Registers two agents through a port-forward, submits tasks, and repeatedly
# claims them. The claim loop is the user-impact path: when the release is
# broken, this drives the 5xx ratio that the alert fires on.
set -euo pipefail

NAMESPACE="${K8S_NAMESPACE:-agent-relay}"
LOCAL_PORT="${LOCAL_PORT:-18080}"
BASE="http://127.0.0.1:${LOCAL_PORT}"
ROUNDS="${ROUNDS:-30}"
SLEEP="${SLEEP:-2}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

kubectl -n "${NAMESPACE}" port-forward svc/agent-relay "${LOCAL_PORT}:8000" >/tmp/relay-port-forward.log 2>&1 &
PF=$!
trap 'kill ${PF} 2>/dev/null || true' EXIT

for _ in $(seq 1 30); do
  curl -sf "${BASE}/ready" >/dev/null 2>&1 && break
  sleep 1
done

sender=$(curl -sS -X POST "${BASE}/api/v1/agents" -H 'content-type: application/json' -d '{"name":"traffic-sender"}')
worker=$(curl -sS -X POST "${BASE}/api/v1/agents" -H 'content-type: application/json' -d '{"name":"traffic-worker"}')
sender_token=$(printf '%s' "${sender}" | python3 -c 'import sys,json;print(json.load(sys.stdin)["token"])')
worker_token=$(printf '%s' "${worker}" | python3 -c 'import sys,json;print(json.load(sys.stdin)["token"])')
worker_id=$(printf '%s' "${worker}" | python3 -c 'import sys,json;print(json.load(sys.stdin)["agent_id"])')

echo "sending ${ROUNDS} rounds of task traffic to ${BASE}"
fail=0
for i in $(seq 1 "${ROUNDS}"); do
  code=$(curl -sS -o /dev/null -w '%{http_code}' -X POST "${BASE}/api/v1/tasks" \
    -H "authorization: Bearer ${sender_token}" -H 'content-type: application/json' \
    -d "{\"to\":\"${worker_id}\",\"input\":\"message ${i}\"}")
  claim_code=$(curl -sS -o /dev/null -w '%{http_code}' -X POST "${BASE}/api/v1/tasks/claim" \
    -H "authorization: Bearer ${worker_token}" -H 'content-type: application/json' \
    -d '{"worker_id":"traffic","wait_seconds":0}')
  [ "${code}" != "201" ] && fail=$((fail + 1))
  [ "${claim_code}" != "200" ] && [ "${claim_code}" != "204" ] && fail=$((fail + 1))
  printf 'round %2d: create=%s claim=%s\n' "${i}" "${code}" "${claim_code}"
  sleep "${SLEEP}"
done
echo "traffic complete; non-success responses: ${fail}"
