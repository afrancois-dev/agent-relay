#!/usr/bin/env bash
# Manual escape hatch: roll the deployment back to the previous revision.
# The responder executes exactly this command (rendered by policy) when it is
# authorized; this script is for a human doing it by hand.
set -euo pipefail

NAMESPACE="${K8S_NAMESPACE:-agent-relay}"
DEPLOYMENT="${K8S_DEPLOYMENT:-agent-relay}"
REVISION="${1:-0}" # 0 = previous revision

if [ "${REVISION}" = "0" ]; then
  kubectl -n "${NAMESPACE}" rollout undo "deployment/${DEPLOYMENT}"
else
  kubectl -n "${NAMESPACE}" rollout undo "deployment/${DEPLOYMENT}" --to-revision="${REVISION}"
fi

kubectl -n "${NAMESPACE}" rollout status "deployment/${DEPLOYMENT}" --timeout=180s
kubectl -n "${NAMESPACE}" rollout history "deployment/${DEPLOYMENT}"
