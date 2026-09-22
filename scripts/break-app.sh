#!/usr/bin/env bash
# Break the deployed app on purpose and ship it through the same path CI uses.
#
# The fault is a realistic one: an unhandled error in the task-claim path that
# turns the hottest endpoint into a 500. It is introduced as a separate patch
# file so the healthy tree is never left broken and the fault is trivially
# reversible with `git apply -R`.
set -euo pipefail

CLUSTER="${KIND_CLUSTER:-agent-relay}"
NAMESPACE="${K8S_NAMESPACE:-agent-relay}"
DEPLOYMENT="${K8S_DEPLOYMENT:-agent-relay}"
RELEASE="${RELEASE_TAG:-bad-$(date +%s)}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PATCH="${ROOT}/scripts/faults/claim-500.patch"

echo "==> Building the broken image '${RELEASE}' (release label baked in)"
cd "${ROOT}"
if git apply --check "${PATCH}" 2>/dev/null; then
  git apply "${PATCH}"
  echo "    applied ${PATCH}"
  trap 'git apply -R "${PATCH}" 2>/dev/null || true' EXIT
else
  echo "    ${PATCH} already applied; building as-is"
fi

# The release label is a build arg so `rollout undo` reverts code and label
# together. There is no separate `set env` step to drift out of sync.
docker build --build-arg "RELAY_RELEASE=${RELEASE}" -t "agent-relay:${RELEASE}" .
kubectl -n "${NAMESPACE}" set env "deployment/${DEPLOYMENT}" RELAY_RELEASE- 2>/dev/null || true
kind load docker-image "agent-relay:${RELEASE}" --name "${CLUSTER}"

echo "==> Rolling out ${RELEASE} (single atomic image change)"
kubectl -n "${NAMESPACE}" set image "deployment/${DEPLOYMENT}" "${DEPLOYMENT}=agent-relay:${RELEASE}"
kubectl -n "${NAMESPACE}" rollout status "deployment/${DEPLOYMENT}" --timeout=180s

echo "==> Generating user traffic against the broken release"
"${ROOT}/scripts/generate-traffic.sh" || true
echo
echo "Release ${RELEASE} is live. Watch it fire: ${ROOT}/scripts/watch-incident.sh"
