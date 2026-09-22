#!/usr/bin/env bash
# Deploy one immutable release to the kind cluster.
#
#   scripts/deploy-release.sh                 # healthy release from the current tree
#   scripts/deploy-release.sh bad             # build the tree as-is (use break-app.sh instead)
#
# Design rule that avoids a whole class of incident: the release label is baked
# into the image at build time, and the Deployment template carries the image
# only. `rollout undo` therefore restores code and release label atomically,
# and there is no mutable `RELAY_RELEASE` env var that can drift out of sync.
set -euo pipefail

CLUSTER="${KIND_CLUSTER:-agent-relay}"
NAMESPACE="${K8S_NAMESPACE:-agent-relay}"
DEPLOYMENT="${K8S_DEPLOYMENT:-agent-relay}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

RELEASE="${RELEASE_TAG:-$(git -C "${ROOT}" rev-parse --short HEAD 2>/dev/null || echo local)-$(date +%s)}"
IMAGE="agent-relay:${RELEASE}"

echo "==> Building ${IMAGE} (RELAY_RELEASE=${RELEASE} baked in)"
cd "${ROOT}"
docker build --build-arg "RELAY_RELEASE=${RELEASE}" -t "${IMAGE}" .
kind load docker-image "${IMAGE}" --name "${CLUSTER}"

echo "==> Removing any RELAY_RELEASE env override so the baked label is authoritative"
kubectl -n "${NAMESPACE}" set env "deployment/${DEPLOYMENT}" RELAY_RELEASE- 2>/dev/null || true

echo "==> Pointing the deployment at ${IMAGE}"
kubectl -n "${NAMESPACE}" set image "deployment/${DEPLOYMENT}" "${DEPLOYMENT}=${IMAGE}"
kubectl -n "${NAMESPACE}" rollout status "deployment/${DEPLOYMENT}" --timeout=180s

echo "==> Deployed release ${RELEASE}"
kubectl -n "${NAMESPACE}" get pods -l "app=${DEPLOYMENT}" -o wide
