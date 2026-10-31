#!/usr/bin/env bash
# cast inside the pinned foundry container (fallback when the host has no cast). Loopback
# RPC URLs work through --network host. Each call starts a container (~0.3 s).
set -euo pipefail
source "$(cd "$(dirname "$0")/.." && pwd)/scripts/localnet.env"
exec docker run --rm --network host -u "$LOCALNET_UID:$LOCALNET_GID" -e HOME=/tmp -e FOUNDRY_DISABLE_NIGHTLY_WARNING=1 \
  --entrypoint cast "$FOUNDRY_IMAGE" "$@"
