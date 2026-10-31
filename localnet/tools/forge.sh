#!/usr/bin/env bash
# forge inside the pinned foundry container. The localnet tree is mounted read-only at /work and
# used as the project root (config contracts-local/foundry.toml, sources contracts-local/ + the
# upstream contracts/), every artifact goes under $LOCALNET_DATA/forge (out, cache, broadcast,
# solc cache), so the checkout never changes. --network host lets `forge script --broadcast`
# reach anvil on 127.0.0.1. Usage: tools/forge.sh build --sizes | tools/forge.sh script <path> ...
set -euo pipefail
source "$(cd "$(dirname "$0")/.." && pwd)/scripts/localnet.env"
mkdir -p "$LOCALNET_DATA/forge/home"
env_args=(); for v in PRIVATE_KEY BITCOINSPV_ADDR STAKE_TOKEN_ADDR COMMITTEE_0 COMMITTEE_1 COMMITTEE_2 COMMITTEE_3 WATCHTOWER_0 WATCHTOWER_1; do
  [[ -n "${!v:-}" ]] && env_args+=(-e "$v=${!v}"); done
exec docker run --rm --network host -u "$LOCALNET_UID:$LOCALNET_GID" \
  -v "$LOCALNET_ROOT:/work:ro" -v "$LOCALNET_DATA/forge:/forge" -w /work \
  -e HOME=/forge/home -e FOUNDRY_CONFIG=/work/contracts-local/foundry.toml -e FOUNDRY_OUT=/forge/out -e FOUNDRY_CACHE_PATH=/forge/cache -e FOUNDRY_BROADCAST=/forge/broadcast \
  -e FOUNDRY_DISABLE_NIGHTLY_WARNING=1 "${env_args[@]}" \
  --entrypoint forge "$FOUNDRY_IMAGE" "$1" --root /work "${@:2}"
