#!/usr/bin/env bash
# Build the mock-enabled node + helper binaries for the localnet from this checkout.
#   localnet/build.sh                 # cargo build -r -p bitvm-noded --features "rpc-debug-endpoints mock-gc" --bins
# CARGO_TARGET_DIR defaults to the repo's own target/ (never share it with another checkout);
# scripts/install-bins.sh then copies the binaries into $LOCALNET_DATA/bin.
set -euo pipefail
source "$(cd "$(dirname "$0")" && pwd)/scripts/localnet.env"
# shellcheck disable=SC1090
[[ -f ~/.zkm-toolchain/env ]] && source ~/.zkm-toolchain/env
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$REPO_ROOT/target}"
export SQLX_OFFLINE=true
cd "$REPO_ROOT"
echo "building in $REPO_ROOT (target $CARGO_TARGET_DIR, features ${NODE_FEATURES:-rpc-debug-endpoints mock-gc})"
exec nice -n "${BUILD_NICE:-15}" cargo build --release -j "${BUILD_JOBS:-8}" -p bitvm-noded \
  --features "${NODE_FEATURES:-rpc-debug-endpoints mock-gc}" --bins
