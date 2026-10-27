#!/usr/bin/env bash
# Bring the localnet down in reverse order: nodes, proof-builder, miner, fault proxy.
# By default LEAVES the infra (anvil/graph-node/bitcoind/...) running. Pass `infra` to also
# `docker compose stop` the containers (data is preserved).
#   scripts/down.sh            # stop nodes + support processes only
#   scripts/down.sh infra      # also docker compose stop the infra
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
source "$ROOT/scripts/localnet.env"

echo "==== nodes ===="
"$ROOT/scripts/nodes.sh" stop
echo "==== proof builder ===="
"$ROOT/scripts/proof-builder.sh" stop
echo "==== miner ===="
"$ROOT/scripts/miner.sh" stop
echo "==== fault proxy ===="
"$ROOT/scripts/chaos.sh" proxy stop

if [[ "${1:-}" == "infra" ]]; then
  echo "==== infra (docker compose stop, data preserved) ===="
  docker compose -p "$COMPOSE_PROJECT" -f "$ROOT/infra/docker-compose.yml" stop
else
  echo "==== infra left running (pass 'infra' to also stop it) ===="
fi
echo "done."
