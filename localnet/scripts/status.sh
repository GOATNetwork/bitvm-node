#!/usr/bin/env bash
# One-shot health overview of the localnet: infra containers, support
# processes, chain heights, subgraph sync, and per-node readiness/peers.
set -uo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
source "$ROOT/scripts/localnet.env"

echo "================= localnet status ($COMPOSE_PROJECT, data $LOCALNET_DATA) ================="

echo "--- infra containers ($COMPOSE_PROJECT) ---"
docker ps --format '{{.Names}}\t{{.Status}}' 2>/dev/null | grep "^$COMPOSE_PROJECT-" | sort | sed 's/^/  /' || echo "  (docker unavailable)"

echo "--- chains ---"
tip=$($BCLI getblockcount 2>/dev/null || echo "?")
echo "  bitcoind regtest height : $tip"
if abn=$($CAST block-number --rpc-url "$GOAT_CHAIN_URL" 2>/dev/null); then
  echo "  anvil block             : $abn (chain-id $($CAST chain-id --rpc-url "$GOAT_CHAIN_URL" 2>/dev/null))"
else echo "  anvil                   : unreachable"; fi
sg=$(curl -s --max-time 5 -XPOST -H 'content-type: application/json' \
  -d '{"query":"{indexingStatuses{synced health chains{latestBlock{number} chainHeadBlock{number}}}}"}' \
  $GRAPH_INDEX/graphql 2>/dev/null)
if [[ -n "$sg" ]]; then
  echo "  gateway subgraph        : $(jq -rc '.data.indexingStatuses[0] | "synced=\(.synced) health=\(.health) latest=\(.chains[0].latestBlock.number) head=\(.chains[0].chainHeadBlock.number)"' <<<"$sg" 2>/dev/null || echo "$sg")"
fi

echo "--- support processes ---"
"$ROOT/scripts/miner.sh" status | sed 's/^/  /'
"$ROOT/scripts/proof-builder.sh" status | sed 's/^/  /'

echo "--- nodes ---"
"$ROOT/scripts/nodes.sh" status | tail -n +2
echo "==========================================================="
