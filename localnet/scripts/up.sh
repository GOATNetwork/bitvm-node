#!/usr/bin/env bash
# Bring the whole localnet up: start the infra if it is not running, (re)install binaries,
# regenerate node .env files, then start miner, proof-builder and the 5 nodes.
# Safe/idempotent and state-preserving: an existing localnet (containers, chains, contracts,
# node DBs under $LOCALNET_DATA) is adopted, never rebuilt. Only manages the $COMPOSE_PROJECT
# docker project and processes launched from $BIN_DIR.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
source "$ROOT/scripts/localnet.env"
COMPOSE="docker compose -p $COMPOSE_PROJECT -f $ROOT/infra/docker-compose.yml"

echo "==== 0. layout ===="
echo "  code  $LOCALNET_ROOT"
echo "  data  $LOCALNET_DATA  (project $COMPOSE_PROJECT, ports $PORT_BASE+)"
[[ -f "$STATE_DIR/keys.json" ]] || { echo "  no $STATE_DIR/keys.json: this is a fresh data dir, run scripts/reset.sh --yes first" >&2; exit 1; }
[[ -f "$STATE_DIR/contracts.json" && -f "$STATE_DIR/subgraph.json" ]] || { echo "  contracts/subgraph not deployed: run scripts/reset.sh --yes" >&2; exit 1; }
mkdir -p "$LOGS_DIR" "$RUN_DIR" "$TMP_DIR" "$SOLDERING_PROOF_PAYLOAD_STORE_PATH"

echo "==== 1. infra ===="
need=(bitcoind electrs anvil postgres ipfs graph-node)
missing=0
for c in "${need[@]}"; do
  docker ps --format '{{.Names}}' 2>/dev/null | grep -qx "$COMPOSE_PROJECT-$c" || { echo "  $COMPOSE_PROJECT-$c is down"; missing=1; }
done
if (( missing )); then
  echo "  starting $COMPOSE_PROJECT infra (docker compose up -d) ..."
  $COMPOSE up -d
else
  echo "  all 6 $COMPOSE_PROJECT containers already running"
fi
# wait for anvil + bitcoind to answer
for i in $(seq 1 30); do
  a=$($CAST chain-id --rpc-url "$GOAT_CHAIN_URL" 2>/dev/null || true)
  b=$($BCLI getblockcount 2>/dev/null || true)
  [[ -n "$a" && -n "$b" ]] && break
  sleep 2
done
cid=$($CAST chain-id --rpc-url "$GOAT_CHAIN_URL" 2>/dev/null || true)
echo "  anvil chain-id=$cid  btc height=$($BCLI getblockcount 2>/dev/null)"
# bitcoind does not reload the miner wallet after its container restarted (down.sh infra, host reboot)
$BCLI loadwallet "$BTC_RPC_WALLET" >/dev/null 2>&1 || true
$BCLI -rpcwallet="$BTC_RPC_WALLET" getwalletinfo >/dev/null 2>&1 || { echo "  bitcoind wallet $BTC_RPC_WALLET not available" >&2; exit 1; }
[[ -n "$cid" ]] || { echo "  anvil not reachable at $GOAT_CHAIN_URL" >&2; exit 1; }
if [[ "$cid" != "$ANVIL_CHAIN_ID" ]]; then
  echo "  anvil runs chain id $cid but ANVIL_CHAIN_ID=$ANVIL_CHAIN_ID; set ANVIL_CHAIN_ID=$cid in $LOCALNET_DATA/localnet.override.env to adopt this chain" >&2
  exit 1
fi

echo "==== 2. binaries + node env files ===="
"$ROOT/scripts/install-bins.sh"
"$ROOT/scripts/gen-node-envs.sh"

echo "==== 3. miner ===="
"$ROOT/scripts/miner.sh" start

echo "==== 4. mock proof builder ===="
"$ROOT/scripts/proof-builder.sh" start

echo "==== 5. funding ===="
"$ROOT/scripts/fund.sh"

echo "==== 6. nodes ===="
# nodes attached to the fault proxy (scripts/chaos.sh attach) reach their backends only through it
if ls "$RUN_DIR/overrides"/*.env >/dev/null 2>&1; then "$ROOT/scripts/chaos.sh" proxy start; fi
"$ROOT/scripts/nodes.sh" start
# A node whose DB needs a migration the binary cannot apply exits within seconds.
sleep 5
dead=()
for r in committee_0 committee_1 operator_0 verifier_0 watchtower_0; do
  "$ROOT/scripts/nodes.sh" status "$r" | grep -q 'up(pid' || dead+=("$r")
done
if (( ${#dead[@]} )); then
  echo "  nodes not running: ${dead[*]}" >&2
  for r in "${dead[@]}"; do
    if grep -qiE 'migrat|VersionMismatch|schema' "$LOGS_DIR/nodes/$r/current" 2>/dev/null; then
      echo "  $r: its DB does not fit this binary (migration failed) -- a fresh state is needed: scripts/reset.sh --yes" >&2
    fi
    tail -n 3 "$LOGS_DIR/nodes/$r/current" 2>/dev/null | cut -c1-200 | sed 's/^/      /' >&2
  done
  exit 1
fi

echo "==== 7. settling (15s) then status ===="
sleep 15
"$ROOT/scripts/status.sh"
