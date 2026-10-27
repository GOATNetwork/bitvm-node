#!/usr/bin/env bash
# DESTRUCTIVE full (re)build of the localnet under $LOCALNET_DATA. Stops everything, WIPES all
# infra data (bitcoin/electrs/anvil/postgres/ipfs) and every node DB/state, recreates the infra
# from scratch, generates the keys if missing, mines 101 blocks, deploys the contracts and the
# subgraph, funds every role, and starts the miner, proof builder and nodes.
#
# This DELETES on-chain state. Requires explicit confirmation:  scripts/reset.sh --yes
# Binaries: builds them (localnet/build.sh) when none are in the cargo target yet; set
# LOCALNET_SKIP_BUILD=1 to refuse instead.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
source "$ROOT/scripts/localnet.env"
COMPOSE="docker compose -p $COMPOSE_PROJECT -f $ROOT/infra/docker-compose.yml"
T_START=$(date +%s)
step() { echo "==== $* ($(( $(date +%s) - T_START ))s) ===="; }

[[ "${1:-}" == "--yes" ]] || { echo "Refusing without --yes. This WIPES all localnet data under $LOCALNET_DATA." >&2; exit 2; }
echo "code $LOCALNET_ROOT"; echo "data $LOCALNET_DATA (project $COMPOSE_PROJECT, ports $PORT_BASE+, anvil chain id $ANVIL_CHAIN_ID)"
mkdir -p "$LOCALNET_DATA" "$STATE_DIR" "$LOGS_DIR" "$RUN_DIR" "$TMP_DIR" "$BIN_DIR"

step "0. binaries"
TARGET="${CARGO_TARGET_DIR:-$REPO_ROOT/target}/release"
if [[ ! -x "$TARGET/bitvm-noded" || ! -x "$TARGET/mock-proof-builder" ]]; then
  [[ "${LOCALNET_SKIP_BUILD:-0}" == 1 ]] && { echo "no binaries in $TARGET and LOCALNET_SKIP_BUILD=1" >&2; exit 1; }
  "$ROOT/build.sh" 2>&1 | tee "$LOGS_DIR/build.log" | tail -n 3
fi
"$ROOT/scripts/install-bins.sh"

step "1. stop everything"
"$ROOT/scripts/down.sh" || true

step "2. remove infra containers + wipe data"
$COMPOSE down --remove-orphans || true
for d in bitcoin electrs anvil postgres ipfs; do
  rm -rf "${DATA_DIR:?}/$d"; mkdir -p "$DATA_DIR/$d"
done
for r in committee_0 committee_1 operator_0 verifier_0 watchtower_0; do
  mkdir -p "$NODES_DIR/$r"
  rm -f  "$NODES_DIR/$r/"bitvm-node.db* 2>/dev/null || true
  rm -rf "$NODES_DIR/$r/cache" "$NODES_DIR/$r/.bitvm-babe-state" 2>/dev/null || true
done
mkdir -p "$SOLDERING_PROOF_PAYLOAD_STORE_PATH"; rm -rf "${SOLDERING_PROOF_PAYLOAD_STORE_PATH:?}"/* 2>/dev/null || true
rm -f "$RUN_DIR/nodes/"*.pid "$RUN_DIR/"*.pid "$RUN_DIR/tuning.env" 2>/dev/null || true
rm -rf "$RUN_DIR/overrides" "$RUN_DIR/e2e" 2>/dev/null || true
rm -f "$STATE_DIR/contracts.json" "$STATE_DIR/subgraph.json"

step "3. keys"
if [[ -f "$STATE_DIR/keys.json" ]]; then echo "  keeping $STATE_DIR/keys.json"; else "$ROOT/tools/gen-keys.sh" | tail -n 2; fi

step "4. recreate infra"
$COMPOSE up -d
echo "  waiting for anvil + bitcoind ..."
for i in $(seq 1 60); do
  a=$($CAST chain-id --rpc-url "$GOAT_CHAIN_URL" 2>/dev/null || true)
  b=$($BCLI getblockcount 2>/dev/null || true)
  [[ -n "$a" && -n "$b" ]] && break
  sleep 2
done
cid=$($CAST chain-id --rpc-url "$GOAT_CHAIN_URL" 2>/dev/null || true)
[[ "$cid" == "$ANVIL_CHAIN_ID" ]] || { echo "anvil not ready / wrong chain id ('$cid')" >&2; exit 1; }

step "5. bitcoind wallet + 101 blocks"
$BCLI createwallet "$BTC_RPC_WALLET" >/dev/null 2>&1 || $BCLI loadwallet "$BTC_RPC_WALLET" >/dev/null 2>&1 || true
ADDR=$($BCLI -rpcwallet="$BTC_RPC_WALLET" getnewaddress bvlocal-miner bech32)
$BCLI generatetoaddress 101 "$ADDR" >/dev/null
echo "  height=$($BCLI getblockcount)"

step "6. deploy contracts (fund gas + deploy + register + stake)"
bash "$ROOT/contracts-local/deploy-local.sh"
step "7. deploy subgraph"
bash "$ROOT/subgraph/deploy-local.sh"

step "8. node env files"
"$ROOT/scripts/gen-node-envs.sh"

step "9. fund roles (BTC + GOAT top-up)"
"$ROOT/scripts/fund.sh"

step "10. start miner, proof builder, nodes"
"$ROOT/scripts/miner.sh" start
"$ROOT/scripts/proof-builder.sh" start
"$ROOT/scripts/nodes.sh" start

step "11. settle + status"
sleep 15
"$ROOT/scripts/status.sh"
echo "reset done in $(( $(date +%s) - T_START ))s"
