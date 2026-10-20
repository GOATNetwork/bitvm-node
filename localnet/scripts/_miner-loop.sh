#!/usr/bin/env bash
# Internal: the regtest mining loop backgrounded by scripts/miner.sh.
# Distinct filename so the process is unambiguously identifiable in /proc.
set -uo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
source "$ROOT/scripts/localnet.env"
ADDR=$($BCLI -rpcwallet="$BTC_RPC_WALLET" getnewaddress bvlocal-miner bech32 2>/dev/null)
echo "[$(date -u +%FT%TZ)] miner loop start: interval=${MINE_INTERVAL_SECS}s addr=$ADDR"
while true; do
  h=$($BCLI generatetoaddress 1 "$ADDR" 2>/dev/null | tr -d '[]" \n' | cut -c1-64)
  tip=$($BCLI getblockcount 2>/dev/null)
  echo "[$(date -u +%FT%TZ)] mined -> height=$tip"
  sleep "$MINE_INTERVAL_SECS"
done
