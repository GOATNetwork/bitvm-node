#!/usr/bin/env bash
# N9: subgraph latency 8 s (< 10 s timeout) on every node for a full peg-in. Exits with the peg-in flow's status.
source "$(cd "$(dirname "$0")/.." && pwd)/lib.sh"
scenario_begin N9 subgraph-latency-8s pegin
# The fast localnet window (50 blocks = 100 s on Anvil) can expire before
# every committee discovers the request under 8 s latency. Use at least the
# upstream 200-block window for this scenario, then restore the live value.
window_before=$($CAST call $GW "responseWindowBlocks()(uint256)" --rpc-url "$GOAT_CHAIN_URL" | awk '{print $1}') || exit 1
[[ $window_before =~ ^[0-9]+$ ]] || { log "invalid response window: $window_before"; exit 1; }
cleanup() {
  local rc=$?
  trap - EXIT
  "$CHAOS" clear all graph >/dev/null 2>&1 || rc=1
  $CAST send $GW "debugSetResponseWindowBlocks(uint256)" "$window_before" --private-key "$C0_GOAT_PRIVATE_KEY" --rpc-url "$GOAT_CHAIN_URL" >/dev/null || rc=1
  exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT TERM
window=$(( window_before > 200 ? window_before : 200 ))
$CAST send $GW "debugSetResponseWindowBlocks(uint256)" "$window" --private-key "$C0_GOAT_PRIVATE_KEY" --rpc-url "$GOAT_CHAIN_URL" >/dev/null || exit 1
log "response window: $window blocks (restored to $window_before on exit)"
"$CHAOS" fault all graph latency 8000 --ttl 2400 || exit 1
"$ROOT/e2e/flows/pegin.sh"; rc=$?
log "event watcher lag/ages:"; for r in committee_0 operator_0; do backend_probe "$r" | grep -E 'event_watch|ready'; done
"$CHAOS" clear all graph
scenario_end N9; log "N9 rc=$rc"
exit $rc
