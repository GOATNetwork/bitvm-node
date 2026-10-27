#!/usr/bin/env bash
# Happy peg-in: request -> answers -> Prepare -> ceremony -> PeginConfirm -> L2 mint. Prints the instance and graph ids.
source "$(cd "$(dirname "$0")/.." && pwd)/lib.sh"
set -o pipefail
"$ROOT/scripts/miner.sh" stop >/dev/null 2>&1 || true
set -a; source "$CLI_ENV/user.env"; set +a
log "tip $(tip); requesting a 1_000_000 sat peg-in to the operator address"
out=$("$BIN_DIR/pegin-request" --network regtest --esplora-url "$BTC_CHAIN_URL" request --pegin-amount-sats 1000000 --receiver-evm-address "$OP0_GOAT_ADDRESS" 2>&1) || { echo "$out"; log "REQUEST FAILED"; exit 1; }
echo "$out" | tail -5
id=$(grep -oE '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}' <<<"$out" | head -1)
[[ -n "$id" ]] || { log "no instance id in the output"; exit 1; }
echo "$id" > "$E2E_RUN/inst.txt"; log "instance $id"
wait_all inst "$id" UserInited 180 || exit 1
wait_all inst "$id" CommitteesAnswered 600 || exit 1
log "prepare (deposit)"
"$BIN_DIR/pegin-request" --network regtest --esplora-url "$BTC_CHAIN_URL" prepare --instance-id "$id" 2>&1 | tail -3
wait_mempool 60 || exit 1
mine 1
wait_all inst "$id" UserBroadcastPeginPrepare 240 || exit 1
log "ceremony running (mock delays 15 s each)"
wait_all inst "$id" Presigned 1200 || exit 1
log "waiting for the relayer's Peg-In-Confirm"
wait_log committee_0 "Peg-In-Confirm broadcast.*$id\|$id.*Peg-In-Confirm broadcast" 300 || exit 1
wait_mempool 300 || exit 1
mine 1
wait_all inst "$id" RelayerL1Broadcasted 180 || exit 1
mine 1
log "SPV fed; waiting for postPeginData"
wait_all inst "$id" RelayerL2Minted 600 || exit 1
gid=$(graph_of_instance "$id" | awk '{print $1}' | head -1); echo "$gid" > "$E2E_RUN/graph.txt"
log "graph(s): $(graph_of_instance "$id" | tr '\n' ';')"
wait_all graph "$gid" L2Recorded 300 || exit 1
engine_summary
log "PEGIN DONE instance=$id graph=$gid tip=$(tip)"
