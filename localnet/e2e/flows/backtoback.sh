#!/usr/bin/env bash
# Two peg-ins back to back with a slow verifier soldering (MOCK_GC_SOLDER_DELAY_SECS=120). B is prepared while A's
# ceremony still runs; the engine's cpu pool runs one GC job per node at a time (ENGINE_CPU_POOL_SLOTS, default 1),
# so the verifier queues B's setup behind A's solder. Asserted: A is still in its ceremony on every node when B's
# Prepare confirms, the verifier created B's setup job before A's solder finished, both end L2Minted / L2Recorded,
# and their graphs take consecutive slots.
source "$(cd "$(dirname "$0")/.." && pwd)/lib.sh"
"$ROOT/scripts/miner.sh" stop >/dev/null 2>&1 || true
SOLDER_BEFORE=$(tuning_get MOCK_GC_SOLDER_DELAY_SECS); set_tuning MOCK_GC_SOLDER_DELAY_SECS 120
NODES_SH restart verifier_0 >/dev/null 2>&1; log "verifier_0 restarted with a 120 s solder delay"
sleep 8
req() { local out id; out=$( set -a; source "$CLI_ENV/user.env"; set +a; "$BIN_DIR/pegin-request" --network regtest --esplora-url "$BTC_CHAIN_URL" request --pegin-amount-sats 1000000 --receiver-evm-address "$OP0_GOAT_ADDRESS" 2>&1 ) || { echo "$out" >&2; return 1; }
  grep -oE '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}' <<<"$out" | head -1; }
prep() { ( set -a; source "$CLI_ENV/user.env"; set +a; "$BIN_DIR/pegin-request" --network regtest --esplora-url "$BTC_CHAIN_URL" prepare --instance-id "$1" 2>&1 ) | tail -1; }
A=$(req) || exit 1; log "instance A $A"
wait_all inst "$A" CommitteesAnswered 600 || exit 1
prep "$A"; wait_mempool 60 || exit 1; mine 1
wait_all inst "$A" UserBroadcastPeginPrepare 240 || exit 1
B=$(req) || exit 1; log "instance B $B (requested while A's setup runs)"
wait_all inst "$B" CommitteesAnswered 600 || exit 1
prep "$B"; wait_mempool 60 || exit 1; mine 1
wait_all inst "$B" UserBroadcastPeginPrepare 240 || exit 1
sA=$(all_inst "$A"); log "A: $sA"
[[ $(grep -o "=UserBroadcastPeginPrepare " <<<"$sA " | wc -l) -eq ${#NODES[@]} ]] || { log "FAIL: A left its ceremony before B's Prepare confirmed, no overlap: $sA"; exit 1; }
log "operator sessions: $(db operator_0 "select substr(hex(instance_id),1,8)||':'||substr(hex(graph_id),1,8) from pending_graph_init" | tr '\n' ' ')"
log "operator build jobs: $(db operator_0 "select substr(aggregate_id,1,8)||':'||action||':'||state from engine_job where action in ('build_graph','ingest_soldering_proof','verifier_setup') and state in ('Pending','Running')" | tr '\n' ' ')"
# each instance: wait for the relayer's Peg-In-Confirm to be broadcast, then confirm it with a block (the fast
# poll otherwise mines before B's confirm reaches the mempool and B stays Presigned with the miner stopped)
confirm() { wait_log committee_0 "Peg-In-Confirm broadcast.*$1\|$1.*Peg-In-Confirm broadcast" 300 || return 1; wait_mempool 120 || return 1; mine 1; }
wait_all inst "$A" Presigned 1500 || { engine_summary; exit 1; }
confirm "$A" || exit 1
wait_all inst "$B" Presigned 1500 || { engine_summary; exit 1; }
confirm "$B" || exit 1
wait_all inst "$A" RelayerL1Broadcasted 240 || exit 1
wait_all inst "$B" RelayerL1Broadcasted 240 || exit 1
mine 1
wait_all inst "$A" RelayerL2Minted 600 || exit 1
wait_all inst "$B" RelayerL2Minted 600 || exit 1
gA=$(graph_of_instance "$A" | awk '{print $1}' | head -1); gB=$(graph_of_instance "$B" | awk '{print $1}' | head -1)
log "graphs: A $(graph_of_instance "$A" | tr '\n' ';') B $(graph_of_instance "$B" | tr '\n' ';')"
wait_all graph "$gA" L2Recorded 300 || exit 1
wait_all graph "$gB" L2Recorded 300 || exit 1
echo "$gB" > "$E2E_RUN/graph.txt"
kA=$(graph_of_instance "$A" | awk '{print $2}' | head -1); kB=$(graph_of_instance "$B" | awk '{print $2}' | head -1)
bset=$(db verifier_0 "select created_at from engine_job where aggregate_id='$gB' and action='verifier_setup' order by created_at limit 1")
asol=$(db verifier_0 "select finished_at from engine_job where aggregate_id='$gA' and action='verifier_solder' order by created_at limit 1")
log "slots A=$kA B=$kB; verifier: B setup queued at $bset, A solder finished at $asol"
rc=0
[[ -n $kA && -n $kB && $kB -eq $((kA + 1)) ]] || { log "FAIL: graphs not in consecutive slots (A=$kA B=$kB)"; rc=1; }
[[ -n $bset && -n $asol && $bset -lt $asol ]] || { log "FAIL: the verifier did not take B's setup while A's solder ran (B setup $bset, A solder done $asol)"; rc=1; }
set_tuning MOCK_GC_SOLDER_DELAY_SECS "$SOLDER_BEFORE"
NODES_SH restart verifier_0 >/dev/null 2>&1; log "verifier_0 restarted with the ${SOLDER_BEFORE} s solder delay"
engine_summary
(( rc == 0 )) || exit 1
log "BACK-TO-BACK DONE A=$A/$gA B=$B/$gB tip=$(tip)"
