#!/usr/bin/env bash
# P2: operator_0 fully p2p-isolated for 90 s while the setup ceremony runs (after Prepare confirmed). Fails when the
# isolation did not take (operator still has peers half way through), when it does not reconnect to both committee
# members within 60 s of the heal, or when the peg-in flow fails.
source "$(cd "$(dirname "$0")/.." && pwd)/lib.sh"
peers() { curl -s --max-time 3 "$(metrics_url operator_0)" | awk '/^bitvm_node_p2p_connected_peers/{print $2}'; }
scenario_begin P2 p2p-isolate-operator pegin
"$ROOT/e2e/flows/pegin.sh" > "$E2E_RUN/last-P2-pegin.out" 2>&1 &
flow=$!
for i in $(seq 1 200); do grep -q 'ceremony running' "$E2E_RUN/last-P2-pegin.out" && break; sleep 3; done
sleep 10
before=$(peers)
"$CHAOS" p2p isolate operator_0; log "operator_0 isolated for 90 s; peers before=$before"
sleep 45; mid=$(peers); log "operator peers mid-isolation=$mid $(all_inst "$(cat "$E2E_RUN/inst.txt")")"
sleep 45
"$CHAOS" p2p heal; log "healed"
p=""; for i in $(seq 1 12); do sleep 5; p=$(peers); [[ $p == 2 ]] && break; done; log "operator peers after heal=$p (after $((i*5)) s)"
wait $flow; rc=$?
cat "$E2E_RUN/last-P2-pegin.out"
[[ ${mid:-x} == 0 ]] || { log "FAIL: isolation did not take, operator still had ${mid:-?} peers"; rc=1; }
[[ $p == 2 ]] || { log "FAIL: operator did not reconnect to both committee members within 60 s of the heal"; rc=1; }
scenario_end P2; log "P2 rc=$rc"
exit $rc
