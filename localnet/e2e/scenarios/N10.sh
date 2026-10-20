#!/usr/bin/env bash
# N10: the operator's proof-builder requests are black-holed (accepted, never answered) for 240 s, injected once
# Commit-Pubin is broadcast (the operator then polls the proof builder for the Assert proof). The challenge flow is
# expected to time out meanwhile (the runner's case finishes the graph with Take-2); the scenario itself fails only
# when the black hole never caught a request of the operator.
source "$(cd "$(dirname "$0")/.." && pwd)/lib.sh"
gid=${1:?graph id}
scenario_begin N10 proof-builder-blackhole challenge "$gid"
"$ROOT/e2e/flows/challenge.sh" "$gid" valid > "$E2E_RUN/last-N10-challenge.out" 2>&1 &
flow=$!
for i in $(seq 1 400); do fresh_log operator_0 | grep -q "Operator-Commit-Pubin broadcast" && break; sleep 3; done
hits() { curl -s --max-time 5 "$CHAOS_CTRL/stats" | jq -r '.["operator_0/proof"].faulted.blackhole // 0'; }
h0=$(hits)
"$CHAOS" fault operator_0 proof blackhole 240 --ttl 300; T0=$(date +%s)
log "proof blackhole set at $(ts) (proxy closes the hung connections after 240 s)"
for i in $(seq 1 30); do sleep 20
  log "t+$(( $(date +%s)-T0 ))s proof proxy: $(curl -s $CHAOS_CTRL/stats | jq -c '.["operator_0/proof"]') jobs: $(db operator_0 "select action||':'||state||':'||attempts from engine_job where aggregate_id='$gid' and state in ('Running','Pending') order by updated_at desc limit 3" | tr '\n' ' ')"
  fresh_log operator_0 | grep -q "Prover-Assert broadcast" && break
done
wait $flow; rc=$?
cat "$E2E_RUN/last-N10-challenge.out"
h1=$(hits); log "black-holed operator proof requests: $((h1 - h0))"
scenario_end N10; log "N10 flow rc=$rc"
(( h1 > h0 )) || { log "FAIL: no operator proof request hit the black hole"; exit 1; }
exit 0
