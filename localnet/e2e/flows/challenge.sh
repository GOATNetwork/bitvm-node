#!/usr/bin/env bash
# Challenge flow on a posted graph. MODE=valid: verifier finds the assert valid -> Take-2 -> finishWithdrawUnhappyPath.
# MODE=invalid (operator_0 + verifier_0 restarted with MOCK_GC_PROOF_VERDICT=always-invalid): ChallengeAssert ->
# Wrongly-Challenged cannot be built -> Disprove -> finishWithdrawDisproved.
source "$(cd "$(dirname "$0")/.." && pwd)/lib.sh"
gid=${1:?graph id}; MODE=${2:-valid}
"$ROOT/scripts/miner.sh" stop >/dev/null 2>&1 || true
topup_pegbtc
log "tip $(tip); MODE=$MODE; initWithdraw on graph $gid"
( set -a; source "$CLI_ENV/operator.env"; set +a; "$BIN_DIR/pegout" --rpc-url "$(rpc_url operator_0)" once --graph-id "$gid" 2>&1 ) | tail -2
wait_log operator_0 "Pre-Kickoff and Kickoff broadcast.*$gid\|$gid.*Pre-Kickoff and Kickoff broadcast" 240 || { engine_summary; exit 1; }
wait_mempool 60 || exit 1
mine 1; K=$(tip)
wait_all graph "$gid" OperatorKickOff 180 || exit 1
mine 1
wait_log committee_0 "$gid.*proceedWithdraw sent\|proceedWithdraw sent.*$gid" 180 || { engine_summary; exit 1; }
log "challenging from the verifier while tip=$(tip) (< K+2=$((K+2)))"
( set -a; source "$CLI_ENV/verifier.env"; set +a; "$BIN_DIR/challenge" --rpc-url "$(rpc_url verifier_0)" --graph-id "$gid" 2>&1 | tail -2 )
wait_mempool 60 || exit 1
mine 1
wait_log operator_0 "$gid.*Watchtower-Challenge-Init broadcast\|Watchtower-Challenge-Init broadcast.*$gid" 240 || { engine_summary; exit 1; }
wait_mempool 60 || exit 1
mine 1; W=$(tip); log "WCI confirmed at W=$W; holding for the watchtower proof (30 s)"
wait_log watchtower_0 "$gid.*Watchtower-Challenge broadcast\|Watchtower-Challenge broadcast.*$gid" 300 || { engine_summary; exit 1; }
wait_mempool 60 || exit 1
mine 1
wait_log operator_0 "$gid.*Operator-Challenge-ACK broadcast\|Operator-Challenge-ACK broadcast.*$gid" 240 || { engine_summary; exit 1; }
wait_mempool 60 || exit 1
mine 1
# commit-pubin needs the watchtower challenge buried 2 blocks (= verifier commit timeout at W+3): keep the
# verifier out of the race, as the runbook does.
"$ROOT/scripts/nodes.sh" stop verifier_0 >/dev/null 2>&1; log "verifier_0 stopped for the pubin block"
mine 1; log "tip $(tip) = W+3"
wait_log operator_0 "$gid.*Operator-Commit-Pubin broadcast\|Operator-Commit-Pubin broadcast.*$gid" 240 || { engine_summary; NODES_SH start verifier_0 >/dev/null 2>&1; exit 1; }
wait_mempool 60 || exit 1
mine 1
NODES_SH start verifier_0 >/dev/null 2>&1; log "verifier_0 restarted (verdict: $(current_verdict))"
log "waiting for the operator proof (30 s) and the assert"
wait_log operator_0 "$gid.*Prover-Assert broadcast\|Prover-Assert broadcast.*$gid" 300 || { engine_summary; exit 1; }
wait_mempool 60 || exit 1
mine 1; A=$(tip); log "assert confirmed at A=$A"
if [[ $MODE == valid ]]; then
  wait_log verifier_0 "operator assert proof is valid" 240 || { engine_summary; exit 1; }
  for i in $(seq 1 15); do
    if fresh_log operator_0 | grep -q "Take-2 broadcast"; then break; fi
    sleep 20; mine 1
  done
  wait_log operator_0 "$gid.*Take-2 broadcast\|Take-2 broadcast.*$gid" 120 || { engine_summary; exit 1; }
  [[ -n "$(mempool)" ]] && mine 1
  wait_all graph "$gid" OperatorTake2 180 || exit 1
  mine 1
  wait_log committee_0 "$gid.*finishWithdrawUnhappyPath sent\|finishWithdrawUnhappyPath sent.*$gid" 240 || { engine_summary; exit 1; }
else
  wait_log verifier_0 "ChallengeAssert broadcast\|Verifier-Assert broadcast\|verifier assert broadcast\|verifier connector spent by unconfirmed" 300 || { engine_summary; exit 1; }
  wait_mempool 60 || exit 1
  mine 1; log "ChallengeAssert confirmed at $(tip); the operator cannot answer under always-invalid"
  sleep 30
  for i in $(seq 1 8); do
    if [[ "$(all_graph "$gid") " == *"verifier_0=Disprove "* ]]; then break; fi
    mine 1; sleep 25
  done
  wait_any graph "$gid" Disprove 120 || { engine_summary; exit 1; }
  [[ -n "$(mempool)" ]] && mine 1
  wait_all graph "$gid" Disprove 180 || exit 1
  mine 1
  wait_log committee_0 "$gid.*finishWithdrawDisproved sent\|finishWithdrawDisproved sent.*$gid" 240 || { engine_summary; exit 1; }
fi
engine_summary
log "CHALLENGE FLOW ($MODE) DONE graph=$gid tip=$(tip)"
