#!/usr/bin/env bash
# N2: Goat latency 25 s (> 20 s timeout) on every node for 60 s from the kickoff block (the docker-pause case, via proxy).
source "$(cd "$(dirname "$0")/.." && pwd)/lib.sh"
gid=${1:?graph id}
scenario_begin N2 goat-timeout-60s pegout "$gid"
"$ROOT/scripts/miner.sh" stop >/dev/null 2>&1 || true
topup_pegbtc
( set -a; source "$CLI_ENV/operator.env"; set +a; "$BIN_DIR/pegout" --rpc-url "$(rpc_url operator_0)" once --graph-id "$gid" 2>&1 ) | tail -1
wait_log operator_0 "$gid.*Pre-Kickoff and Kickoff broadcast\|Pre-Kickoff and Kickoff broadcast.*$gid" 300 || { engine_summary; exit 1; }
wait_mempool 60 || exit 1
"$CHAOS" fault all goat latency 25000 --ttl 60; T0=$(date +%s)
mine 1; K=$(tip); log "kickoff confirmed at K=$K with Goat timing out"
sleep 30; mine 1; log "K+1 mined"; sleep 35
log "fault expired after $(( $(date +%s)-T0 )) s; WARN/ERROR so far:"; for r in committee_0 operator_0; do echo "  $r:"; warn_delta "$r"; done
wait_all graph "$gid" OperatorKickOff 180 || exit 1
wait_log committee_0 "$gid.*proceedWithdraw sent\|proceedWithdraw sent.*$gid" 300 || { engine_summary; exit 1; }
mine 2
wait_log operator_0 "$gid.*Take-1 broadcast\|Take-1 broadcast.*$gid" 240 || { engine_summary; exit 1; }
wait_mempool 60 || exit 1; mine 1
wait_all graph "$gid" OperatorTake1 180 || exit 1; mine 1
wait_log committee_0 "$gid.*finishWithdrawHappyPath sent\|finishWithdrawHappyPath sent.*$gid" 240 || { engine_summary; exit 1; }
scenario_end N2; log "N2 DONE graph=$gid"
