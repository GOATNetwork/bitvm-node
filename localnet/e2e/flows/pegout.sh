#!/usr/bin/env bash
# Happy peg-out: initWithdraw -> kickoff -> proceedWithdraw -> Take-1 -> finishWithdrawHappyPath.
source "$(cd "$(dirname "$0")/.." && pwd)/lib.sh"
gid=${1:?graph id}
"$ROOT/scripts/miner.sh" stop >/dev/null 2>&1 || true
topup_pegbtc
log "tip $(tip); initWithdraw on graph $gid"
( set -a; source "$CLI_ENV/operator.env"; set +a; "$BIN_DIR/pegout" --rpc-url "$(rpc_url operator_0)" once --graph-id "$gid" 2>&1 ) | tail -3
# Earlier unsettled slots are skipped first; each Skip needs a block to confirm.
for i in $(seq 1 10); do
  if fresh_log operator_0 | grep -q "$gid.*Pre-Kickoff and Kickoff broadcast\|Pre-Kickoff and Kickoff broadcast.*$gid"; then break; fi
  if fresh_log operator_0 | grep -q "graph_skip" && [[ -n "$(mempool)" ]]; then mine 1; fi
  sleep 20
done
wait_log operator_0 "$gid.*Pre-Kickoff and Kickoff broadcast\|Pre-Kickoff and Kickoff broadcast.*$gid" 240 || { engine_summary; exit 1; }
wait_mempool 60 || exit 1
mine 1
wait_all graph "$gid" OperatorKickOff 180 || exit 1
mine 1
wait_log committee_0 "$gid.*proceedWithdraw sent\|proceedWithdraw sent.*$gid" 180 || { engine_summary; exit 1; }
log "verifier verdicts: $(grep -h "graph_job" "$LOGS_DIR/nodes/verifier_0.log" | grep "$gid" | grep -oE 'note=[^ ]*.*' | tail -3 | cut -c1-160 | tr '\n' '|')"
mine 2
wait_log operator_0 "$gid.*Take-1 broadcast\|Take-1 broadcast.*$gid" 240 || { engine_summary; exit 1; }
wait_mempool 60 || exit 1
mine 1
wait_all graph "$gid" OperatorTake1 180 || exit 1
mine 1
wait_log committee_0 "$gid.*finishWithdrawHappyPath sent\|finishWithdrawHappyPath sent.*$gid" 240 || { engine_summary; exit 1; }
engine_summary
log "PEGOUT DONE graph=$gid tip=$(tip)"
