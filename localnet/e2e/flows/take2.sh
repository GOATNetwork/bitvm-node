#!/usr/bin/env bash
# Continue a challenged graph whose assert stands unchallenged: mine until Take-2 appears, confirm it, finish on Goat.
source "$(cd "$(dirname "$0")/.." && pwd)/lib.sh"
gid=${1:?graph id}
log "tip $(tip); stepping blocks until the operator broadcasts Take-2"
for i in $(seq 1 15); do
  if fresh_log operator_0 | grep -q "Take-2 broadcast"; then break; fi
  sleep 20; mine 1
done
wait_log operator_0 "$gid.*Take-2 broadcast\|Take-2 broadcast.*$gid" 120 || { engine_summary; exit 1; }
[[ -n "$(mempool)" ]] && mine 1
wait_all graph "$gid" OperatorTake2 180 || { mine 1; wait_all graph "$gid" OperatorTake2 120 || exit 1; }
mine 1
wait_log committee_0 "$gid.*finishWithdrawUnhappyPath sent\|finishWithdrawUnhappyPath sent.*$gid" 240 || { engine_summary; exit 1; }
engine_summary
log "TAKE2 DONE graph=$gid tip=$(tip)"
