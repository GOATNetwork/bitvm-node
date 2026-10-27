#!/usr/bin/env bash
# Finish a peg-out that is already past the confirmed kickoff: proceedWithdraw -> Take-1 -> finishWithdrawHappyPath.
source "$(cd "$(dirname "$0")/.." && pwd)/lib.sh"
gid=${1:?graph id}
wait_log committee_0 "$gid.*proceedWithdraw sent\|proceedWithdraw sent.*$gid" ${2:-600} || { engine_summary; exit 1; }
mine 2
wait_log operator_0 "$gid.*Take-1 broadcast\|Take-1 broadcast.*$gid" 300 || { engine_summary; exit 1; }
wait_mempool 60 || exit 1
mine 1
wait_all graph "$gid" OperatorTake1 180 || exit 1
mine 1
wait_log committee_0 "$gid.*finishWithdrawHappyPath sent\|finishWithdrawHappyPath sent.*$gid" 300 || { engine_summary; exit 1; }
engine_summary
log "PEGOUT FINISHED graph=$gid tip=$(tip)"
