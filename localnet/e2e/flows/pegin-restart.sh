#!/usr/bin/env bash
# Happy peg-in with one node restarted while it is executing a job of this peg-in's ceremony (stability check).
#   e2e/flows/pegin-restart.sh <role> [max-wait-secs]     RESTART_ON_ACTION=<action> restricts the trigger to one job action
# After Prepare confirms, the target's engine_job table is polled; the node is restarted the moment one of the
# instance's (or its graphs') jobs is Running. Fails when no such job is caught before the instance is Presigned
# on the target, when the interrupted job does not end Done (re-run by the new process, or finished by the old one
# during its graceful shutdown), or when the restart produced a duplicate side effect (a second graph, a second
# Peg-In-Confirm transaction).
source "$(cd "$(dirname "$0")/.." && pwd)/lib.sh"
role=${1:?role}; max_wait=${2:-900}
set -o pipefail
"$ROOT/scripts/miner.sh" stop >/dev/null 2>&1 || true
log "tip $(tip); requesting a 1_000_000 sat peg-in (restart of $role while it runs one of the ceremony's jobs)"
out=$( set -a; source "$CLI_ENV/user.env"; set +a; "$BIN_DIR/pegin-request" --network regtest --esplora-url "$BTC_CHAIN_URL" request --pegin-amount-sats 1000000 --receiver-evm-address "$OP0_GOAT_ADDRESS" 2>&1 ) || { echo "$out"; log "REQUEST FAILED"; exit 1; }
id=$(grep -oE '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}' <<<"$out" | head -1)
[[ -n "$id" ]] || { log "no instance id in the output"; exit 1; }
echo "$id" > "$E2E_RUN/inst.txt"; log "instance $id"
wait_all inst "$id" UserInited 180 || exit 1
wait_all inst "$id" CommitteesAnswered 600 || exit 1
log "prepare (deposit)"
T_PREP=$(date +%s)   # graphs whose first job on the target appears after this belong to this peg-in
( set -a; source "$CLI_ENV/user.env"; set +a; "$BIN_DIR/pegin-request" --network regtest --esplora-url "$BTC_CHAIN_URL" prepare --instance-id "$id" 2>&1 ) | tail -1
wait_mempool 60 || exit 1
mine 1
wait_all inst "$id" UserBroadcastPeginPrepare 240 || exit 1
rport=$((RPC_PORT_BASE + $(role_idx "$role"))); t0=$(date +%s); job=""
while :; do
  # the graph is not listed on the target's RPC until it is stored there, so its setup jobs are found by age instead
  job=$(db "$role" "select job_id||'|'||action from engine_job j where state='Running' and (aggregate_id='$id' or (aggregate_kind='graph' and (select min(created_at) from engine_job k where k.aggregate_id=j.aggregate_id) >= $T_PREP))${RESTART_ON_ACTION:+ and action='$RESTART_ON_ACTION'} limit 1")
  [[ -n $job ]] && break
  st=$(inst_status "$id" "$rport")
  case $st in Presigned|RelayerL1Broadcasted|RelayerL2Minted) log "FAIL: the ceremony on $role reached $st before any of its jobs was caught running"; exit 1;; esac
  (( $(date +%s) - t0 >= max_wait )) && { log "FAIL: no running job of this peg-in on $role within ${max_wait}s"; exit 1; }
  sleep 0.5
done
jid=${job%%|*}; jact=${job#*|}
log "restarting $role while job $jact (${jid:0:12}) is Running; other jobs: $(db $role "select action||':'||state from engine_job where state in ('Running','Pending')" | tr '\n' ' ')"
NODES_SH restart "$role" 2>&1 | grep -E 'started|FAILED' | sed 's/^/     /'
T_UP=$(date +%s)   # the old process has exited, the new one is running
wait_all inst "$id" Presigned 1500 || { engine_summary; exit 1; }
log "waiting for the relayer's Peg-In-Confirm"
# wait for the broadcast line itself: a stale mempool entry would otherwise make us mine one block too early
wait_log committee_0 "Peg-In-Confirm broadcast.*$id\|$id.*Peg-In-Confirm broadcast" 300 || exit 1
wait_mempool 300 || exit 1
mine 1
wait_all inst "$id" RelayerL1Broadcasted 180 || exit 1
mine 1
wait_all inst "$id" RelayerL2Minted 600 || exit 1
gid=$(graph_of_instance "$id" | awk '{print $1}' | head -1); echo "$gid" > "$E2E_RUN/graph.txt"
log "graph(s): $(graph_of_instance "$id" | tr '\n' ';')"
wait_all graph "$gid" L2Recorded 300 || exit 1
log "$role recovery lines: $(fresh_log $role | grep -E 'engine_recovery|lost its holder|re-claimed|resumed' | grep -oE '"message":"[^"]*"' | sort | uniq -c | tr '\n' '|')"
engine_summary
rc=0
jrow=$(db "$role" "select state||'|'||attempts||'|'||coalesce(finished_at,0) from engine_job where job_id='$jid'")
IFS='|' read -r jst jatt jfin <<<"$jrow"
log "interrupted job $jact: state=$jst attempts=$jatt finished_at=$jfin (new process up at $T_UP)"
if [[ $jst != Done ]]; then log "FAIL: the interrupted job $jact did not end Done ($jst)"; rc=1
elif (( jatt < 2 && jfin > T_UP )); then log "FAIL: $jact finished after the restart without being re-run (attempts=$jatt)"; rc=1
elif (( jatt < 2 )); then log "$jact finished in the old process during its graceful shutdown"
else log "$jact was re-run by the new process"; fi
ng=$(graph_of_instance "$id" | wc -l)
[[ $ng == 1 ]] || { log "FAIL: $ng graphs for the instance, expected 1"; rc=1; }
nc=$(fresh_log committee_0 | jq -r --arg id "$id" 'select(.message=="Peg-In-Confirm broadcast" and .instance_id==$id) | .txid' 2>/dev/null | sort -u | wc -l)
[[ $nc == 1 ]] || { log "FAIL: $nc distinct Peg-In-Confirm transactions for the instance, expected 1"; rc=1; }
(( rc == 0 )) || exit 1
log "PEGIN(restart $role) DONE instance=$id graph=$gid tip=$(tip)"
