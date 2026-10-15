#!/usr/bin/env bash
# Timeline of one peg-in instance or one graph on a single bitvm-noded: RPC status, database rows
# (instance, graphs, engine aggregate / jobs / parked inbox events / poison) and the log lines naming the id.
#   trace.sh <instance_id|graph_id> [-r http://host:rpc] [-d <sqlite file>] [-f <log file>] [-s 6h] [-n 300]
# Defaults: NODE_RPC (http://127.0.0.1:8080), NODE_DB (sqlite file path, e.g. /tmp/bitvm-node.db), NODE_LOG.
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
id=${1:?instance or graph id}; shift
rpc=${NODE_RPC:-http://127.0.0.1:8080} db=${NODE_DB:-} log=${NODE_LOG:-} since=6h n=300
while getopts 'r:d:f:s:n:' o; do case $o in r) rpc=$OPTARG;; d) db=$OPTARG;; f) log=$OPTARG;; s) since=$OPTARG;; n) n=$OPTARG;; *) exit 2;; esac; done
q() { sqlite3 -readonly -noheader -list -cmd ".timeout 8000" "$db" "$1" 2>/dev/null | tr '|' ' '; }
# uuid text for a column stored either as TEXT or as a 16-byte BLOB
uf() { echo "CASE WHEN typeof($1)='blob' THEN lower(substr(hex($1),1,8)||'-'||substr(hex($1),9,4)||'-'||substr(hex($1),13,4)||'-'||substr(hex($1),17,4)||'-'||substr(hex($1),21)) ELSE $1 END"; }
hexid=$(tr -d - <<<"$id" | tr a-f A-F)
echo "### trace $id ($(date -u +%FT%TZ))"
related=""
if [[ -n $db && -r $db ]]; then
  related=$(q "select $(uf graph_id) from graph where instance_id='$id' or hex(instance_id)='$hexid'; select $(uf instance_id) from graph where graph_id='$id' or hex(graph_id)='$hexid';" | sort -u | grep -av '^$')
fi
ids="$id"; [[ -n $related ]] && ids+=$'\n'"$related"
echo "related ids: $(tr '\n' ' ' <<<"$related")"
echo "### RPC"
is=$(curl -s --max-time 5 "$rpc/v1/instances/$id" | jq -r '.instance_wrap.instance.status // "-"' 2>/dev/null)
gs=$(curl -s --max-time 5 "$rpc/v1/graphs/$id" | jq -r '.graph | "\(.status // "-")/\(.sub_status // "")"' 2>/dev/null)
echo "  instance=${is:-?} graph=${gs:-?}"
if [[ -n $db && -r $db ]]; then
  echo "### database $db"
  q "select '  instance', status, 'btc_h='||btc_height, 'status_updated_at='||status_updated_at, 'goat_tx='||substr(goat_tx_hash,1,10) from instance where instance_id='$id' or hex(instance_id)='$hexid';"
  for g in $ids; do gh=$(tr -d - <<<"$g" | tr a-f A-F)
    q "select '  graph', $(uf graph_id), 'slot='||kickoff_index, status, sub_status, 'status_updated_at='||status_updated_at, 'kickoff='||substr(kickoff_txid,1,10) from graph where graph_id='$g' or hex(graph_id)='$gh';"
  done
  q "select '  pending_graph_init', $(uf graph_id), operator_pubkey, updated_at from pending_graph_init where hex(instance_id)='$hexid' or instance_id='$id';"
  for g in $ids; do gh=$(tr -d - <<<"$g" | tr a-f A-F)
    q "select '  aggregate', aggregate_kind, status, phase, 'v='||version, 'updated='||updated_at from engine_aggregate where aggregate_id='$g';"
    q "select '  job', aggregate_kind, phase||'/'||action, state, 'attempts='||attempts, 'next_at='||next_at, 'lease='||lease_until, 'cancel='||cancel_requested, substr(coalesce(last_error,''),1,70), 'updated='||updated_at from engine_job where aggregate_id='$g' order by updated_at;"
    q "select '  inbox!', kind, state, 'attempts='||attempts, coalesce(waiting_ref,''), substr(coalesce(waiting_detail,last_error,''),1,70) from engine_inbox where aggregate_id='$g' and state!='Applied';"
    q "select '  POISON', action, 'count='||poison_count, 'blocked_until='||blocked_until, substr(reason,1,70) from engine_aggregate_poison where aggregate_id='$g';"
  done
else echo "### database: not given (-d) or unreadable; skipped"; fi
if [[ -n $log && -r $log ]]; then
  echo "### log timeline (last $n lines, since $since)"
  for g in $ids; do "$HERE/logq.sh" -f "$log" -s "$since" -g "${g:0:8}"; done | grep -av ' http_re[sq]' | sort -u | tail -n "$n"
else echo "### log: not given (-f) or unreadable; skipped"; fi
