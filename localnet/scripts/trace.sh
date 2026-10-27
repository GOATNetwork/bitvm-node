#!/usr/bin/env bash
# Cross-node timeline of one peg-in instance or one graph.
#   scripts/trace.sh <instance_id|graph_id> [-s 6h] [-n 300] [-a]     (-a: all boot logs; default current boots)
# Prints RPC statuses, DB rows (instance / graphs / engine aggregate, jobs, parked inbox, poison) on every node and the
# merged log timeline of every line mentioning the id (and its related graph/instance ids). Copy in tmp/trace-<id8>.txt.
set -uo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
source "$ROOT/scripts/localnet.env"
ROLES=(committee_0 committee_1 operator_0 verifier_0 watchtower_0)
id=${1:?instance or graph id}; shift
since=6h n=300 all=""
while getopts 's:n:a' o; do case $o in s) since=$OPTARG;; n) n=$OPTARG;; a) all=-a;; *) exit 2;; esac; done
out="$TMP_DIR/trace-${id:0:8}.txt"
db() { sqlite3 -readonly -noheader -list -cmd ".timeout 8000" "$NODES_DIR/$1/bitvm-node.db" "$2" 2>/dev/null; }
# uuid text for a column stored either as TEXT or as a 16-byte BLOB
uf() { echo "CASE WHEN typeof($1)='blob' THEN lower(substr(hex($1),1,8)||'-'||substr(hex($1),9,4)||'-'||substr(hex($1),13,4)||'-'||substr(hex($1),17,4)||'-'||substr(hex($1),21)) ELSE $1 END"; }
hexid=$(tr -d - <<<"$id" | tr a-f A-F)
{
echo "### trace $id  ($(date -u +%FT%TZ), tip $($BCLI getblockcount 2>/dev/null))"
# related ids: graphs of the instance, or the instance of the graph
related=$(for r in "${ROLES[@]}"; do db "$r" "select $(uf graph_id) from graph where instance_id='$id' or hex(instance_id)='$hexid'; select $(uf instance_id) from graph where graph_id='$id' or hex(graph_id)='$hexid';"; done | sort -u | grep -av '^$')
ids="$id"; [[ -n $related ]] && ids+=$'\n'"$related"
echo "related ids: $(tr '\n' ' ' <<<"$related")"
echo
echo "### RPC status per node"
for i in "${!ROLES[@]}"; do r=${ROLES[$i]}; p=$((RPC_PORT_BASE+i))
  is=$(curl -s --max-time 5 "http://127.0.0.1:$p/v1/instances/$id" | jq -r '.instance_wrap.instance.status // "-"' 2>/dev/null)
  gs=$(curl -s --max-time 5 "http://127.0.0.1:$p/v1/graphs/$id" | jq -r '.graph | "\(.status // "-")/\(.sub_status // "")" ' 2>/dev/null)
  printf '  %-13s instance=%-26s graph=%s\n' "$r" "${is:-?}" "${gs:-?}"; done
echo
for r in "${ROLES[@]}"; do
  echo "### $r DB"
  db "$r" "select '  instance', status, 'btc_h='||btc_height, 'status_updated_at='||status_updated_at, 'goat_tx='||substr(goat_tx_hash,1,10) from instance where instance_id='$id' or hex(instance_id)='$hexid';" | tr '|' ' '
  for g in $ids; do gh=$(tr -d - <<<"$g" | tr a-f A-F); db "$r" "select '  graph', $(uf graph_id), 'slot='||kickoff_index, status, sub_status, 'status_updated_at='||status_updated_at, 'kickoff='||substr(kickoff_txid,1,10) from graph where graph_id='$g' or hex(graph_id)='$gh';" | tr '|' ' '; done
  db "$r" "select '  pending_graph_init', $(uf graph_id), operator_pubkey, updated_at from pending_graph_init where hex(instance_id)='$hexid' or instance_id='$id';" | tr '|' ' '
  for g in $ids; do gh=$(tr -d - <<<"$g" | tr a-f A-F)
    db "$r" "select '  aggregate', aggregate_kind, status, phase, 'v='||version, 'updated='||updated_at from engine_aggregate where aggregate_id='$g';" | tr '|' ' '
    db "$r" "select '  job', aggregate_kind, phase||'/'||action, state, 'attempts='||attempts, 'next_at='||next_at, 'lease='||lease_until, 'cancel='||cancel_requested, substr(coalesce(last_error,''),1,70), 'updated='||updated_at from engine_job where aggregate_id='$g' order by updated_at;" | tr '|' ' '
    db "$r" "select '  inbox!', kind, state, 'attempts='||attempts, coalesce(waiting_ref,''), substr(coalesce(waiting_detail,last_error,''),1,70) from engine_inbox where aggregate_id='$g' and state!='Applied';" | tr '|' ' '
    db "$r" "select '  POISON', action, 'count='||poison_count, 'blocked_until='||blocked_until, substr(reason,1,70) from engine_aggregate_poison where aggregate_id='$g';" | tr '|' ' '
  done
done
echo
echo "### log timeline (last $n lines, since $since)"
for g in $ids; do "$ROOT/scripts/logq.sh" -s "$since" -g "${g:0:8}" $all; done | grep -av " http_re[sq]" | sort -u | tail -n "$n"
} | tee "$out"
echo "(saved to $out)"
