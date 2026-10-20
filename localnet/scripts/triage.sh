#!/usr/bin/env bash
# One-screen "why is this node unhealthy" view.   scripts/triage.sh [role|all] [-s 10m]
set -uo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
source "$ROOT/scripts/localnet.env"
ROLES=(committee_0 committee_1 operator_0 verifier_0 watchtower_0)
role=${1:-all}; since=${3:-10m}; [[ ${2:-} == -s ]] && since=$3
role_idx() { local i; for i in "${!ROLES[@]}"; do [[ ${ROLES[$i]} == "$1" ]] && { echo "$i"; return; }; done; echo 0; }
now=$(date +%s)
tip=$($BCLI getblockcount 2>/dev/null || echo "?")
anvil=$($CAST block-number --rpc-url "$GOAT_CHAIN_URL" 2>/dev/null || echo "?")
sg=$(curl -s --max-time 5 -XPOST -H 'content-type: application/json' -d '{"query":"{_meta{block{number}}}"}' $(jq -r .query_url "$STATE_DIR/subgraph.json" 2>/dev/null) | jq -r '.data._meta.block.number // "?"' 2>/dev/null)
echo "truth: btc tip=$tip  anvil=$anvil  subgraph=$sg  miner=$("$ROOT/scripts/miner.sh" status | grep -oE '^miner [a-z]+')  proof-builder=$("$ROOT/scripts/proof-builder.sh" status | grep -oE '^proof-builder [a-z]+')"
"$ROOT/scripts/chaos.sh" status | tail -n +2 | grep -v 'overrides:' | grep -v 'rules: 0' | grep -v 'faults: none' | sed 's/^/chaos:/'
metric() { awk -v k="$1" '$1==k{print $2; exit}' <<<"$2"; }
one() {
  local r=$1 i; i=$(role_idx "$r"); local rpc=$((RPC_PORT_BASE+i)) met=$((METRICS_PORT_BASE+i))
  local pid; pid=$(cat "$RUN_DIR/nodes/$r.pid" 2>/dev/null)
  local ovr=""; [[ -f $RUN_DIR/overrides/$r.env ]] && ovr=" [proxied]"
  if [[ -z $pid || ! -d /proc/$pid ]]; then echo "== $r DOWN (no process)"; return; fi
  local et rss fds; et=$(ps -o etimes= -p "$pid" | tr -d ' '); rss=$(awk '/VmRSS/{printf "%dMB",$2/1024}' /proc/$pid/status); fds=$(ls /proc/$pid/fd 2>/dev/null | wc -l)
  local logf; logf=$(readlink -f "$LOGS_DIR/nodes/$r/current")
  local boot; boot=$(jq -r 'select(.event=="service_started") | "\(.timestamp[0:19])Z v\(.version)"' "$logf" 2>/dev/null | head -1)
  echo "== $r pid=$pid up=${et}s rss=$rss fds=$fds boot=${boot:-?} log=$(du -h "$logf" | cut -f1)$ovr"
  local m; m=$(curl -s --max-time 4 "http://127.0.0.1:$met/metrics")
  if [[ -z $m ]]; then echo "   metrics: UNREACHABLE"; else
    echo "   ready=$(metric bitvm_node_ready "$m") event_watch_ready=$(metric bitvm_node_event_watch_ready "$m") event_watch_lag=$(metric bitvm_node_event_watch_lag_blocks "$m") spv_lag=$(metric bitvm_node_spv_lag_blocks "$m") p2p peers=$(metric bitvm_node_p2p_connected_peers "$m") topics_healthy=$(metric bitvm_node_p2p_required_topics_healthy "$m") gas_wei=$(metric bitvm_node_goat_gas_balance_wei "$m") fee_sats=$(metric bitvm_node_fee_wallet_balance_sats "$m")"
    echo "   backends: $(grep -E '^bitvm_node_(btc|goat)_backend_requests_total' <<<"$m" | sed -E 's/bitvm_node_(btc|goat)_backend_requests_total\{outcome="([a-z]+)"\} ([0-9]+)/\1.\2=\3/' | tr '\n' ' ') btc_last_ok=$(( now - $(metric bitvm_node_btc_backend_last_success_timestamp_seconds "$m" || echo 0) ))s goat_last_ok=$(( now - $(metric bitvm_node_goat_backend_last_success_timestamp_seconds "$m" || echo 0) ))s event_watch_last_ok=$(( now - $(metric bitvm_node_event_watch_last_success_timestamp_seconds "$m" || echo 0) ))s"
    echo "   stale tasks (>90s): $(grep '^bitvm_node_task_last_success_timestamp_seconds' <<<"$m" | awk -v now="$now" -F'[{}" ]+' '{age=now-$NF; if (age>90) printf "%s=%ds ", $3, age}')"
    local al; al=$(grep '^bitvm_node_instance_alerts_total' <<<"$m" | sed -E 's/.*alert="([a-z_]+)"\} ([0-9]+)/\1=\2/' | tr '\n' ' '); [[ -n $al ]] && echo "   alerts: $al"
  fi
  local d; d=$(curl -s --max-time 6 "http://127.0.0.1:$rpc/v1/debug/status")
  if [[ -n $d ]]; then
    echo "   heights: $(jq -r '"btc=\(.bitcoin_height // "null") goat=\(.goat_height // "null") spv=\(.goat_spv_height // "null")"' <<<"$d") (truth btc=$tip anvil=$anvil)  engine: $(jq -c '.engine // {}' <<<"$d" | cut -c1-200)"
  else echo "   rpc: UNREACHABLE"; fi
  local e; e=$(curl -s --max-time 6 "http://127.0.0.1:$rpc/v1/debug/engine")
  [[ -n $e ]] && jq -r '(.waiting[]? | "   WAITING \(.aggregate_kind) \(.aggregate_id[0:8]) \(.kind) \(.waiting_ref // "") \((.waiting_detail // "")[0:80])"), (.poisoned[]? | "   POISONED \(.aggregate_kind) \(.aggregate_id[0:8]) \(.action) count=\(.poison_count) blocked_until=\(.blocked_until) \((.reason // "")[0:80])")' <<<"$e"
  echo "   warn/error last $since (top 8):"
  "$ROOT/scripts/logq.sh" -r "$r" -s "$since" -l WARN | awk '{printf "%s %s %s\n", $2, $4, $5}' | sort | uniq -c | sort -rn | head -8 | sed 's/^/     /'
  local le; le=$("$ROOT/scripts/logq.sh" -r "$r" -s "$since" -l ERROR -n 1); [[ -n $le ]] && echo "   last ERROR: $le"; return 0
}
if [[ $role == all ]]; then for r in "${ROLES[@]}"; do one "$r"; done; else one "$role"; fi
